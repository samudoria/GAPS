import csv
import os
import sys
import time
from collections import defaultdict
from androguard.misc import AnalyzeDex
import logging
import gc
import json
from threading import Thread
from collections import deque

from . import dalvik_disassembler
from . import method_utils
from . import icc_analysis
from . import path_generation
from . import ui_id_finder
from . import myAndroguard

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# CODE
###############################################################################


class GAPS:
    def __init__(
        self,
        dalvik_path,
        target_method,
        class_name,
        parent_class,
        signature,
        seed_file,
        custom_seed_file,
        output,
        conditional,
        loglevel,
        max_paths,
    ):
        """
        Initializes the Graph-based Automated Path Synthesizer.

        Args:
            dalvik_path (str): Path to the Dalvik file.
            target_method (str): Target method name.
            class_name (str): Class name.
            parent_class (str): Parent class name.
            signature (str): Method signature.
            seed_file (str): Path to the seed file.
            custom_seed_file (str): Path to the custom seed file.
            conditional (bool): Flag indicating whether to consider conditional paths.
            append_instructions (bool): Flag indicating whether to append instructions.
            loglevel (str): Log level.
            max_paths (int): Maximum number of paths to consider.

        Returns:
            None
        """
        self.start_time = time.time()
        self.dalvik_path = dalvik_path
        self.target_method = target_method
        self.class_name = class_name
        self.parent_class = parent_class
        self.signature = signature
        self.seed_file = seed_file
        self.custom_seed_file = custom_seed_file
        self.output = output
        self.conditional = conditional
        self.loglevel = ""
        if loglevel == 10:
            self.loglevel = "debug"
        if loglevel == 20:
            self.loglevel = "verbose"
        self.max_paths = max_paths
        self._setup()

    def _setup(self):
        """
        Set up the Graph-based Automated Path Synthesizer.

        Retrieves necessary information from the Dalvik file, such as package name,
        main activity, and method signatures. Sets up data structures for analysis.

        Args:
            None

        Returns:
            None
        """
        ext = os.path.splitext(self.dalvik_path)[1]
        self.file_name = os.path.splitext(os.path.basename(self.dalvik_path))[
            0
        ]
        self.tmp_path = "/tmp/" + self.file_name + ".cache"
        disassembling_thread = Thread(
            target=self._disassemble_app,
            args=(ext,),
        )
        disassembling_thread.start()

        LOG.info("[+] ANALYZING APP")

        self.package_name = ""
        self.main_activity = []
        self.app_type = "apk"

        if ext == ".apk":
            self.dalvik, self.dx = myAndroguard.AnalyzeAPK(self.dalvik_path)
            self.manifest_xml = self.dalvik.get_android_manifest_xml()
            self.package_name = "L" + self.manifest_xml.get("package").replace(
                ".", "/"
            )
            icc_analysis.get_main_activities(self)

            icc_analysis.get_main_activity_aliases(
                self.main_activity, self.manifest_xml
            )
            LOG.debug(f"[+] MAIN ACTIVITY {self.main_activity}")
            self.target_sdk = -1
            target_sdk_ver = self.dalvik.get_target_sdk_version()
            if target_sdk_ver:
                self.target_sdk = int(self.dalvik.get_target_sdk_version())
            LOG.info(f"[+] TARGET SDK IS {self.target_sdk}")
            LOG.debug(f"[+] PACKAGE NAME {self.package_name}")
        elif ext == ".dex":
            self.app_type = "dex"
            self.dalvik, d, self.dx = AnalyzeDex(
                self.dalvik_path, session=None
            )
        else:
            LOG.error("ERROR: input file is not .dex or .apk")
            sys.exit(1)

        self.icc = dict()
        self.icc_string_analysis = defaultdict(set)
        self.content_providers = {}
        self.exported_components = {}

        self.condition_visited = deque()
        self.conditional_key = ""
        self.conditional_paths = defaultdict(list)

        self.reflection_paths = {}

        self.all_methods = defaultdict(set)
        self.search_list = {}
        self.call_sequences = set()

        self.json_output = {}

        self.starting_points = defaultdict(set)
        if self.signature:
            self.starting_points[self.signature] = set()
        self.save_testing_seeds = True
        self.custom_seeds = {}
        if self.target_method or self.signature or self.custom_seed_file:
            self.save_testing_seeds = False
        if self.custom_seed_file and os.path.exists(self.custom_seed_file):
            self.process_custom_seed()
        if self.seed_file:
            self._init_testing_seeds()
        self.signature_to_address = defaultdict(
            lambda: defaultdict(lambda: defaultdict(set))
        )
        self.icc_method_addresses = defaultdict(set)
        self.return_by = defaultdict(set)
        self.access_methods = {}
        self.methods_with_switches = {}
        self.object_instantiated = defaultdict(set)
        self.fragment_to_activity = defaultdict(set)

        self.testing_seeds = ""
        self.method_index = 0
        self.method_objs = defaultdict()

        LOG.info("[+] STARTING METHODS ANALYSIS")

        dalvik_disassembler.disassemble(self)

        LOG.info("[+] END METHODS ANALYSIS")
        self._save_testing_seeds()
        self.append_mode = False
        self.instruction = ""
        self.logs = ""
        self.classes = self.dx.classes.copy()
        self.public_xml = {}
        self.strings_xml = {}

        LOG.info("[+] RETRIEVING ICC INFORMATION")
        """
        from pyinstrument import Profiler

        profiler = Profiler()
        profiler.start()
        """
        icc_analysis.get_icc_info(self)
        """
        profiler.stop()
        profiler.print()
        """
        path_generation.get_reflection_calls(self)

        disassembling_thread.join()
        ui_id_finder.save_public_strings_xml(self)
        self._free_memory()
        self._init_stats()

    def _disassemble_app(self, ext):
        """
        Disassembles the application based on its file extension.

        Args:
            ext (str): File extension of the application.

        Returns:
            None
        """
        if ext == ".apk":
            dalvik_disassembler.run_apktool(self)
        else:
            dalvik_disassembler.run_baksmali(self)

    def _free_memory(self):
        """
        Frees memory by deleting Dalvik and Dex objects.

        Args:
            None

        Returns:
            None
        """
        self.dalvik = None
        self.dx = None
        gc.collect()

    def process_custom_seed(self):
        """
        Processes custom seeds from a file.

        Args:
            None

        Returns:
            None
        """
        with open(self.custom_seed_file, "r") as custom_seed_file:
            lines = custom_seed_file.readlines()
            for line in lines:
                if line.strip():
                    class_name = ""
                    parent_name = ""
                    splits = line.split()
                    for i in range(len(splits)):
                        if splits[i] == "-m":
                            method_name = splits[i + 1].replace('"', "")
                        if splits[i] == "-cls":
                            class_name = splits[i + 1].replace('"', "")
                        if splits[i] == "-p_cls":
                            parent_name = splits[i + 1].replace('"', "")
                    if method_name not in self.custom_seeds:
                        self.custom_seeds[method_name] = deque()
                    self.custom_seeds[method_name].append(
                        {
                            "class_name": class_name,
                            "parent_class": parent_name,
                        }
                    )

    def _init_stats(self):
        """
        Initializes statistics file for logging analysis results.

        Args:
            None

        Returns:
            None
        """
        stats_path = os.path.join(self.output, "stats.csv")
        if not os.path.exists(stats_path):
            with open(stats_path, "w") as stats_file:
                stats_writer = csv.writer(
                    stats_file,
                    delimiter=",",
                    quotechar='"',
                    quoting=csv.QUOTE_MINIMAL,
                )
                stats_writer.writerow(
                    [
                        "APP",
                        "TIME",
                        "REACHED METHODS",
                        "TOT. REACHABLE PATHS",
                        "REACHABLE CONDITIONAL PATHS",
                        "AVG. REACHABLE PATHS",
                        "UNIQUE PATHS",
                    ]
                )

    def _init_testing_seeds(self):
        """
        Initializes testing seeds directory.

        Args:
            None

        Returns:
            None
        """
        if not os.path.exists("./testing_seeds"):
            os.mkdir("./testing_seeds")
        testing_seeds_file = os.path.join(
            "testing_seeds", f"{self.file_name}.seed"
        )
        if os.path.exists(testing_seeds_file):
            with open(testing_seeds_file, "r") as log_file:
                signatures = log_file.readlines()
                for signature in signatures:
                    self.starting_points[signature.replace("\n", "")] = set()
                    self.save_testing_seeds = False
        else:
            self.save_testing_seeds = True

    def _save_testing_seeds(self):
        """
        Saves testing seeds to a file.

        Args:
            None

        Returns:
            None
        """
        testing_seeds_file = os.path.join(
            "testing_seeds", f"{self.file_name}.seed"
        )
        if not os.path.exists(testing_seeds_file):
            with open(testing_seeds_file, "w") as log_file:
                log_file.write(self.testing_seeds)

    def _save_stats(self):
        """
        Saves analysis statistics in csv format.

        Args:
            None

        Returns:
            None
        """
        self.stats_row[1] = time.time() - self.start_time
        self.stats_row[2] = len(self.solved_methods)
        self.stats_row[5] = 0
        for method in self.solved_methods:
            self.stats_row[5] += self.solved_methods[method]
        if self.stats_row[2] != 0:
            self.stats_row[5] /= self.stats_row[2]
        else:
            self.stats_row[5] = 0
        self.stats_row[5] = "{:.2f}".format(self.stats_row[5])
        stats_path = os.path.join(self.output, "stats.csv")
        with open(stats_path, "a") as stats_file:
            stats_writer = csv.writer(
                stats_file,
                delimiter=",",
                quotechar='"',
                quoting=csv.QUOTE_MINIMAL,
            )
            stats_writer.writerow(self.stats_row)
        app_out_path = os.path.join(self.output, self.file_name)
        if not os.path.exists(app_out_path):
            os.mkdir(app_out_path)
        with open(
            os.path.join(app_out_path, f"{self.file_name}.gaps-log"), "w"
        ) as log_file:
            log_file.write(self.logs)

    def _save_json_output(self):
        """
        Saves analysis output in JSON format.

        Args:
            None

        Returns:
            None
        """
        app_out_path = os.path.join(self.output, self.file_name)
        if not os.path.exists(app_out_path):
            os.mkdir(app_out_path)
        json_object = json.dumps(self.json_output, indent=4)
        with open(
            os.path.join(app_out_path, f"{self.file_name}-instr.json"),
            "w",
        ) as outfile:
            outfile.write(json_object)

    def start_path_finding(self):
        """
        Starts the path reconstruction process.

        Args:
            None

        Returns:
            None
        """
        LOG.info("[+] STARTING PATH RECONSTRUCTION")
        self.stats_row = [self.file_name, 0, 0, 0, 0, 0, 0]
        self.solved_methods = defaultdict(int)
        index = 0
        self.search_list = {}
        for instruction in self.starting_points:
            LOG.info(f"[+] METHOD {index}/{len(self.starting_points)-1}")
            index += 1
            self.call_sequences = set()
            self.instruction = instruction
            self.conditional_paths = defaultdict(list)
            self.path_index = 0
            (
                search_class_name,
                search_method_name,
            ) = method_utils.get_class_and_method(instruction, True)
            dict_2_start = {instruction: self.starting_points[instruction]}
            partial_paths = path_generation.find_path_smali(
                search_method_name,
                self,
                target_class=search_class_name,
                starting_points=dict_2_start,
                consider_hierarchy=False,
            )
            seen_parents = set()
            for partial_path in partial_paths:
                if partial_path[-1] in seen_parents:
                    continue
                seen_parents.add(partial_path[-1])
                path_generation.build_paths(
                    [partial_path],
                    self,
                    self.conditional,
                    max_paths=self.max_paths // len(partial_paths),
                )
        LOG.info("--- %s seconds ---" % (time.time() - self.start_time))
        self._save_stats()
        self._save_json_output()
