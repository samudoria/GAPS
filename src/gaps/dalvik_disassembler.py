import subprocess
import random
import re
import os
import sys
import logging
import threading
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import method_utils
from . import myAndroguard

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# GLOBALS
###############################################################################

MAX_THREADS = 4

icc_methods = [
    "startService",
    "startForegroundService",
    "bindService",
    "bindIsolatedService",
    "bindServiceAsUser",
    "startIntentSender",
    "startActivity",
    "startActivityForResult",
    "startActivities",
    "sendBroadcast",
    "sendBroadcastAsUser",
    "sendBroadcastWithMultiplePermissions",
    "sendOrderedBroadcast",
    "sendOrderedBroadcastAsUser",
    "sendStickyBroadcast",
    "sendStickyBroadcastAsUser",
    "sendStickyOrderedBroadcast",
    "sendStickyOrderedBroadcastAsUser",
    "registerReceiver",
    "setContent",
    "setIntent",
]


analysis_blacklist = [
    r"(\[)?Lkotlin/.*",
    r"(\[)?Lkotlinx/.*",
    r"(\[)?Ljava/.*",
    r"(\[)?Ljavax/.*",
    r"(\[)?Landroidx/.*",
    r"(\[)?Ldalvik/.*",
    r"(\[)?Landroid/.*",
    r"L(\[)?Lcom/android/internal/util.*",
    r"L(\[)?Lorg/apache/.*",
    r"L(\[)?Lorg/json/.*",
    r"L(\[)?Lorg/w3c/dom/.*",
    r"L(\[)?Lorg/xml/sax.*",
    r"L(\[)?Lorg/xmlpull/v1/.*",
    r"L(\[)?Ljunit/.*",
]

package_name_blacklist = [
    r"(\[)?Landroid/.*",
    r"(\[)?Lcom/android/.*",
    r"(\[)?Ldalvik/.*",
    r"(\[)?Landroidx/.*",
    r"(\[)?Ljava/.*",
    r"(\[)?Ljavax/.*",
    r"(\[)?Ljunit/.*",
    r"(\[)?Lorg/xml.*",
    r"(\[)?Lkotlin/.*",
    r"(\[)?Lkotlinx/.*",
    r"(\[)?Lorg/jetbrains/.*",
    r"(\[)?Lcom/fasterxml/.*",
    r"(\[)?Lorg/json/.*",
    r"(\[)?Lorg/mozilla/.*",
    r"(\[)?Lorg/apache/.*",
    r"(\[)?Lssh/.*",
    r"(\[)?Lorg/w3c/.*",
    r"(\[)?Lorg/spongycastle/.*",
    r"(\[)?Lorg/bouncycastle/.*",
    r"(\[)?Lorg/joda/.*",
    r"(\[)?Lcom/tasermonkeys/.*",
    r"(\[)?Lorg/tukaani.*",
    r"(\[)?Lcom/ibm/.*",
    r"(\[)?Lorg/simpleframework/.*",
    r"(\[)?Lcom/kazy/.*",
    r"(\[)?Lcom/millennialmedia/.*",
    r"(\[)?Lcom/jumptap/.*",
    r"(\[)?Lorg/swiftp/.*",
    r"(\[)?Lcom/artfulbits/.*",
    r"(\[)?Lcom/bumptech/.*",
    r"(\[)?Lorg/jsoup/.*",
    r"(\[)?Lretrofit2/.*",
    r"(\[)?Lokhttp3/.*",
    r"(\[)?Lio/reactivex/.*",
    r"(\[)?Lcom/google/.*",
    r"(\[)?Lleakcanary/.*",
    r"(\[)?Lokio/.*",
    r"(\[)?Lcom/skydoves/.*",
    r"(\[)?Lde/mrapp/.*",
    r"(\[)?Lcom/actionbarsherlock/.*",
    r"(\[)?Lcom/flurry/.*",
    r"(\[)?Lorg/kxml2/.*",
    r"(\[)?Lorg/kobjects/.*",
    r"(\[)?Lorg/ksoap2/.*",
    r"(\[)?Lcom/twofortyfouram/.*",
    r"(\[)?Lcom/theartofdev/.*",
    r"(\[)?Leltos/simpledialogfragment/.*",
    r"(\[)?Lorg/acra/.*",
    r"(\[)?Lcom/itextpdf/.*",
    r"(\[)?Lcom/alimuzaffar/.*",
    r"(\[)?Lnet/vrallev/.*",
    r"(\[)?Lch/qos/logback/.*",
    r"(\[)?Lshark/.*",
    r"(\[)?Lcom/squareup/.*",
    r"(\[)?Lio/requery/.*",
    r"(\[)?Larrow/.*",
    r"(\[)?Lmyiconpack/.*",
    r"(\[)?Lio/flutter/.*",
]


###############################################################################
# CODE
###############################################################################


def disassemble(gaps):
    """
    Disassembles the provided file using apktool or baksmali.

    Args:
        gaps (object): Instance of GAPS.

    Returns:
        None
    """
    global current_threads, lock
    all_methods = [defaultdict(set), defaultdict(set)]
    for blacklisted in package_name_blacklist:
        if re.search(blacklisted, gaps.package_name):
            package_name_blacklist.remove(blacklisted)

    for blacklisted in analysis_blacklist:
        if re.search(blacklisted, gaps.package_name):
            analysis_blacklist.remove(blacklisted)

    combined = "(" + ")|(".join(package_name_blacklist) + ")"

    combined_avoid_analysis = "(" + ")|(".join(analysis_blacklist) + ")"

    args = deque()

    for method in gaps.dx.get_methods():
        if method.is_android_api():
            continue

        m = method.get_method()
        method_name = str(m)

        class_name_parent, _ = method_utils.get_class_and_method(
            method_name, True
        )
        if re.match(combined_avoid_analysis, class_name_parent):
            continue

        gaps.method_objs[gaps.method_index] = method

        method_index = gaps.method_index

        args.append(
            [
                gaps,
                method,
                method_index,
                combined,
                all_methods,
            ]
        )
        gaps.method_index += 1

    with ThreadPoolExecutor() as e:

        futures = deque()

        for x in args:
            futures.append(
                e.submit(process_method, x[0], x[1], x[2], x[3], x[4])
            )

    for future in as_completed(futures):
        pass

    save_testing_seeds(gaps, all_methods)


def process_method(
    gaps, method, method_index: int, combined: str, all_methods: list
) -> str:
    """
    Processes the methods during disassembly.

    Args:
        gaps (object): Instance of GAPS.
        method (object): Method object.
        method_index (int): Index of the method.
        combined (str): Combined blacklist patterns.
        all_methods (list): List of all methods.

    Returns:
        str: Completion status message.
    """
    basic_blocks = method.get_basic_blocks()
    for bb in basic_blocks:
        instructions = list(bb.get_instructions())
        for instruction in instructions:
            inst_out = instruction.get_output()
            if "(" in inst_out:
                inst_out = inst_out.replace(" ", "").replace(",", ", ")
            str_inst = "{} {}".format(instruction.get_name(), inst_out)
            process_instr(
                gaps,
                str_inst,
                method,
                method_index,
                combined,
                all_methods,
            )
    return "finish"


def process_instr(
    gaps,
    str_inst: str,
    method,
    method_index: int,
    combined: str,
    all_methods: list,
):
    """
    Processes instructions during disassembly.

    Args:
        gaps (object): Instance of GAPS.
        str_inst (str): Instruction string.
        method: Method object.
        method_index (int): Index of the method.
        combined (str): Combined blacklist patterns.
        all_methods (list): List of all methods.

    Returns:
        None
    """
    class_name, method_name = method_utils.get_class_and_method(str_inst, True)
    instr_type = str_inst.split()[0]
    parent_method = _get_method_name(method)
    class_name_parent, method_name_parent = method_utils.get_class_and_method(
        parent_method, True
    )
    rest_signature_parent = parent_method.split(";->")[1].split()[0]
    gaps.all_methods[rest_signature_parent].add(parent_method)
    entry = method_index
    if (
        "invoke" in instr_type
        and "this$0" not in str_inst
        and len(method_name) > 0
    ):
        rest_of_signature = str_inst.split("->")[1]
        gaps.signature_to_address[method_name][rest_of_signature][
            class_name
        ].add(entry)
        if (
            not gaps.target_method
            and not gaps.signature
            and gaps.save_testing_seeds
        ):
            if gaps.package_name in class_name:
                all_methods[0][str_inst.split()[-1]].add(entry)
            elif not re.match(combined, class_name):
                all_methods[1][str_inst.split()[-1]].add(entry)
    if (
        "put" in instr_type
        and ";->" in str_inst
        and "this$0" not in str_inst
        and len(method_name) > 0
    ):
        rest_of_signature = str_inst.split("->")[1].split()[0]
        gaps.signature_to_address[method_name][rest_of_signature][
            class_name
        ].add(entry)
        object_type = str_inst.split()[-1]

        if ";" in object_type:
            gaps.object_instantiated[object_type].add(entry)
    if (
        "get" in instr_type
        and ";->" in str_inst
        and "this$0" not in str_inst
        and len(method_name) > 0
    ):
        object_type = str_inst.split()[-1]

        if ";" in object_type:
            gaps.object_instantiated[object_type.split(";")[0]].add(entry)
    if "check-cast" in instr_type:
        object_type = str_inst.split()[-1]

        if ";" in object_type:
            gaps.object_instantiated[object_type.split(";")[0]].add(entry)
    if method_name in icc_methods or re.search(
        r"\(.*Landroid/app/PendingIntent;.*\)", str_inst
    ):
        gaps.icc_method_addresses[str_inst.split()[-1]].add(entry)
    if "const-class" == instr_type:
        string_class = str_inst.split()[-1].replace(";", "")
        gaps.icc_string_analysis[string_class].add(entry)
    if "sparse-switch" in str_inst or "packed-switch" in str_inst:
        if parent_method.split()[1] not in gaps.methods_with_switches:
            method_body = myAndroguard.get_whole_method(
                method.basic_blocks.get()
            )
            gaps.methods_with_switches[parent_method.split()[1]] = method_body
    if "return" in instr_type:
        gaps.return_by[parent_method.split()[1]].add(entry)
    if ";->access$" in parent_method:
        gaps.access_methods[parent_method.split()[1]] = str_inst
    if gaps.target_method:
        if (
            method_name == gaps.target_method
            and "invoke" in instr_type
            and (
                not gaps.class_name
                or (gaps.class_name and gaps.class_name == class_name)
            )
            and (
                not gaps.parent_class
                or (
                    gaps.parent_class
                    and gaps.parent_class in class_name_parent
                )
            )
        ):
            key = str_inst.split(",")[-1][1:]
            gaps.starting_points[key].add(entry)
    elif (
        gaps.class_name
        and gaps.class_name == class_name
        and (
            not gaps.parent_class
            or (gaps.parent_class and gaps.parent_class in class_name_parent)
        )
    ):
        key = str_inst.split(",")[-1][1:]
        gaps.starting_points[key].add(entry)
    elif (
        (gaps.seed_file or gaps.signature)
        and str_inst.split()[-1] in gaps.starting_points
        and "invoke" in instr_type
    ):
        gaps.starting_points[str_inst.split()[-1]].add(entry)
    elif gaps.custom_seeds:
        if method_name in gaps.custom_seeds:
            custom_seeds_for_method = gaps.custom_seeds[method_name]
            for custom_seed in custom_seeds_for_method:
                class_seed = custom_seed["class_name"]
                parent_seed = custom_seed["parent_class"]
                # or (class_seed.strip() and class_name == parent_seed)
                if (
                    class_seed.strip()
                    and class_name == class_seed
                    and parent_seed == class_name_parent
                ):
                    gaps.starting_points[str_inst.split()[-1]].add(entry)


def _get_method_name(method):
    """
    Retrieves the method name.

    Args:
        method: Method object.

    Returns:
        str: Method name.
    """
    method_name = str(method.get_method())
    if "[access" in method_name:
        method_name = (
            "> " + method_name.split("[access")[0].replace(" ", "") + " <"
        )
    return method_name


def basic_blocks_2_graph(
    gaps,
    method,
) -> defaultdict:
    """
    Converts basic blocks to a graph representation.

    Args:
        gaps (object): Instance of GAPS.
        method: Method object.

    Returns:
        defaultdict: Graph representation of basic blocks.
    """
    graph = defaultdict(set)
    m = method.get_method()
    method_name = _get_method_name(method)
    if method_name in gaps.search_list:
        return gaps.search_list[method_name]
    offset_method = m.get_address()
    translate = dict()
    translate[-1] = method_name
    basic_blocks = method.get_basic_blocks()
    for bb in basic_blocks:
        instructions = list(bb.get_instructions())
        offset_inst = bb.get_start() + offset_method
        for inst in instructions[:-1]:
            inst_out = inst.get_output()
            if "(" in inst_out:
                inst_out = inst_out.replace(" ", "").replace(",", ", ")
            str_inst = "{} {}".format(inst.get_name(), inst_out)
            translate[offset_inst] = str_inst

            next_inst_offset = offset_inst + inst.get_length()

            graph[next_inst_offset].add(offset_inst)

            offset_inst = next_inst_offset
        # multiple destinations ?
        last_inst = instructions[-1]
        # node
        inst_out = last_inst.get_output()
        if "(" in inst_out:
            inst_out = inst_out.replace(" ", "").replace(",", ", ")
        str_inst = "{} {}".format(last_inst.get_name(), inst_out)
        translate[offset_inst] = str_inst
        # edges
        for child in bb.childs:
            child_offset = child[1] + offset_method
            graph[child_offset].add(offset_inst)
    gaps.search_list[method_name] = graph, translate
    return graph, translate


def save_testing_seeds(gaps, all_methods: list):
    """
    Saves testing seeds.

    Args:
        gaps (object): Instance of GAPS.
        all_methods (list): List of all methods.

    Returns:
        None
    """
    if not gaps.save_testing_seeds:
        return
    max_random_methods = 50
    random_method = 0
    methods_list = list(all_methods[0].keys())
    meth_dict = all_methods[0]
    step = 0
    while random_method < max_random_methods:
        if len(methods_list) == 0:
            methods_list = list(all_methods[1].keys())
            if len(methods_list) == 0:
                break
            meth_dict = all_methods[1]
            step += 1
            if step == 2:
                break
        random_index = random.randint(0, len(methods_list) - 1)
        picked_method = methods_list[random_index]
        gaps.starting_points[picked_method] = meth_dict[picked_method]
        random_method += 1
        gaps.testing_seeds += picked_method + "\n"
        methods_list.pop(random_index)


def resolve_access_method(access_signature: str, gaps) -> str:
    """
    Resolves access methods.

    Args:
        access_signature (str): Access signature.
        gaps (object): Instance of GAPS.

    Returns:
        str: Resolved access method.
    """
    if access_signature in gaps.access_methods:
        return gaps.access_methods[access_signature]
    return ""


def run_apktool(gaps):
    """
    Runs apktool for disassembly.

    Args:
        gaps (object): Instance of GAPS.

    Returns:
        None
    """
    LOG.info(f"[+] STARTING APK DISASSEMBLY IN {gaps.tmp_path}")
    cmd = f'apktool d -f --no-assets "{gaps.dalvik_path}" -o "{gaps.tmp_path}"'
    subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not os.path.exists(gaps.tmp_path):
        LOG.error("[-] ERROR IN DISASSEMBLY")
        sys.exit(0)
    LOG.info(f"[+] DISASSEMBLED IN {gaps.tmp_path}")


def run_baksmali(gaps):
    """
    Runs baksmali for disassembly.

    Args:
        gaps (object): Instance of GAPS.

    Returns:
        None
    """
    LOG.info(f"[+] STARTING DEX DISASSEMBLY IN {gaps.tmp_path}")
    subprocess.run(
        f'baksmali d "{gaps.dalvik_path}" -o "{gaps.tmp_path}"',
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not os.path.exists(gaps.tmp_path):
        LOG.error("[-] ERROR IN DISASSEMBLY")
        sys.exit(0)
    LOG.info(f"[+] DISASSEMBLED IN {gaps.tmp_path}")
