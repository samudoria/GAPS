#!/usr/bin/python3
import argparse
import os
import subprocess as subp
import sys
import time
import json
import frida
import threading
import csv
import threading

from com.dtmilano.android.viewclient import ViewClient


class LLMThread(threading.Thread):
    def __init__(self, apk_path, activity, _id):
        self.apk_path = apk_path
        self.activity = activity
        self._id = _id
        threading.Thread.__init__(self)

    def run(self):
        cmd = f'python Guardian/run.py -a "{self.apk_path}" -t "interact with the application to help me explore" -m 15 -c {self.activity}'
        if self._id:
            cmd += f" -id {self._id}"
        print(cmd)
        p = subp.Popen(
            cmd,
            shell=True,
            stdout=subp.PIPE,
            stderr=subp.PIPE,
        )
        print(p.communicate()[1].decode().strip())


class GAPSRUN:

    def __init__(self, apk_path, output, manual_setup, frida_bool):
        self.apk_path = apk_path
        self.output = output
        self.stats_file_path = os.path.join(self.output, "stats.csv")
        if not os.path.exists(self.stats_file_path):
            print(f"Missing stats file at: {self.stats_file_path}")
            sys.exit(1)
        self.manual_setup = manual_setup
        self.avc_device = None
        self.vc = None
        self.frida_device = None
        self.frida_bool = frida_bool
        self.method_reached = False
        self.package_name = ""
        self.log = ""
        self.frida_script_name = "fridaHooks.js"
        self.hook_dir = self.output
        self.hook_path = os.path.join(self.hook_dir, self.frida_script_name)
        if not os.path.exists(self.hook_path):
            with open(self.hook_path, "w") as _:
                pass

    def spawn_added(self, spawn):
        event.set()
        if spawn.identifier.startswith(self.package_name):
            session = self.frida_device.attach(spawn.pid)
            try:
                script = session.create_script(open(self.hook_path).read())
                script.on("message", self.on_message)
                script.load()
            except:
                pass
            self.frida_device.resume(spawn.pid)

    def on_message(self, message, data):
        if message["type"] == "send":
            comm = message["payload"]
            if not self.method_reached:
                print("[+] Received response")
                print(comm)
            self.method_reached = True

    def extract_arguments(self, method_arg):
        i = 0
        args = []
        isArray = False
        while i < len(method_arg):
            # class or interface
            if method_arg[i] == "L":
                if method_arg[i - 1] == "[":
                    isArray = True

                # check array
                if isArray:
                    args.append(
                        "[L" + method_arg[i + 1 : method_arg.find(";")] + ";"
                    )
                    isArray = False
                else:
                    args.append(method_arg[i + 1 : method_arg.find(";")])

                i = method_arg.find(";") + 1
                method_arg = method_arg.replace(";", " ", 1)

                continue

            # Int
            if method_arg[i] == "I":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[I")
                    isArray = False
                else:
                    args.append("int")

            # Boolean
            if method_arg[i] == "Z":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[Z")
                    isArray = False
                else:
                    args.append("boolean")

            # Float
            if method_arg[i] == "F":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[F")
                    isArray = False
                else:
                    args.append("float")

            # Long
            if method_arg[i] == "J":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[J")
                    isArray = False
                else:
                    args.append("long")

            # Double
            if method_arg[i] == "D":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[D")
                    isArray = False
                else:
                    args.append("double")

            # Char
            if method_arg[i] == "C":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[C")
                    isArray = False
                else:
                    args.append("char")

            # Byte
            if method_arg[i] == "B":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[B")
                    isArray = False
                else:
                    args.append("byte")

            # Short
            if method_arg[i] == "S":
                if method_arg[i - 1] == "[":
                    isArray = True

                if isArray:
                    args.append("[S")
                    isArray = False
                else:
                    args.append("short")

            i += 1

        return args

    def save(self, javascript):
        if not os.path.exists(self.hook_dir):
            os.makedirs(self.hook_dir)

        with open(self.hook_path, "w") as f:
            f.write(javascript)

    def create_javascript(self, class_method):
        if class_method == "CONDITIONAL":
            return ""
        javascript = "Java.perform(function() {\n"

        full_class_name = class_method.split(";->")[0][1:].replace("/", ".")
        class_name = "class_hook"
        javascript += (
            "    var "
            + class_name
            + " = Java.use('"
            + full_class_name
            + "');\n\n"
        )
        # extract method
        full_method_name = class_method.split(";->")[1]
        method_name = full_method_name.split("(")[0]
        if method_name == "<init>":
            method_name = "$init"
        method_arg = full_method_name.split("(")[1].split(")")[0]

        # args extract
        if len(method_arg) == 0:  # args is not exist
            javascript += (
                "    "
                + class_name
                + "."
                + method_name
                + ".overload().implementation = function(){\n"
            )
            javascript += (
                "        send('[Method] "
                + full_class_name
                + "."
                + method_name
                + "() reached');\n"
            )

            # create retval
            javascript += "        var retval = this." + method_name + "();\n"
            # return method
            javascript += "        return retval;\n"

            javascript += "    };\n\n"

        else:  # args exist
            args_list = self.extract_arguments(method_arg)

            args_string = ""
            args_len = len(args_list)
            args_quota_added = []

            for i in range(args_len):
                # replace / to .
                args_list[i] = args_list[i].replace("/", ".")
                args_quota_added.append("'" + args_list[i] + "'")
                # arg string create
                args_string += "arg" + str(i)
                # if last arg
                if i != args_len - 1:
                    args_string += ","

            javascript += (
                "    "
                + class_name
                + "."
                + method_name
                + ".overload("
                + ",".join(args_quota_added)
                + ").implementation = function("
                + args_string
                + "){\n"
            )

            # print hook method name
            javascript += (
                "        send('[Method] "
                + full_class_name
                + "."
                + method_name
                + "("
                + ",".join(args_list)
                + ") reached');\n"
            )

            # create retval
            javascript += (
                "        var retval = this."
                + method_name
                + "("
                + args_string
                + ");\n"
            )

            # return method
            javascript += "        return retval;\n"

            javascript += "    };\n\n"

        javascript += "});\n"
        return javascript

    def get_package_name(self, apk_path):
        """get the package name of an app"""
        p1 = subp.Popen(
            ["aapt", "dump", "badging", apk_path], stdout=subp.PIPE
        )
        p2 = subp.Popen(
            ["grep", r"package:\ name"],
            stdin=p1.stdout,
            stdout=subp.PIPE,
            stderr=subp.DEVNULL,
        )
        p3 = subp.Popen(
            ["cut", "-c", "15-"], stdin=p2.stdout, stdout=subp.PIPE
        )
        p4 = subp.Popen(
            ["awk", "{print $1}"], stdin=p3.stdout, stdout=subp.PIPE
        )
        return p4.communicate()[0].decode().strip()

    def get_main_activity(self, apk_path):
        """get the main activity of an app"""
        p1 = subp.Popen(
            ["aapt", "dump", "badging", apk_path], stdout=subp.PIPE
        )
        p2 = subp.Popen(
            ["grep", "launchable-activity"],
            stdin=p1.stdout,
            stdout=subp.PIPE,
            stderr=subp.DEVNULL,
        )
        p3 = subp.Popen(
            ["awk", "{print $2}"], stdin=p2.stdout, stdout=subp.PIPE
        )
        p4 = subp.Popen(["cut", "-c6-"], stdin=p3.stdout, stdout=subp.PIPE)
        return p4.communicate()[0].decode().strip()

    def get_main_component(self, apk_path):
        """gets the main activity component by combining the app package and app main activity"""
        app_package_name = self.get_package_name(apk_path)
        app_main_activity = self.get_main_activity(apk_path)
        return app_package_name + "/" + app_main_activity

    def get_serialno(self):
        """get serial number of device"""
        return subp.check_output(["adb", "get-serialno"]).decode().strip()

    def force_dump(self, vc):
        """force dump of the screen despite errors"""
        attempts = 0
        while attempts < 10:
            try:
                attempts += 1
                vc.dump(-1, sleep=1)
                break
            except:
                pass

    def check_current_activity(self, activity):
        cycles = 0
        while True:
            get_current_focus = subp.Popen(
                "adb shell dumpsys window | grep mCurrentFocus",
                shell=True,
                stdout=subp.PIPE,
            )
            communicate = get_current_focus.communicate()
            if len(communicate) > 0:
                if activity in str(communicate):
                    print(f"[+] CURRENT FOCUS {activity}")
                    return True
            if cycles > 5:
                return False
            time.sleep(5)
            cycles += 1

    def scroll_find_click(self, vc, comp_id):
        # manual scrolling
        tries = 2
        scroll = 0
        while True:
            self.force_dump(vc)
            if vc.findViewById(comp_id):
                vc.findViewById(comp_id).touch()
                break
            if scroll > 5:
                subp.Popen(
                    "adb shell input swipe 300 300 500 1000",
                    shell=True,
                    stdout=subp.DEVNULL,
                    stderr=subp.DEVNULL,
                )
                vc.sleep(1)
                tries -= 1
                scroll = 0
                if tries == 0:
                    break
            else:
                subp.Popen(
                    "adb shell input swipe 500 1000  300 300",
                    shell=True,
                    stdout=subp.DEVNULL,
                    stderr=subp.DEVNULL,
                )
                vc.sleep(1)
                scroll += 1

    def perform_action(self, vc, instruction, package_name):
        if instruction[0] == "intent":
            print(f"[+] SENT INTENT FOR {instruction[1]}")
            if instruction[1] == "android.intent.action.MAIN":
                return 0
            if instruction[1].startswith("android.intent.action"):
                self.log += "unsupported intent " + instruction[1] + " \n"
                return 0
            subp.Popen(
                f"adb shell am {instruction[2]} {instruction[1]}",
                shell=True,
                stdout=subp.PIPE,
            )
            return 0
        if instruction[0] == "press menu":
            print("[+] PRESSED MENU")
            self.avc_device.shell("input keyevent KEYCODE_MENU")
            return 0
        if instruction[0] == "main activity":
            return 0
        if len(instruction) > 2:
            correct_activity = True
        else:
            correct_activity = self.check_current_activity(instruction[0])
        if correct_activity:
            self.force_dump(vc)
            if instruction[1] == "<unknown>":
                return -2
            try:
                comp_id = f"{package_name}:id/{instruction[1]}"
                vc.findViewByIdOrRaise(comp_id).touch()
            except:
                try:
                    if len(instruction) > 2:
                        vc.findViewWithText(instruction[2]).touch()
                    else:
                        self.scroll_find_click(vc, comp_id)
                except:
                    self.log += (
                        "missing id " + instruction[1] + " not found \n"
                    )
                    return -1

            print(f"[+] CLICKED {instruction[1]}")
            vc.sleep(1)
        else:
            return -1
        return 0

    def update_csv(self, app_name, tot_methods, methods_por):
        rows = []
        app_por = 0
        if tot_methods > 0:
            app_por = "{:.2f}".format(
                float((len(methods_por) / tot_methods) * 100)
            )
        with open(self.stats_file_path, "r") as stats_file:
            reader = csv.reader(stats_file)
            header = next(reader)
            if header[-1] != "PoR":
                header.append("PoR")
            rows.append(header)
            for row in reader:
                if row[0] == app_name:
                    if len(row) == 8:
                        row[7] = app_por
                    else:
                        row.append(app_por)
                rows.append(row)

        with open(self.stats_file_path, "w") as stats_file:
            writer = csv.writer(stats_file)
            writer.writerows(rows)

    def uninstall_app(self, package_name):
        print("[+] UNINSTALLING APP")
        subp.Popen(
            ["adb", "shell", "pm", "uninstall", package_name], stdout=subp.PIPE
        )

    def start_app(self, package_name):
        print("[+] APP STARTING")
        subp.Popen(
            f"adb shell monkey -p {package_name} -c android.intent.category.LAUNCHER 1",
            shell=True,
            stdout=subp.DEVNULL,
            stderr=subp.DEVNULL,
        )

    def stop_app(self, app_pkg_name):
        print("[+] APP STOPPING")
        subp.call(
            f"adb shell am force-stop {app_pkg_name}",
            shell=True,
            stdout=subp.DEVNULL,
            stderr=subp.DEVNULL,
        )

    def use_llms(self, instruction):
        if len(instruction) == 2:
            activity, _id = instruction
        else:
            activity, _id = instruction[0], None

        if _id == "<unknown>":
            _id = None

        attempts = 1

        while attempts > 0:
            if self.frida_bool and self.method_reached:
                break
            llmThread = LLMThread(self.apk_path, activity, _id)
            llmThread.start()
            llmThread.join()

            status = self.perform_action(
                self.vc, instruction, self.package_name
            )
            if status > 0:
                break
            attempts -= 1

    def _process_method(self, class_method, json_paths):
        methods_por = {}
        print(f"[+] LOOKING FOR {class_method}")
        if self.frida_bool:
            self.save("")
            frida_script = self.create_javascript(class_method)
            self.save(frida_script)
            print("[+] CREATED FRIDA SCRIPT\n")
        frida_err = False
        self.method_reached = False
        if self.frida_bool:
            try:
                pid = self.frida_device.spawn([self.package_name])
                session = self.frida_device.attach(pid)
                script = session.create_script(open(self.hook_path).read())
                script.on("message", self.on_message)
                script.load()

                self.frida_device.resume(pid)
            except Exception as e:
                frida_err = True
                pass
        else:
            self.start_app(self.package_name)
        if frida_err:
            self.log += "could not hook " + class_method + " \n "
            print(f"[!] ERROR COULD NOT HOOK {class_method}")
            # return tot_methods, methods_por
            self.stop_app(self.package_name)
            time.sleep(5)
            self.start_app(self.package_name)

        seen_paths = set()
        traversable_paths = []
        for key in json_paths[class_method]:
            path = json_paths[class_method][key]["path"]
            path_key = ""
            if path[0][0] == "intent":
                continue
            for element in path:
                path_key += str(element) + " "
            if path_key in seen_paths:
                print("already visited")
                continue
            seen_paths.add(path_key)
            traversable_paths.append(path)
        for path in traversable_paths:
            """
            if frida_err:
                frida_err_again = True
                attempts = 0
                for method_to_hook in json_paths[class_method][key][
                    "call_sequence"
                ]:
                    attempts += 1
                    if attempts > 5:
                        break
                    method_to_hook = method_to_hook.split()[1]
                    print(method_to_hook)
                    frida_script = self.create_javascript(method_to_hook)
                    self.save(frida_script)
                    try:
                        if self.frida_bool and self.method_reached:
                            print("[*] PATH SUCCESSFULLY VISITED!\n")
                            if class_method not in methods_por:
                                methods_por[class_method] = 0
                            methods_por[class_method] += 1
                            break
                        pid = self.frida_device.spawn([self.package_name])
                        session = self.frida_device.attach(pid)
                        script = session.create_script(
                            open(self.hook_path).read()
                        )
                        script.on("message", self.on_message)
                        script.load()

                        self.frida_device.resume(pid)
                        frida_err_again = False
                    except Exception:
                        self.stop_app(self.package_name)
                        time.sleep(5)
                        self.start_app(self.package_name)
                        pass
                    if not frida_err_again:
                        break
            if self.frida_bool and frida_err:
                self.log += (
                    "could not hook anything in the callsequence of "
                    + class_method
                    + " \n "
                )
                self.stop_app(self.package_name)
                time.sleep(5)
                self.start_app(self.package_name)
                continue
            """
            self.force_dump(self.vc)
            self.vc.sleep(1)
            self.avc_device.startActivity(
                component=self.get_main_component(self.apk_path)
            )
            self.vc.sleep(1)
            for i in range(len(path)):
                if type(path[i]) is str:
                    self.start_app(self.package_name)
                    self.vc.sleep(2)
                    pass
                elif type(path[i]) is list:
                    self.vc.sleep(5)
                    status = self.perform_action(
                        self.vc, path[i], self.package_name
                    )
                    if status == -1 or status == -2:
                        print("[+] USING LLMs")
                        self.use_llms(path[i])
                    self.vc.sleep(5)
                if self.frida_bool and self.method_reached:
                    break
            if self.frida_bool and self.method_reached:
                print("[*] PATH SUCCESSFULLY VISITED!\n")
                if class_method not in methods_por:
                    methods_por[class_method] = 0
                methods_por[class_method] += 1
                break
            print("-" * 100)
            if class_method in methods_por:
                break
        subp.call(f"adb shell am force-stop {self.package_name}", shell=True)
        self.save("")
        return methods_por

    def run(self, json_path, target):
        tot_methods = 0
        methods_por = {}
        app_name = os.path.splitext(os.path.basename(self.apk_path))[0]
        with open(self.stats_file_path, "r") as stats_file:
            reader = csv.reader(stats_file)
            header = next(reader)
            if header[-1] != "PoR":
                header.append("PoR")
            for row in reader:
                if row[0] == app_name and len(row) == 8:
                    sys.exit(1)
        self.avc_device, serialno = ViewClient.connectToDeviceOrExit(
            serialno=self.get_serialno()
        )

        if self.frida_bool:
            subp.run(
                'adb shell "su -c /data/local/tmp/frida-server -D &"',
                shell=True,
            )
            self.frida_device = frida.get_usb_device()
            self.frida_device.on("spawn-added", self.spawn_added)
            self.frida_device.enable_spawn_gating()

        ViewClient.sleep(4)

        self.package_name = self.get_package_name(self.apk_path).replace(
            "'", ""
        )

        print("[+] INSTALLING APP")
        install_status = subp.Popen(
            ["adb", "install", "-r", "-g", self.apk_path], stderr=subp.PIPE
        )

        print(install_status.communicate())

        adb_packages = subp.Popen(
            "adb shell pm list package", shell=True, stdout=subp.PIPE
        )
        list_packages = adb_packages.communicate()[0].decode()
        installed = False
        for pkg in list_packages.split("\n"):
            if self.package_name in pkg:
                installed = True
        if not installed:
            self.update_csv(app_name, tot_methods, methods_por)
            print("[+] APP NOT INSTALLED")
            return

        print("[+] INSTALLATION SUCCESSFUL")

        self.start_app(self.package_name)

        print("[+] CONNECTING TO VIEW CLIENT\n")
        while True:
            try:
                self.vc = ViewClient(self.avc_device, serialno)
                break
            except ValueError:
                pass

        if self.manual_setup:
            print("[?] Initial setup (CTRL+C to end)")
            try:
                sys.stdin.read()
            except KeyboardInterrupt:
                pass

        with open(json_path, "r") as json_file:
            json_paths = json.load(json_file)

        if target:
            update_methods_por = self._process_method(target, json_paths)
            tot_methods += 1
            methods_por.update(update_methods_por)
        else:
            tot_methods = len(json_paths)
            for i, class_method in enumerate(json_paths):
                print(f"[+] METHOD {str(i)}/{str(tot_methods)}")
                update_methods_por = self._process_method(
                    class_method, json_paths
                )
                methods_por.update(update_methods_por)

        self.uninstall_app(self.package_name)
        self.update_csv(app_name, tot_methods, methods_por)

        with open(
            os.path.join(self.output, app_name, app_name + "_run.gaps-log"),
            "w",
        ) as log_file:
            log_file.write(self.log)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", help="APK path file to run", required=True
    )
    parser.add_argument("-o", "--output", help="Output directory")
    parser.add_argument(
        "-instr", "--instructions", help="json instruction file", required=True
    )
    parser.add_argument(
        "-frida", "--frida", help="add frida hooks", action="store_true"
    )
    parser.add_argument(
        "-ms",
        "--manual_setup",
        help="Introduce a manual setup",
        action="store_true",
    )
    parser.add_argument(
        "-t",
        "--target",
        help="target a method",
    )
    args = parser.parse_args(sys.argv[1:])

    event = threading.Event()

    output = "./out"
    if args.output:
        output = args.output

    if not os.path.exists(output):
        os.mkdir(output)

    if args.input and args.instructions:
        apk_path = args.input
        gaps_run = GAPSRUN(apk_path, output, args.manual_setup, args.frida)
        gaps_run.run(args.instructions, args.target)
