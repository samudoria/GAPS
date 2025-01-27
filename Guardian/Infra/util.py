import os, subprocess, time
import re
from xml.etree import ElementTree as ET
from pathlib import Path

import configs


def slice_dict(dict, keys):
    return {k: dict[k] for k in keys}


def isInteger(s: str):
    try:
        int(s)
        return True
    except ValueError:
        return False


def transform_bounds(bounds: str):
    match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    match = [int(i) for i in match.group(1, 2, 3, 4)]
    return ((match[0], match[1]), (match[2], match[3]))


def in_bounds(bounds, point):
    return (
        point[0] >= bounds[0]
        and point[0] <= bounds[2]
        and point[1] >= bounds[1]
        and point[1] <= bounds[3]
    )


def adb_exec(cmd: str, sleep=0.5):
    # print(cmd)
    os.system("adb shell " + cmd)
    time.sleep(sleep)


def adb_input(cmd: str, sleep=0.5):
    adb_exec(f"input {cmd}", sleep)


def adb_pm(cmd: str, sleep=0.5):
    adb_exec(f"pm {cmd}", sleep)


def adb_pull(name, target=None):
    os.system(f"adb pull {name}" + f" {target}" if target else "")


def adb_tap_center(bounds, sleep=0.5):
    if type(bounds) == str:
        bounds = transform_bounds(bounds)
    adb_input(
        f"tap {(bounds[0][0] + bounds[1][0]) // 2} {(bounds[0][1] + bounds[1][1]) // 2}",
        sleep,
    )


def get_current_ui():
    adb_exec("uiautomator dump")
    adb_pull("/sdcard/window_dump.xml", "hierarchy.xml")
    return ET.parse("hierarchy.xml")


def save_current_ui(path):
    # print(str(path))
    adb_exec("uiautomator dump")
    adb_pull("/sdcard/window_dump.xml", str(path))


def save_current_screen(path):
    # print(str(path))
    os.system("adb exec-out screencap -p > " + str(path))


def get_current_screen():
    raise NotImplementedError("Cannot get current screen yet!")


def get_current_activity() -> str:
    return subprocess.check_output(
        [
            "adb",
            "shell",
            "dumpsys window windows | grep -E 'mCurrentFocus|mFocusedApp'",
        ]
    ).decode()


def get_package_name(apk_path) -> str:
    """Get the package name of an APK"""
    return (
        subprocess.check_output(["aapt", "dump", "badging", apk_path])
        .decode()
        .split("package: name='")[1]
        .split("'")[0]
    )


def get_app_name(apk_path) -> str:
    app_name_command = subprocess.Popen(
        f'aapt dump badging {apk_path} | grep "application-label:"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    app_name = app_name_command.communicate()[0].decode("utf-8").split("\n")
    for result in app_name:
        if result.strip():
            return (
                result.split("application-label:")[1].replace("'", "").strip()
            )
    return apk_path


def get_account(apk: str) -> tuple:
    """Get the account for an app"""
    info = configs.apk_info[apk]
    return info["username"], info["password"]


def check_activity(acts):
    if type(acts) is str:
        acts = [acts]
    cur_act = get_current_activity()
    # print('current activity ',cur_act)
    return any([act in cur_act for act in acts])


def install_apk(apk: str):
    # print(f"adb install -r {configs.apk_dir}/{apk}.apk")
    os.system(f"adb install -r {configs.apk_dir}/{apk}.apk")


def uninstall_pkg(pkg: str):
    os.system(f"adb uninstall {pkg}")


def check_installed(apk: str, pkg: str = None) -> bool:
    pkg = pkg if pkg else get_package_name(apk)
    return bool(
        subprocess.check_output(
            ["adb", "shell", "pm", "list", "packages", pkg]
        ).decode()
    )


def ensure_installed(apk, pkg: str = None):
    pkg = pkg if pkg else get_package_name(apk)
    if not check_installed(apk, pkg):
        install_apk(apk)
        return check_installed(apk, pkg)
    else:
        return True


def ensure_reinstalled(apk: str, pkg: str = None):
    pkg = pkg if pkg else get_package_name(apk)
    if check_installed(apk, pkg):
        uninstall_pkg(pkg)
    return ensure_installed(apk, pkg)


def uninstall_app(apk: str, pkg: str = None):
    pkg = pkg if pkg else get_package_name(apk)
    uninstall_pkg(pkg)


def start_app(pkg: str = None):
    if not pkg:
        return
    adb_exec(f"monkey -p {pkg} 1", 4)


def restart_app(pkg: str = None):
    if not pkg:
        return
    adb_exec(f"am force-stop {pkg}", 2)
    start_app(pkg)


def wait_for_activity(acts, timeout=5):
    if type(acts) is str:
        acts = [acts]
    for retry in range(timeout - 1):
        if check_activity(acts):
            return True
        time.sleep(2)
    if check_activity(acts):
        return True
    return False


import json

uia_to_toller = {
    "clickable": "cl",
    "long-clickable": "lcl",
    "scrollable": "scr",
    "checkable": "ch",
}


def concatStrings(l, d=";"):
    return d.join(filter(lambda x: x.strip(), l))


def jsonToET(json_str):
    dic = json.loads(json_str)

    def recursive_buildETfromDict(dic: dict):
        if "class" not in dic:
            return None
        root = ET.Element("node")
        root.set("package", "")
        root.set("class", dic["class"])
        root.set("bounds", dic["bound"])
        root.set("enabled", "true" if dic["en"] else "false")
        root.set("resource-id", str(dic["id"]).strip() if "id" in dic else "")

        for p in uia_to_toller:
            root.set(p, "true" if uia_to_toller[p] in dic else "false")
        root.set("content-desc", dic["cdesc"] if "cdesc" in dic else "")
        if "ch" in dic and dic["ch"]:
            for child in dic["ch"]:
                childNode = recursive_buildETfromDict(child)
                if childNode is not None:
                    root.append(childNode)
        return root

    return recursive_buildETfromDict(dic)
