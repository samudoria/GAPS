import os
import re
import logging
import subprocess
from collections import deque, defaultdict
from difflib import SequenceMatcher

from . import path_generation
from . import method_utils
from . import data_flow_analysis

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# CODE
###############################################################################


def find_ui_id(last_path: list, gaps) -> [str, str]:
    """
    Finds the UI element ID and text based on the last instruction in a given path.

    Args:
        last_path (list): A list of instructions leading up to the current point of analysis.
        gaps (object): An object containing various attributes and methods to assist in finding the UI ID and text.

    Returns:
        [str, str]: A list containing the UI element ID and text, both as strings. Returns [None, None] if no relevant
        UI element is found.
    """
    last_instr = last_path[len(last_path) - 1]
    class_name, method_name = method_utils.get_class_and_method(
        last_instr, True
    )
    element_id, element_text = None, None
    save = True
    if "ID = " in last_instr:
        return element_id, element_text
    if method_name == "onScroll":
        element_id = "@@scroll"
        return element_id, element_text
    search_tag = "ID- " + last_instr
    if search_tag in gaps.search_list:
        return gaps.search_list[search_tag]
    method_arguments = ""
    if "(" in last_instr and ")" in last_instr:
        method_arguments = last_instr.split("(")[1].split(")")[0]
    if (
        "Landroid/view" in method_arguments
        or "Landroid/widget" in method_arguments
    ):
        element_id, element_text = _get_ui_id_or_text(
            class_name, method_name, last_path, gaps
        )
        if not element_id and not element_text:
            element_int_id = _get_int_id_from_MenuItem(
                last_path, gaps.tmp_path, gaps
            )
            save = False
            element_id = get_ui_id_from_int(element_int_id, gaps)
        if element_id and not element_text:
            element_text = _grep_element_text(element_id, gaps)
        if not element_id and not element_text:
            log = f"MISSING ID {last_instr}\n"
            if log not in gaps.logs:
                gaps.logs += log
    if not re.search(r"\(.*Landroid/view/MenuItem;.*\)", last_instr) and save:
        gaps.search_list[search_tag] = [element_id, element_text]
    return element_id, element_text


def use_ui_id_finder_on_paths(path: list, gaps) -> list:
    """
    Processes a path to find UI element IDs and texts, adding this info to the path.

    Args:
        path (list): List of instructions.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        tuple: Path with UI element IDs and texts added where applicable.
    """
    result = deque()
    str_path = str(path)
    signatures = str_path.count("> ")
    if signatures > 1:
        for i, instruction in enumerate(path):
            if instruction[0] == ">":
                element_id, element_text = find_ui_id(path[:i], gaps)
                result.append([element_id, element_text])
    else:
        element_id, element_text = find_ui_id(path, gaps)
        result.append([element_id, element_text])
    return result


def _grep_element_text(element_id, gaps):
    element_text = None
    grep = subprocess.Popen(
        f'grep -r "{element_id}" "{gaps.tmp_path}"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    output_grep = grep.communicate()[0].decode("utf-8").split("\n")
    for output in output_grep:
        if output.strip():
            if ".xml" in output and 'android:title="' in output:
                string_text = output.split('android:title="')[1].split('"')[0]
                if "@string/" in string_text:
                    string_id = string_text.split("/")[1]
                    element_text = get_string_xml(string_id, gaps)
                    return element_text
    return element_text


def add_ui_info_to_path(element_id, element_text, path, gaps):
    """
    Adds UI element ID and text to the last instruction in the path.

    Args:
        element_id (str): UI element ID.
        element_text (str): UI element text.
        path (list): List of instructions.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        tuple: Path with UI element ID and text added.
    """
    if element_id or element_text:
        path = list(path)
        last_inst = path[len(path) - 1]
        if element_id:
            if re.search(
                r"\(.*Landroid/view/MenuItem;.*\)",
                last_inst,
            ):
                additional_info = _get_text_id_from_MenuInflater(
                    path, element_id, gaps
                )
                if additional_info:
                    path[len(path) - 1] += (
                        ' {ID = "'
                        + element_id
                        + '", INFO = "'
                        + additional_info
                        + '"}'
                    )
                path.append("PRESS MENU")
            else:
                path[len(path) - 1] += ' {ID = "' + element_id + '"}'
        if element_text:
            if not element_id:
                element_id = "@@unkown"
            path[len(path) - 1] += (
                ' {ID = "' + element_id + '", INFO = "' + element_text + '"}'
            )
    return path


def _get_ui_id_or_text(
    class_name_callback: str, method_name: str, last_path: list, gaps
) -> [str, str]:
    """
    Searches for ID associated with the graphical element.

    Args:
        class_name_callback (str): Class name from the callback.
        method_name (str): Method name.
        last_path (list): List of instructions leading up to this point.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        [str, str]: UI element ID and text.
    """
    element_id, element_text = None, None

    if re.search(
        r"\(.*Landroid/view/MenuItem;.*\)", last_path[len(last_path) - 1]
    ):
        element_int_id = _get_int_id_from_MenuItem(
            last_path, gaps.tmp_path, gaps
        )
        if element_int_id:
            return (
                get_ui_id_from_int(element_int_id, gaps),
                element_text,
            )

    element_id = _get_id_from_xml(class_name_callback, method_name, gaps)
    if element_id:
        return element_id, element_text

    if method_name == "onCheckedChanged":
        method_name = "onCheckedChange"
    set_listener = (
        "set" + method_name[0].upper() + method_name[1:] + "Listener"
    )
    set_listener_paths = path_generation.find_path_smali(
        set_listener, gaps, explore=True, consider_hierarchy=False
    )
    # find the ui element's variable name or int id
    (
        object_class,
        object_name,
        element_int_id,
    ) = _get_variable_or_int_id(set_listener_paths, class_name_callback, gaps)

    if not object_class and not object_name and not element_int_id:
        (
            object_class,
            object_name,
            element_int_id,
        ) = _get_variable_or_int_id_via_proxy(
            set_listener_paths, class_name_callback, gaps
        )
    if object_class and object_name:
        target_object = object_class + ";->" + object_name
        object_paths = path_generation.find_path_smali(
            object_name,
            gaps,
            target_class=object_class,
            target_instruction=target_object,
            consider_hierarchy=False,
        )
        element_int_id = _get_int_id_from_variable(object_paths, gaps)
        if not element_int_id and len(object_paths) > 0:
            element_type = object_paths[0][0].split()[-1]
            element_text = _get_element_text_from_variable(
                target_object, element_type, gaps
            )
            if "ImageView" in object_paths[0][0].split()[-1]:
                element_int_id = _try_finding_image_view(target_object, gaps)
    if element_int_id:
        return get_ui_id_from_int(element_int_id, gaps), element_text

    return element_id, element_text


def _get_element_text_from_variable(
    target_object: str, element_type: str, gaps
) -> str:
    """
    Retrieves the element text from a variable.

    Args:
        target_object (str): Target object.
        element_type (str): Type of the element.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        str: Element text.
    """
    text_set = ""
    target_instruction = element_type + "->setText(Ljava/lang/CharSequence;)V"
    object_paths = path_generation.find_path_smali(
        "setText",
        gaps,
        target_class=element_type,
        target_instruction=target_instruction,
        consider_hierarchy=False,
    )
    for object_path in object_paths:
        registers = data_flow_analysis.get_registers(object_path[0])
        parameters = data_flow_analysis.points_to_analysis(
            object_path, 0, gaps
        )
        for path_dfa in parameters:
            if (
                registers[0] in parameters[path_dfa]
                and registers[1] in parameters[path_dfa]
            ):
                if "instruction" in parameters[path_dfa][registers[0]]:
                    object_used = parameters[path_dfa][registers[0]][
                        "instruction"
                    ]
                    if target_object in object_used:
                        text_instruction = parameters[path_dfa][registers[1]][
                            "instruction"
                        ]
                        if "const" in text_instruction.split()[0]:
                            text_set = path_generation.get_const_value(
                                text_instruction
                            )
                            if re.search(r"^\d+$", text_set):
                                string_int_id = hex(int(text_set))
                                text_set = get_string_xml(string_int_id, gaps)
                            if '"' in text_set:
                                text_set = text_set.replace('"', "")
                            return text_set
    return text_set


def _try_finding_image_view(target_object, gaps):
    image_paths = path_generation.find_path_smali(
        "setImageResource",
        gaps,
        target_class="Landroid/widget/ImageView",
        target_instruction="Landroid/widget/ImageView;->setImageResource(I)V",
        consider_hierarchy=False,
    )
    for image_path in image_paths:
        parameters = data_flow_analysis.points_to_analysis(
            image_path, 0, gaps, only_caller=True
        )
        for path_dfa in parameters:
            for reg in parameters[path_dfa]:
                if "instruction" in parameters[path_dfa][reg]:
                    parameter = parameters[path_dfa][reg]["instruction"]
                    if target_object in parameter:
                        element_int_id = _get_int_id_from_findViewById(
                            image_path, 0, gaps
                        )
                        return element_int_id
    return None


def get_ui_id_from_int(element_int_id: str, gaps) -> str:
    """
    Retrieves the UI ID from its integer representation.

    Args:
        element_int_id (str): Integer representation of the UI ID.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        str: UI ID.
    """
    element_id = ""
    if element_int_id in gaps.public_xml:
        element_id = gaps.public_xml[element_int_id]
    return element_id


def _get_int_id_from_variable(object_paths: list, gaps) -> str:
    """
    Retrieves the integer ID from a variable.

    Args:
        object_paths (list): Paths related to the object.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        str: Integer ID.
    """
    element_int_id = None
    for object_path in object_paths:
        if "put" in object_path[0].split()[0]:
            parameters = data_flow_analysis.points_to_analysis(
                object_path, 0, gaps, only_caller=True
            )
            for path_dfa in parameters:
                for reg in parameters[path_dfa]:
                    if "instruction" in parameters[path_dfa][reg]:
                        parameter = parameters[path_dfa][reg]["instruction"]
                        if "invoke" in parameter.split()[0] and (
                            "findViewById" in parameter
                            or "setImageResource" in parameter
                        ):
                            inst_index = parameters[path_dfa][reg][
                                "instruction_index"
                            ]
                            element_int_id = _get_int_id_from_findViewById(
                                object_path, inst_index, gaps
                            )
                            if element_int_id:
                                return element_int_id
    return element_int_id


def _get_variable_or_int_id(
    paths: list, class_name_callback: str, gaps
) -> [str, str, str]:
    """
    Retrieves variable or integer ID from paths.

    Args:
        paths (list): List of paths to analyze.
        class_name_callback (str): Callback class name.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        [str, str, str]: Object class, object name, and resource integer ID.
    """
    object_class, object_name, resource_int_id = None, None, None
    for path in paths:
        parameters = data_flow_analysis.points_to_analysis(
            path, 0, gaps, ignore_caller=True
        )
        for path_dfa in parameters:
            for reg in parameters[path_dfa]:
                if "instruction" in parameters[path_dfa][reg]:
                    parameter = parameters[path_dfa][reg]["instruction"]
                    if (
                        class_name_callback in parameter
                        and "new-instance" in parameter.split()[0]
                    ):
                        (
                            object_class,
                            object_name,
                            resource_int_id,
                        ) = _extract_variable_or_int_id(path, gaps)
                        if (object_class and object_name) or resource_int_id:
                            return object_class, object_name, resource_int_id
    return object_class, object_name, resource_int_id


def _extract_variable_or_int_id(path: list, gaps) -> [str, str, str]:
    """
    Extracts variable or integer ID from a path.

    Args:
        path (list): List of instructions.
        gaps (object): Object containing necessary data and methods for processing.

    Returns:
        [str, str, str]: Object class, object name, and resource integer ID.
    """
    object_class, object_name, resource_int_id = None, None, None
    parameters = data_flow_analysis.points_to_analysis(
        path, 0, gaps, only_caller=True
    )
    for path_dfa in parameters:
        for reg in parameters[path_dfa]:
            if "instruction" in parameters[path_dfa][reg]:
                parameter = parameters[path_dfa][reg]["instruction"]
                if (
                    "get-object" in parameter.split()[0]
                    and not object_class
                    and not object_name
                ):
                    (
                        object_class,
                        object_name,
                    ) = method_utils.get_class_and_method(parameter, True)
                    return (
                        object_class,
                        object_name,
                        resource_int_id,
                    )
                if "invoke" in parameter.split()[0]:
                    if (
                        "findViewById" in parameter
                        or "setImageResource" in parameter
                    ):
                        inst_index = parameters[path_dfa][reg][
                            "instruction_index"
                        ]
                        resource_int_id = _get_int_id_from_findViewById(
                            path, inst_index, gaps
                        )
                        if resource_int_id:
                            return (
                                object_class,
                                object_name,
                                resource_int_id,
                            )
    return (
        object_class,
        object_name,
        resource_int_id,
    )


def _get_variable_or_int_id_via_proxy(
    paths: list, class_name_callback: str, gaps
) -> [str, str, str]:
    """
    Extracts the variable or integer ID via proxy analysis.

    Args:
        paths (list): Paths to analyze.
        class_name_callback (str): Callback class name.
        gaps (object): Data and methods for processing.

    Returns:
        [str, str, str]: Object class, object name, and resource integer ID.
    """
    object_class, object_name = None, None
    resource_int_id = None
    for path in paths:
        obj_class, obj_name = method_utils.get_class_and_method(path[1], True)
        if len(obj_class) > 0 and obj_class in class_name_callback:
            target_object = obj_class + ";->" + obj_name
            object_paths = path_generation.find_path_smali(
                obj_name,
                gaps,
                target_class=obj_class,
                target_instruction=target_object,
                consider_hierarchy=False,
            )

            for variable_path in object_paths:
                class_name, method_name = method_utils.get_class_and_method(
                    variable_path[1], True
                )
                if (
                    class_name == class_name_callback
                    and method_name == "<init>"
                ):
                    (
                        object_class,
                        object_name,
                        resource_int_id,
                    ) = _extract_variable_or_int_id(path, gaps)
                    if (object_class and object_name) or resource_int_id:
                        return (
                            object_class,
                            object_name,
                            resource_int_id,
                        )
    return object_class, object_name, resource_int_id


def _get_int_id_from_findViewById(path: list, inst_index: int, gaps) -> int:
    """
    Extracts the integer ID from a findViewById method.

    Args:
        path (list): List of instructions.
        inst_index (int): Index of the instruction.
        gaps (object): Data and methods for processing.

    Returns:
        str: Resource integer ID.
    """
    resource_int_id = None
    parameters_id = data_flow_analysis.points_to_analysis(
        path, inst_index, gaps, ignore_caller=True
    )
    for path_dfa in parameters_id:
        for reg_id in parameters_id[path_dfa]:
            if "instruction" in parameters_id[path_dfa][reg_id]:
                parameter_id = parameters_id[path_dfa][reg_id]["instruction"]
                if "const" in parameter_id.split()[0]:
                    value = parameter_id.split()[-1]
                    if re.search(r"^\d+$", value):
                        resource_int_id = hex(int(value))
                        return resource_int_id
                if "get" in parameter_id.split()[0]:
                    (
                        class_name,
                        variable_name,
                    ) = method_utils.get_class_and_method(parameter_id, True)
                    only_class_name = class_name
                    if "$" in only_class_name:
                        only_class_name = only_class_name.split("$")[0]
                    only_class_name = only_class_name.split("/")[-1]
                    if only_class_name == "R":
                        return _lookup_var_in_R(
                            class_name, variable_name, gaps.tmp_path
                        )
                    result = data_flow_analysis.constant_propagation(
                        parameter_id, gaps
                    )
                    for path_var in result:
                        for val_var in result[path_var]:
                            if re.search(r"^\d+$", val_var):
                                resource_int_id = hex(int(val_var))
                                return resource_int_id
    return resource_int_id


def _lookup_var_in_R(
    class_name: str, variable_name: str, tmp_path: str
) -> str:
    """
    Looks up a variable in the R class.

    Args:
        class_name (str): Class name.
        variable_name (str): Variable name.
        tmp_path (str): Temporary path.

    Returns:
        str: Variable ID.
    """
    if "$" in class_name:
        class_name = class_name.replace("$", r"\$")
    find = subprocess.Popen(
        f'find "{tmp_path}" -type f -wholename "*/{class_name.split("/")[-1]}.smali"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    output_find = find.communicate()[0].decode("utf-8").split("\n")
    for file_path in output_find:
        if file_path.strip():
            if "$" in file_path:
                file_path = file_path.replace("$", r"\$")
            grep = subprocess.Popen(
                f'cat "{file_path}" | grep "{variable_name}:"',
                shell=True,
                stdout=subprocess.PIPE,
            )
            output_grep = grep.communicate()[0].decode("utf-8").split("\n")
            for result in output_grep:
                if result.strip():
                    return result.split()[-1]
    return None


def _get_int_id_from_MenuItem(last_path: list, tmp_path: str, gaps) -> str:
    """
    Extracts the integer ID from a MenuItem.

    Args:
        last_path (list): List of instructions.
        tmp_path (str): Temporary path.
        gaps (object): Data and methods for processing.

    Returns:
        str: Menu item integer ID.
    """
    menu_item_found = False
    int_id = None
    for i in range(len(last_path)):
        if_instr = last_path[i].split()[0]
        if "if" == if_instr[:2]:
            parameter_chain = data_flow_analysis.points_to_analysis(
                last_path, i, gaps
            )
            menu_item_found = False
            for path_dfa in parameter_chain:
                for reg in parameter_chain[path_dfa]:
                    if "instruction" in parameter_chain[path_dfa][reg]:
                        parameter = parameter_chain[path_dfa][reg][
                            "instruction"
                        ]
                        if "const" in parameter.split()[0]:
                            value = parameter.split()[-1]
                            if re.search(r"^\d+$", value):
                                int_id = hex(int(value))
                        elif "->" in parameter:
                            (
                                class_name,
                                method_name,
                            ) = method_utils.get_class_and_method(parameter)
                            if (
                                method_name == "getItemId"
                                or method_name == "getId"
                            ):
                                menu_item_found = True
                    if menu_item_found and int_id:
                        return int_id
    if not int_id:
        return _get_int_id_from_switch_payload(last_path, gaps)


def _string_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def _get_int_id_from_switch_payload(last_path: list, gaps) -> str:
    """
    Extracts the integer ID from a switch payload.

    Args:
        last_path (list): List of instructions.
        gaps (object): Data and methods for processing.

    Returns:
        str: Integer ID.
    """
    reference_instr = last_path[0]
    reference_instr_index = 0
    instructions_before_switch = 0
    switch = False
    for i, instruction in enumerate(last_path):
        if (
            "sparse-switch" not in instruction
            and "packed-switch" not in instruction
        ):
            instructions_before_switch += 1
        else:
            switch = True
            break
        instruction_type = instruction.split()[0]
        if (
            "goto" in instruction_type
            or "if" in instruction_type
            or "return" in instruction_type
        ):
            reference_instr = last_path[i + 1]
            reference_instr_index = i + 1
            instructions_before_switch = 0
    if not switch:
        return -1
    if instructions_before_switch > 5:
        instructions_before_switch = 5
    method_signature = last_path[len(last_path) - 1].split()[1]
    if method_signature in gaps.methods_with_switches:
        method_body = gaps.methods_with_switches[method_signature]
    else:
        return -1
    payload_labels = None
    last_label = None
    int_id = -1
    for i, line in enumerate(method_body):
        instr = line.split()[0]
        if "; " in line:
            line = line.replace("; ", ";")
        if "sparse-switch" == instr or "packed-switch" == instr:
            payload_labels = line
            continue
        if payload_labels and line == reference_instr:
            correct = True
            j = 0
            method_body_index = i - j
            while j < instructions_before_switch:
                instr_method_body = method_body[method_body_index]
                if i - j >= 0 and "label:" in instr_method_body:
                    instr_method_body = method_body[method_body_index - 1]
                    method_body_index -= 1
                if "; " in instr_method_body:
                    instr_method_body = instr_method_body.replace("; ", ";")
                if "[ " in instr_method_body:
                    instr_method_body = instr_method_body.split("[ ")[0]
                if (
                    _string_similarity(
                        last_path[reference_instr_index + j], instr_method_body
                    )
                    < 0.2
                ):
                    correct = False
                    break
                j += 1
                method_body_index -= 1
            if correct and last_label and last_label in payload_labels:
                gui_id = payload_labels.split(last_label)[0].split()[-1]
                int_id = -1
                if re.search(r"^\d+$", gui_id):
                    int_id = hex(int(gui_id))
                return int_id
        if line.startswith("label:") and payload_labels:
            last_label = ":" + line.split()[-1]
    return int_id


def get_string_xml(string_id: str, gaps) -> str:
    """
    Retrieves the string value from the strings.xml file.

    Args:
        string_id (str): String ID.
        gaps (object): Data and methods for processing.

    Returns:
        str: String value.
    """
    if not string_id:
        return ""
    if string_id in gaps.strings_xml:
        return gaps.strings_xml[string_id]
    return ""


def _get_text_id_from_MenuInflater(
    last_path: list, element_id: str, gaps
) -> str:
    """
    Extracts the text ID from a MenuInflater.

    Args:
        last_path (list): List of instructions.
        element_id (str): Element ID.
        gaps (object): Data and methods for processing.

    Returns:
        str: Element text.
    """
    last_instr = last_path[len(last_path) - 1]
    target_class_name, _ = method_utils.get_class_and_method(last_instr, True)
    inflate_paths = path_generation.find_path_smali(
        "inflate",
        gaps,
        target_class="Landroid/view/MenuInflater",
        consider_hierarchy=False,
    )
    for inflate_path in inflate_paths:
        _, inflate_method = method_utils.get_class_and_method(inflate_path[0])
        class_name, _ = method_utils.get_class_and_method(
            inflate_path[len(inflate_path) - 1], True
        )
        if class_name == target_class_name:
            parameters = data_flow_analysis.points_to_analysis(
                inflate_path, 0, gaps, ignore_caller=True
            )
            for path_dfa in parameters:
                for reg in parameters[path_dfa]:
                    if "instruction" in parameters[path_dfa][reg]:
                        parameter = parameters[path_dfa][reg]["instruction"]
                        if "const" in parameter.split()[0]:
                            value = data_flow_analysis.get_const_value(
                                parameter
                            )
                            if re.search(r"\d+", value):
                                menu_int_id = hex(int(value))
                                menu_id = get_ui_id_from_int(menu_int_id, gaps)
                                activity_xml_path = (
                                    gaps.tmp_path
                                    + "/res/menu/"
                                    + menu_id
                                    + ".xml"
                                )
                                element_info = get_value_from_xml(
                                    activity_xml_path, "title", element_id
                                )

                                if element_info and "@string/" in element_info:
                                    string_id = element_info.split("/")[1]
                                    element_info = get_string_xml(
                                        string_id, gaps
                                    )

                                return element_info
    return None


def _get_id_from_xml(class_name: str, identifier: str, gaps) -> str:
    """
    Retrieves the ID and type from the activity.xml file.

    Args:
        class_name (str): Class name.
        identifier (str): Identifier.
        gaps (object): Data and methods for processing.

    Returns:
        str: Element ID.
    """
    element_id = None
    # find the activity xml from invocations of setContentView
    paths = path_generation.find_path_smali(
        "setContentView",
        gaps,
        target_class=class_name,
        consider_hierarchy=False,
    )
    # find the numeric id
    activity_int_id = _get_int_id(paths, gaps)
    # find the id of the file
    activity_id = ""
    if activity_int_id in gaps.public_xml:
        activity_id = gaps.public_xml[activity_int_id]

    # look for the button text in the activity.xml file
    if activity_id:
        activity_xml_path = (
            gaps.tmp_path + "/res/layout/" + activity_id + ".xml"
        )
        element_id = get_value_from_xml(activity_xml_path, "id", identifier)

    return element_id


def _get_int_id(paths: list, gaps) -> str:
    """
    Retrieves the integer ID from paths.

    Args:
        paths (list): List of paths.
        gaps (object): Data and methods for processing.

    Returns:
        str: Integer ID.
    """
    id_ = -1
    for path in paths:
        parameters = data_flow_analysis.points_to_analysis(
            path, 0, gaps, ignore_caller=True
        )
        for path_dfa in parameters:
            for reg in parameters[path_dfa]:
                if "instruction" in parameters[path_dfa][reg]:
                    parameter = parameters[path_dfa][reg]["instruction"]
                    const_val = data_flow_analysis.get_const_value(parameter)
                    if "const" in parameter.split()[0] and re.search(
                        r"^\d+$", const_val
                    ):
                        id_ = hex(int(const_val))
                        break
    return id_


def get_value_from_xml(
    file_path: str, attribute: str, resource_id: str
) -> str:
    """
    Retrieves the value of an attribute in an XML file.

    Args:
        file_path (str): Path to the XML file.
        attribute (str): Attribute to retrieve.
        resource_id (str): Resource ID.

    Returns:
        str: Attribute value.
    """
    if resource_id and os.path.exists(file_path):
        lines = open(file_path, "r").readlines()
        for line in lines:
            if str(resource_id) in line and f'{attribute}="' in line:
                resource_value = line.split(f'{attribute}="')[1].split('"')[0]
                if "@id/" in resource_value:
                    resource_value = resource_value.split("/")[1]
                return resource_value
    return None


def save_public_strings_xml(gaps):
    """
    Saves the public strings from the public.xml and strings.xml file.

    Args:
        gaps (object): Data and methods for processing.
    """
    public_xml_path = os.path.join(gaps.tmp_path, "res/values/public.xml")
    if os.path.exists(public_xml_path):
        lines = open(public_xml_path, "r").readlines()
        for line in lines:
            if 'name="' in line and "id=" in line:
                resource_id = line.split('id="')[1].split('"')[0]
                resource_name = line.split('name="')[1].split('"')[0]
                gaps.public_xml[resource_id] = resource_name

    strings_xml_path = os.path.join(gaps.tmp_path, "res/values/strings.xml")
    if os.path.exists(strings_xml_path):
        lines = open(strings_xml_path, "r").readlines()
        for line in lines:
            if 'name="' in line:
                value = line.split(">")[1].split("<")[0]
                name = line.split('name="')[1].split('"')[0]
                gaps.strings_xml[name] = value
