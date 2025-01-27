import logging
import re
from collections import deque

from . import path_generation
from . import method_utils
from . import data_flow_analysis

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# GLOBALS
###############################################################################

android_manifest_tag = "{http://schemas.android.com/apk/res/android}"

black_listed_actions = [
    r"android\.intent\.action.*",
    r"android\.appwidget\.action.*",
    r"android\.bluetooth\.adapter\.action.*",
    r"android\.bluetooth\.device\.action.*",
]

black_list_actions = "(" + ")|(".join(black_listed_actions) + ")"


###############################################################################
# CODE
###############################################################################


def _get_actions_intent_filters(
    itemtype: str, name: str, gaps, action_to_dest: dict
):
    """
    Retrieves intent filters for a given item type.

    Args:
        itemtype (str): Type of the item (activity, service, receiver).
        name (str): Name of the item.
        gaps: Gaps object.
        action_to_dest (dict): Dictionary mapping action to destination.

    Returns:
        None
    """
    dest = "L" + name.replace(".", "/")
    for action, intent_name in gaps.dalvik.get_intent_filters(
        itemtype, name
    ).items():
        if action == "action":
            for action in intent_name:
                if dest not in gaps.icc:
                    gaps.icc[dest] = deque()
                gaps.icc[dest].append(action)
                if action not in action_to_dest:
                    action_to_dest[action] = deque()
                action_to_dest[action] = dest


def _get_content_provider_authorities(gaps):
    """
    Retrieves content provider authorities from the manifest.

    Args:
        gaps: Gaps object.

    Returns:
        None
    """
    components = gaps.manifest_xml.find("application").findall("provider")
    if not components:
        return
    for component in components:
        authority = component.get("android:authorities")
        name = component.get("android:name")
        if not name or not authority:
            continue
        smali_name = "L" + name.replace(".", "/")
        gaps.content_providers[smali_name] = authority


def get_icc_info(gaps):
    """
    Retrieves inter-component communication (ICC) information.

    Args:
        gaps: Gaps object.

    Returns:
        None
    """

    action_to_dest = dict()

    if gaps.app_type == "apk":
        _save_exported_components(gaps)

        activities = gaps.dalvik.get_activities()
        activityString = "activity"
        for activity in activities:
            smali_activity = "L" + activity.replace(".", "/")
            if _check_if_exported(smali_activity, gaps) or (
                gaps.target_sdk <= 31
            ):
                _get_actions_intent_filters(
                    activityString, activity, gaps, action_to_dest
                )

        services = gaps.dalvik.get_services()
        serviceString = "service"
        for service in services:
            _get_actions_intent_filters(
                serviceString, service, gaps, action_to_dest
            )

        receivers = gaps.dalvik.get_receivers()
        receiverString = "receiver"
        for receiver in receivers:
            _get_actions_intent_filters(
                receiverString, receiver, gaps, action_to_dest
            )

        _get_content_provider_authorities(gaps)

    register_receivers = path_generation.find_path_smali(
        "registerReceiver",
        gaps,
        consider_hierarchy=False,
        explore=True,
    )
    for register_receiver in register_receivers:
        dest = None
        class_name, method_name = method_utils.get_class_and_method(
            register_receiver[0], True
        )
        if (
            method_name != "registerReceiver"
            or "invoke" not in register_receiver[0].split()[0]
        ):
            continue
        parameters = data_flow_analysis.points_to_analysis(
            register_receiver, 0, gaps, ignore_caller=True
        )
        receiver_register_regs = data_flow_analysis.get_registers(
            register_receiver[0], ignore_caller=True
        )
        if len(receiver_register_regs) == 0:
            continue
        receiver_register = receiver_register_regs[0]
        for path in parameters:
            if (
                receiver_register in parameters[path]
                and "instruction" in parameters[path][receiver_register]
            ):
                parameter = parameters[path][receiver_register]["instruction"]

                if "get" in parameter.split()[0]:
                    dest = _get_subclass_from_object(parameter, gaps)
                if "new-instance" in parameter.split()[0]:
                    dest = parameter.split()[-1].replace(";", "")
                if dest:
                    _parse_intent_filter(
                        dest,
                        register_receiver,
                        action_to_dest,
                        gaps,
                    )
            if not dest:
                dest, _ = method_utils.get_class_and_method(
                    register_receiver[len(register_receiver) - 1], True
                )
                _parse_intent_filter(
                    dest,
                    register_receiver,
                    action_to_dest,
                    gaps,
                )

    icc_paths = path_generation.find_path_smali_icc(gaps, max_path_len=500)
    for icc_path in icc_paths:
        reg_map = data_flow_analysis.generate_reg_args_map(icc_path[0])

        filtered_reg_map = dict()
        for reg in reg_map:
            if reg_map[reg] == "Landroid/app/PendingIntent":
                filtered_reg_map[reg] = reg_map[reg]
            if reg_map[reg] == "Landroid/content/Intent":
                filtered_reg_map[reg] = reg_map[reg]

        parameters_intent = data_flow_analysis.points_to_analysis(
            icc_path, 0, gaps, reg_map=filtered_reg_map
        )
        for path_pta in parameters_intent:
            for reg in parameters_intent[path_pta]:
                if "instruction" in parameters_intent[path_pta][reg]:
                    parameter_intent = parameters_intent[path_pta][reg][
                        "instruction"
                    ]
                    if (
                        "new-instance" in parameter_intent.split()[0]
                        and (
                            "Landroid/content/Intent;" in parameter_intent
                            or "Landroid/app/PendingIntent;"
                            in parameter_intent
                        )
                        and path_pta != icc_path
                    ):
                        icc_path = path_pta
                        break
                    if "invoke" in parameter_intent.split()[0]:
                        consts = data_flow_analysis.constant_propagation_return_values(
                            parameter_intent.split()[-1], gaps
                        )
                        for const_propr_path in consts:
                            icc_path = const_propr_path
                            break
            _process_intent_declaration(
                icc_path, gaps.icc, action_to_dest, gaps
            )


def _process_intent_declaration(icc_path, dictionary, action_to_dest, gaps):
    for i in range(len(icc_path)):
        node_class, node_method = method_utils.get_class_and_method(
            icc_path[i]
        )
        if node_class == "Landroid/content/Intent" and (
            node_method == "setAction"
            or node_method == "setComponent"
            or node_method == "setClass"
            or node_method == "setClassName"
            or node_method == "<init>"
        ):
            reg_map = data_flow_analysis.generate_reg_args_map(icc_path[i])

            filtered_reg_map = dict()
            for reg in reg_map:
                if reg_map[reg] == "Ljava/lang/Class":
                    filtered_reg_map[reg] = reg_map[reg]
                if reg_map[reg] == "Ljava/lang/String":
                    filtered_reg_map[reg] = reg_map[reg]

            parameters = data_flow_analysis.points_to_analysis(
                icc_path, i, gaps, reg_map=filtered_reg_map
            )
            for path in parameters:
                for reg in parameters[path]:
                    if "instruction" in parameters[path][reg]:
                        parameter = parameters[path][reg]["instruction"]
                        parameter_type = parameter.split()[0]
                        method_arguments = None
                        return_type = None
                        consts = None
                        if "invoke" in parameter_type and "(" in parameter:
                            method_arguments = parameter.split("(")[1].split(
                                ")"
                            )[0]
                            return_type = parameter.split(")")[-1]
                        if "const" in parameter_type:
                            destination_argument = parameter.split()[-1]
                            if (
                                node_method == "setComponent"
                                or node_method == "setClass"
                                or node_method == "setClassName"
                            ):
                                destination_argument = (
                                    method_utils.convert_java_class_to_smali(
                                        destination_argument
                                    )
                                ) + ";"

                            _set_new_destination(
                                destination_argument,
                                path,
                                dictionary,
                                action_to_dest,
                            )
                        elif (
                            "get" in parameter_type
                            and (
                                "Ljava/lang/Class;" in parameter
                                or "Ljava/lang/String;" in parameter
                            )
                        ) or (
                            "invoke" in parameter_type
                            and method_arguments
                            and (
                                "Ljava/lang/Class;" in method_arguments
                                or "Ljava/lang/String;" in method_arguments
                            )
                        ):
                            consts = data_flow_analysis.constant_propagation(
                                parameter, gaps
                            )
                        elif (
                            "invoke" in parameter_type
                            and return_type
                            and (
                                "Ljava/lang/Class;" == return_type
                                or "Ljava/lang/String;" == return_type
                            )
                        ):
                            consts = data_flow_analysis.constant_propagation_return_values(
                                parameter.split()[-1], gaps
                            )
                        if consts:
                            for const_propr_path in consts:
                                destination_argument = consts[const_propr_path]
                                if type(destination_argument) is list:
                                    for (
                                        destination_found
                                    ) in destination_argument:
                                        if (
                                            node_method == "setComponent"
                                            or node_method == "setClass"
                                            or node_method == "setClassName"
                                        ):
                                            destination_found = (
                                                method_utils.convert_java_class_to_smali(
                                                    destination_found
                                                )
                                                + ";"
                                            )
                                        _set_new_destination(
                                            destination_found,
                                            path,
                                            dictionary,
                                            action_to_dest,
                                        )
                                else:
                                    if (
                                        node_method == "setComponent"
                                        or node_method == "setClass"
                                        or node_method == "setClassName"
                                    ):
                                        destination_argument = (
                                            method_utils.convert_java_class_to_smali(
                                                destination_argument
                                            )
                                            + ";"
                                        )
                                    _set_new_destination(
                                        destination_argument,
                                        path,
                                        dictionary,
                                        action_to_dest,
                                    )


def _set_new_destination(
    destination: str, path: list, dictionary: dict, action_to_dest: dict
):
    """
    Sets a new destination based on a given destination string.

    Args:
        destination (str): Destination string.
        path (list): Path information.
        dictionary: dictionary to save results.
        action_to_dest (dict): Dictionary mapping action to destination.

    Returns:
        None
    """
    dest = None
    if ";" in destination:
        dest = destination.replace(";", "")
    else:
        if destination in action_to_dest:
            dest = action_to_dest[destination]
    if dest:
        if dest not in dictionary:
            dictionary[dest] = deque()
        save = True
        for paths in dictionary[dest]:
            if paths[-1] == path[-1]:
                save = False
        if save:
            dictionary[dest].append(path)


def _get_subclass_from_object(parameter: dict, gaps) -> str:
    """
    Retrieves subclass information from an object.

    Args:
        parameter (dict): Parameter information.
        gaps: Gaps object.

    Returns:
        str: Subclass information.
    """
    dest = None
    class_name, object_name = method_utils.get_class_and_method(
        parameter, True
    )
    object_paths = path_generation.find_path_smali(
        object_name,
        gaps,
        target_class=class_name,
        target_instruction=parameter.split()[-2],
        consider_hierarchy=False,
        explore=True,
    )
    for object_path in object_paths:
        parameters = data_flow_analysis.points_to_analysis(
            object_path, 0, gaps, only_caller=True
        )
        for path in parameters:
            for reg in parameters[path]:
                if "instruction" in parameters[path][reg]:
                    parameter = parameters[path][reg]["instruction"]
                    if "new-instance" in parameter.split()[0]:
                        dest = parameter.split()[-1].replace(";", "")
                        return dest
    return dest


def _parse_intent_filter(
    dest: str,
    icc_path: list,
    action_to_dest: dict,
    gaps,
):
    """
    Parses intent filters.

    Args:
        dest (str): Destination.
        icc_path (list): ICC path information.
        action_to_dest (dict): Dictionary mapping action to destination.
        icc (dict): ICC information.
        gaps: Gaps object.

    Returns:
        None
    """
    reg_map = data_flow_analysis.generate_reg_args_map(icc_path[0])

    filtered_reg_map = dict()
    for reg in reg_map:
        if reg_map[reg] == "Landroid/content/IntentFilter":
            filtered_reg_map[reg] = reg_map[reg]

    parameters_intent = data_flow_analysis.points_to_analysis(
        icc_path, 0, gaps, reg_map=filtered_reg_map
    )
    for path_pta in parameters_intent:
        for reg in parameters_intent[path_pta]:
            if "instruction" in parameters_intent[path_pta][reg]:
                parameter_intent = parameters_intent[path_pta][reg][
                    "instruction"
                ]
                if (
                    "new-instance" in parameter_intent
                    and "Landroid/content/IntentFilter;" in parameter_intent
                    and path_pta != icc_path
                ):
                    icc_path = path_pta
                    break
    for i in range(len(icc_path)):
        class_name, method_name = method_utils.get_class_and_method(
            icc_path[i]
        )
        if class_name == "Landroid/content/IntentFilter" and (
            method_name == "addAction" or method_name == "<init>"
        ):
            reg_map = data_flow_analysis.generate_reg_args_map(icc_path[i])

            filtered_reg_map = dict()
            for reg in reg_map:
                if reg_map[reg] == "Ljava/lang/Class":
                    filtered_reg_map[reg] = reg_map[reg]
                if reg_map[reg] == "Ljava/lang/String":
                    filtered_reg_map[reg] = reg_map[reg]

            parameters = data_flow_analysis.points_to_analysis(
                icc_path, i, gaps, reg_map=filtered_reg_map
            )
            param_regs = data_flow_analysis.get_registers(
                icc_path[i], ignore_caller=True
            )
            param_reg = None
            if len(param_regs) > 0:
                param_reg = param_regs[0]
            for path in parameters:
                if param_reg and param_reg in parameters[path]:
                    if "instruction" in parameters[path][param_reg]:
                        parameter = parameters[path][param_reg]["instruction"]
                        parameter_type = parameter.split()[0]
                        method_arguments = None
                        return_type = None
                        consts = None
                        if "invoke" in parameter_type and "(" in parameter:
                            method_arguments = parameter.split("(")[1].split(
                                ")"
                            )[0]
                            return_type = parameter.split(")")[-1]
                        if "const" in parameter_type:
                            action = parameter.split()[-1]
                            if '"' in action:
                                action = action.replace('"', "")
                            if action not in action_to_dest:
                                action_to_dest[action] = deque()
                            action_to_dest[action] = dest
                            if dest not in gaps.icc:
                                gaps.icc[dest] = deque()
                            gaps.icc[dest].append(action)
                        elif (
                            "get" in parameter_type
                            and (
                                "Ljava/lang/Class;" in parameter
                                or "Ljava/lang/String;" in parameter
                            )
                        ) or (
                            "invoke" in parameter_type
                            and method_arguments
                            and (
                                "Ljava/lang/Class;" in method_arguments
                                or "Ljava/lang/String;" in method_arguments
                            )
                        ):
                            consts = data_flow_analysis.constant_propagation(
                                parameter, gaps
                            )
                        elif (
                            "invoke" in parameter_type
                            and return_type
                            and (
                                "Ljava/lang/Class;" == return_type
                                or "Ljava/lang/String;" == return_type
                            )
                        ):
                            consts = data_flow_analysis.constant_propagation_return_values(
                                parameter.split()[-1], gaps
                            )
                        if consts:
                            for const_propr_path in consts:
                                dest = None
                                destination_argument = consts[const_propr_path]
                                if type(destination_argument) is list:
                                    for (
                                        destination_found
                                    ) in destination_argument:
                                        _set_new_destination(
                                            destination_found,
                                            path,
                                            gaps.icc,
                                            action_to_dest,
                                        )
                                else:
                                    _set_new_destination(
                                        destination_argument,
                                        path,
                                        gaps.icc,
                                        action_to_dest,
                                    )


def get_main_activity_aliases(main_activities, manifest):
    """
    Retrieves main activity aliases.

    Args:
        main_activities: Main activity information.
        manifest: Manifest information.

    Returns:
        None
    """
    activity_aliases = manifest.find("application").findall("activity-alias")
    if not activity_aliases:
        return
    for main_activity in main_activities:
        for activity_alias in activity_aliases:
            target_activity = activity_alias.get(
                f"{android_manifest_tag}targetActivity"
            )
            class_name = activity_alias.get(f"{android_manifest_tag}name")
            if not target_activity or not class_name:
                break
            smali_target_activity = method_utils.convert_java_class_to_smali(
                target_activity
            )
            smali_class_name = method_utils.convert_java_class_to_smali(
                class_name
            )
            if (
                smali_class_name in main_activities
                or smali_target_activity in main_activities
            ):
                if smali_class_name not in main_activities:
                    main_activities.append(smali_class_name)
                if smali_target_activity not in main_activities:
                    main_activities.append(smali_target_activity)


def find_icc_comm(last_inst: str, gaps, entry_points) -> list:
    """
    Finds inter-component communication.

    Args:
        last_inst (str): Last instruction.
        gaps: Gaps object.

    Returns:
        list: ICC communication paths.
    """
    class_name, _ = method_utils.get_class_and_method(last_inst, True)
    if class_name in gaps.main_activity or (
        "$" in class_name and class_name.split("$")[0] in gaps.main_activity
    ):
        main_activity_node = tuple(["MAIN ACTIVITY"])
        entry_points.add(main_activity_node)
        return [main_activity_node]
    icc_paths = _find_icc_smali(class_name, gaps, entry_points)
    if len(icc_paths) == 0 and class_name in gaps.icc_string_analysis:
        dict_2_start = {class_name + ";": gaps.icc_string_analysis[class_name]}
        icc_paths = path_generation.find_path_smali(
            class_name + " sa",
            gaps,
            starting_points=dict_2_start,
        )
    return icc_paths


def _find_icc_smali(class_name: str, gaps, entry_points) -> list:
    """
    Finds ICC information from Smali.

    Args:
        class_name (str): Class name.
        dictionart (dict) : used to look for results.
        gaps: Gaps object.

    Returns:
        list: ICC information.
    """
    res = deque()
    super_classes = path_generation.get_root_class_hierarchy(class_name, gaps)
    super_class = ""
    if len(super_classes) > 0:
        super_class = super_classes[-1]
    if "Landroid/app/Application" in super_class:
        main_activity_node = tuple(["MAIN ACTIVITY"])
        entry_points.add(main_activity_node)
        return [main_activity_node]
    component_type = None
    if "Activity" in super_class:
        component_type = "activity"
    elif "Service" in super_class:
        component_type = "service"
    elif "Receiver" in super_class:
        component_type = "receiver"
    if class_name in gaps.icc:
        intent_type = "start"
        if component_type == "receiver":
            intent_type = "broadcast"
        elif component_type == "activity":
            intent_type = "start-activity"
        elif component_type == "service":
            intent_type = "start-service"
        else:
            intent_type = "start"
        intent_type += " -a"
        for icc_info in gaps.icc[class_name]:
            if type(icc_info) is str:
                to_send_action = icc_info
                if '"' in to_send_action:
                    to_send_action = to_send_action.replace('"', "").replace(
                        "\\", ""
                    )
                if not re.match(black_list_actions, to_send_action):
                    entry = tuple(
                        [
                            'SEND INTENT {ACTION = "'
                            + to_send_action
                            + '", TYPE = "'
                            + intent_type
                            + '"}'
                        ]
                    )
                    res.append(entry)
                    entry_points.add(entry)
            else:
                res.append(icc_info)
        if _check_if_exported(class_name, gaps):
            package_name = gaps.package_name[1:].replace("/", ".")
            class_name = class_name[1:].replace("/", ".")
            fully_qual = package_name + "/" + class_name
            entry = tuple(
                [
                    'SEND INTENT {ACTION = "'
                    + fully_qual
                    + '", TYPE = "start -n"}'
                ]
            )
            res.append(entry)
            entry_points.add(entry)
    return res


def get_main_activities(gaps):
    """
    Retrieves main activities.

    Args:
        gaps: Gaps object.

    Returns:
        None
    """
    if gaps.dalvik.get_main_activities():
        java_main_activities = gaps.dalvik.get_main_activities()
        app_name = gaps.manifest_xml.find("application").get(
            "{http://schemas.android.com/apk/res/android}name"
        )
        if app_name:
            java_main_activities.add(app_name)
        for java_main_activity in java_main_activities:
            smali_main_activity = method_utils.convert_java_class_to_smali(
                java_main_activity
            )
            if (
                gaps.package_name not in smali_main_activity
                and smali_main_activity.startswith("L/")
            ) or smali_main_activity.count("/") < 2:

                smali_main_activity = smali_main_activity[1:]
                if smali_main_activity[0] != "/":
                    smali_main_activity = "/" + smali_main_activity
                smali_main_activity = gaps.package_name + smali_main_activity
            gaps.main_activity.append(smali_main_activity)


def _save_exported_components(gaps):
    """
    Saves exported components.

    Args:
        gaps: Gaps object.

    Returns:
        None
    """
    component_types = ["activity", "service", "receiver"]
    for component_type in component_types:
        components = gaps.manifest_xml.findall(
            f"./application/{component_type}"
        )
        if not components:
            continue
        for component in components:
            component_name_full = component.get(
                "{http://schemas.android.com/apk/res/android}name"
            ).replace(".", "/")
            if gaps.package_name not in component_name_full:
                component_name_full = gaps.package_name + component_name_full
            gaps.exported_components[component_name_full] = False
            permission = component.get(
                "{http://schemas.android.com/apk/res/android}permission"
            )
            if (
                component.get(
                    "{http://schemas.android.com/apk/res/android}exported"
                )
                == "true"
                and not permission
            ):
                gaps.exported_components[component_name_full] = True


def _check_if_exported(class_name: str, gaps) -> bool:
    """
    Checks if a component is exported.

    Args:
        class_name (str): Class name.
        gaps: Gaps object.

    Returns:
        bool: True if exported, False otherwise.
    """
    if class_name not in gaps.exported_components:
        return False
    return gaps.exported_components[class_name]
