import re
import subprocess
import sys
import logging
import networkx as nx
import matplotlib.pyplot as plt
import time
from collections import deque, defaultdict
from itertools import groupby

from . import method_utils
from . import conditional_path_generation
from . import icc_analysis
from . import ui_id_finder
from . import data_flow_analysis
from . import dalvik_disassembler

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# CODE
###############################################################################

activity_life_cycle = [
    "onCreate",
    "onStart",
    "onResume",
    "onRestart",
    "onStop",
    "onPause",
    "onDestroy",
]

dont_look_superclass = activity_life_cycle + [
    "onKeyUp",
    "onClick",
]

###############################################################################
# CODE
###############################################################################


def find_path_smali_icc(
    gaps,
    acyclic: bool = False,
    max_path_len: int = 200,
    explore: bool = True,
) -> list:
    """
    Finds paths in Smali inter-component communication (ICC).

    Args:
        gaps: Object containing information about gaps.
        acyclic (bool, optional): Whether to consider acyclic paths. Defaults to False.
        max_path_len (int, optional): Maximum length of the path. Defaults to 200.
        explore (bool, optional): Whether to explore paths. Defaults to True.

    Returns:
        list: List of found paths.
    """
    if len(gaps.icc_method_addresses) == 0:
        LOG.error("[-] ICC METHODS NOT FOUND\n")
        return deque()

    return _breadth_first_search_graph(
        gaps,
        gaps.icc_method_addresses,
        explore,
    )


def find_path_smali(
    target_method: str,
    gaps,
    target_class: str = None,
    target_instruction: str = None,
    starting_points: dict = None,
    explore: bool = False,
    consider_hierarchy: bool = True,
) -> list:
    """
    Finds paths in Smali code.

    Args:
        target_method (str): The target method string.
        gaps: Object containing information about gaps.
        target_class (str, optional): The target class string. Defaults to None.
        target_instruction (str, optional): The target instruction string. Defaults to None.
        starting_points (dict, optional): Starting points for the search. Defaults to None.
        explore (bool, optional): Whether to explore paths. Defaults to False.
        consider_hierarchy (bool, optional): Whether to consider subclasses. Defaults to True.

    Returns:
        list: List of found paths.
    """
    if not target_method.strip():
        return deque()

    search = None
    if target_instruction:
        search = target_instruction
    elif target_class:
        search = f"{target_class};->{target_method}"
    else:
        search = f";->{target_method}"

    search += f" {consider_hierarchy}"

    if search and search in gaps.search_list:
        paths = gaps.search_list[search]
        return paths

    old_search = ""
    if consider_hierarchy:
        old_search = search.replace(str(consider_hierarchy), "False")

    # find starting points
    if not starting_points and old_search not in gaps.search_list:
        starting_points = defaultdict(set)
        if not target_instruction:
            if target_method in gaps.signature_to_address:
                for method in gaps.signature_to_address[target_method]:
                    classes = gaps.signature_to_address[target_method][method]
                    for class_name in classes:
                        if not target_class or (
                            target_class and target_class == class_name
                        ):
                            target_invocation = class_name + ";->" + method
                            starting_points[target_invocation].update(
                                gaps.signature_to_address[target_method][
                                    method
                                ][class_name]
                            )
        else:
            if (
                target_method
                in gaps.signature_to_address
                # and target_method not in dont_look_superclass
            ):
                rest_of_signature = target_instruction.split("->")[1]
                if (
                    rest_of_signature
                    in gaps.signature_to_address[target_method]
                ):
                    if (
                        target_class
                        in gaps.signature_to_address[target_method][
                            rest_of_signature
                        ]
                    ):
                        target_invocation = (
                            target_class + ";->" + rest_of_signature
                        )
                        starting_points[target_invocation].update(
                            gaps.signature_to_address[target_method][
                                rest_of_signature
                            ][target_class]
                        )

    if (
        (
            not starting_points
            or (starting_points and len(starting_points) == 0)
        )
        and consider_hierarchy
        and target_class
    ):
        extra_starting_points = defaultdict(set)
        target_class_hierarchy = get_root_class_hierarchy(target_class, gaps)[
            :-1
        ] + _get_class_interfaces(target_class, gaps)
        if not target_instruction:
            if target_method in gaps.signature_to_address:
                for method in gaps.signature_to_address[target_method]:
                    classes = gaps.signature_to_address[target_method][method]
                    # check if search needs to be performed
                    _find_extra_starting_points_in_class_hierarchy(
                        target_class,
                        target_class_hierarchy,
                        extra_starting_points,
                        classes,
                        method,
                        gaps,
                    )
        else:
            if (
                target_method
                in gaps.signature_to_address
                # and target_method not in dont_look_superclass
            ):
                rest_of_signature = target_instruction.split("->")[1]
                classes = gaps.signature_to_address[target_method][
                    rest_of_signature
                ]
                _find_extra_starting_points_in_class_hierarchy(
                    target_class,
                    target_class_hierarchy,
                    extra_starting_points,
                    classes,
                    rest_of_signature,
                    gaps,
                )
        starting_points = extra_starting_points

    if len(starting_points) == 0:
        if search:
            gaps.search_list[search] = deque()
        return deque()

    return _breadth_first_search_graph(
        gaps,
        starting_points,
        explore,
        search,
    )


def _find_extra_starting_points_in_class_hierarchy(
    target_class: str,
    target_class_hierarchy: list,
    extra_starting_points: dict,
    methods_dict: dict,
    rest_of_signature: str,
    gaps,
):
    """
    Finds extra starting points in a class hierarchy.

    Args:
        target_class: The target class.
        target_class_hierarchy: The hierarchy of the target class.
        extra_starting_points: Extra starting points.
        methods_dict: Dictionary containing methods.
        rest_of_signature: Rest of the method signature.
        gaps: Object containing information about gaps.
    """

    index_in_target_class_hierarchy = sys.maxsize
    target_class_is_parent = None
    target_class_is_parent_signature = None

    for class_name in methods_dict:
        if class_name == target_class:
            continue
        method_signature = "> " + class_name + ";->" + rest_of_signature + " <"
        if (
            rest_of_signature in gaps.all_methods
            and method_signature not in gaps.all_methods[rest_of_signature]
        ):
            class_hierarchy = get_root_class_hierarchy(class_name, gaps)[
                :-1
            ] + _get_class_interfaces(class_name, gaps)
            true_parent = _is_true_parent(
                target_class,
                class_hierarchy,
            )
            if true_parent:
                to_add = list(methods_dict[class_name])
                extra_starting_points[method_signature.split()[1]].update(
                    to_add
                )

            if class_name in target_class_hierarchy:
                class_name_index = target_class_hierarchy.index(class_name)
                if (
                    class_name_index < index_in_target_class_hierarchy
                    and class_name_index >= 0
                ):
                    index_in_target_class_hierarchy = class_name_index
                    target_class_is_parent = class_name
                    target_class_is_parent_signature = (
                        method_signature.split()[1]
                    )

    if target_class_is_parent:
        extra_starting_points[target_class_is_parent_signature].update(
            methods_dict[target_class_is_parent]
        )


def _is_true_parent(
    candidate_parent: str,
    class_hierarchy: list,
) -> bool:
    """
    Checks if a class is a true parent.

    Args:
        candidate_parent: The candidate parent class.
        class_hierarchy: The hierarchy of classes.
        classes: Dictionary containing classes.
        rest_of_signature: Rest of the method signature.
        gaps: Object containing information about the gaps.

    Returns:
        bool: True if the class is a true parent, False otherwise.
    """
    if candidate_parent in class_hierarchy:
        return True
    return False


def _breadth_first_search_graph(
    gaps,
    starting_points: set,
    explore: bool,
    search: str = None,
) -> list:
    """
    Performs breadth-first search on a graph.

    Args:
        gaps: Object containing information about gaps.
        starting_points (set): Starting points for the search.
        explore (bool): Whether to explore paths.
        search (str, optional): The search string. Defaults to None.

    Returns:
        list: List of found paths.
    """
    list_paths = deque()
    for source_node in starting_points:
        for method_index in starting_points[source_node]:
            method = gaps.method_objs[method_index]
            graph, translate = dalvik_disassembler.basic_blocks_2_graph(
                gaps, method
            )

            for addr in translate:
                if source_node in translate[addr] and addr != -1:
                    list_paths.extend(
                        _graph_visit(graph, translate, addr, explore)
                    )
    if search:
        gaps.search_list[search] = list_paths
    return list_paths


def _graph_visit(graph, translate: dict, source_node: list, explore: bool):
    """
    Visits nodes in a graph.

    Args:
        graph: The graph.
        translate: Translated nodes.
        source_node: Source node.
        explore: Whether to explore paths.

    Returns:
        list: List of visited nodes.
    """
    set_paths = set()
    max_alternative_paths = 1
    if explore:
        max_alternative_paths = 5
    max_path_len = 50
    dict_paths = {}
    paths = deque()
    code_paths = deque()
    destination = source_node
    # new path created
    paths.append([destination])
    code_paths.append([translate[destination]])
    complete = False
    while not complete:
        main_path = False
        while destination in graph:
            list_destinations = list(graph[destination])
            # look for alternative paths
            main_path = False
            if max_alternative_paths > 0:
                main_path_copy = paths[0].copy()
                code_path_copy = code_paths[0].copy()
            for i in range(len(list_destinations)):
                if list_destinations[i] in paths[0]:
                    continue
                if not main_path:
                    destination = list_destinations[0]
                    paths[0].append(destination)
                    instr = translate[destination]
                    code_paths[0].append(instr)
                    main_path = True
                elif max_alternative_paths > 0:
                    max_alternative_paths -= 1
                    new_path = main_path_copy.copy()
                    new_path.append(list_destinations[i])
                    paths.append(new_path)
                    new_code_paths = code_path_copy.copy()
                    instr = translate[list_destinations[i]]
                    new_code_paths.append(instr)
                    code_paths.append(new_code_paths)
            if (len(code_paths[0]) > max_path_len) or not main_path:
                break
        code_paths[0].append(translate[-1])
        if destination not in dict_paths:
            dict_paths[destination] = set()
        dict_paths[destination].add(tuple(code_paths[0]))
        code_paths.popleft()
        paths.popleft()
        # if there are other copied paths to explore
        if len(paths) > 0:
            destination = paths[0][len(paths[0]) - 1]
        else:
            complete = True
    deepest = sys.maxsize
    for distance in dict_paths:
        if deepest > distance:
            deepest = distance
    if deepest != sys.maxsize:
        if not explore:
            set_paths.add(list(dict_paths[deepest])[0])
        else:
            set_paths = set_paths | dict_paths[deepest]
    return list(set_paths)


def get_reflection_calls(gaps):
    """
    Retrieves reflection calls from the given gaps object.

    Args:
        gaps: Object containing information about gaps.

    Returns:
        None
    """
    reflection_invokes = find_path_smali(
        "invoke",
        gaps,
        target_class="Ljava/lang/reflect/Method",
        consider_hierarchy=False,
    )

    for reflection_invoke in reflection_invokes:
        invoke_args = data_flow_analysis.points_to_analysis(
            reflection_invoke, 0, gaps, only_caller=True
        )
        invoke_regs = data_flow_analysis.get_registers(
            reflection_invoke[0], only_caller=True
        )
        for path_pta in invoke_args:
            if (
                invoke_regs[0] in invoke_args[path_pta]
                and "instruction" in invoke_args[path_pta][invoke_regs[0]]
            ):
                instruction = invoke_args[path_pta][invoke_regs[0]][
                    "instruction"
                ]
                if (
                    "getDeclaredMethod" in instruction
                    or "getMethod" in instruction
                ):
                    instruction_index = invoke_args[path_pta][invoke_regs[0]][
                        "instruction_index"
                    ]
                    if (
                        instruction_index < 0
                        or instruction_index > len(path_pta) - 1
                    ):
                        continue
                    method_args = data_flow_analysis.points_to_analysis(
                        path_pta, instruction_index, gaps
                    )
                    method_regs = data_flow_analysis.get_registers(
                        path_pta[instruction_index]
                    )
                    if len(method_regs) != 2:
                        continue
                    for path_pta_2 in method_args:
                        class_invoke, method_invoke = None, None
                        path_involved = path_pta_2
                        for i in range(0, 2):
                            value_found = None
                            if (
                                method_regs[i] in method_args[path_pta_2]
                                and "instruction"
                                in method_args[path_pta_2][method_regs[i]]
                            ):
                                instruction_2 = method_args[path_pta_2][
                                    method_regs[i]
                                ]["instruction"]
                                instruction_type = instruction_2.split()[0]
                                if "const" in instruction_type:
                                    value_found = (
                                        data_flow_analysis.get_const_value(
                                            instruction_2
                                        )
                                    ).replace('"', "")
                                else:
                                    instruction_index_2 = method_args[
                                        path_pta_2
                                    ][method_regs[i]]["instruction_index"]
                                    propagated_args = data_flow_analysis.constant_propagation_through_invocations(
                                        path_pta_2, instruction_index_2, gaps
                                    )
                                    for path_candidate in propagated_args:
                                        value_found = propagated_args[
                                            path_candidate
                                        ]
                                        if path_candidate != path_involved:
                                            path_involved = path_candidate
                                if value_found:
                                    if i == 0:
                                        class_invoke = value_found
                                    else:
                                        method_invoke = value_found
                        if class_invoke and method_invoke:
                            reflection_key = (
                                class_invoke + "->" + method_invoke
                            )
                            if reflection_key not in gaps.reflection_paths:
                                gaps.reflection_paths[reflection_key] = deque()
                            gaps.reflection_paths[reflection_key].append(
                                path_involved
                            )


def filter_by_call_sequence(paths: list, gaps) -> list:
    """
    Filters paths by call sequence.

    Args:
        paths (list): List of paths.
        gaps: Object containing information about gaps.

    Returns:
        list: Filtered list of paths.
    """
    res = deque()
    call_sequence_set = set(gaps.call_sequence)
    for path in paths:
        if path[len(path) - 1] not in call_sequence_set:
            res.append(path)
    return res


def print_paths(paths: list):
    """
    Prints paths.

    Args:
        paths (list): List of paths.

    Returns:
        None
    """
    LOG.debug(f"[+] PATHS FOUND: {len(paths)}")
    atm = 0
    for path in paths:
        LOG.debug(f"[+] PATH {atm}")
        i = len(path) - 1
        for j in range(len(path)):
            LOG.debug(f"{i}| {path[j]}")
            i -= 1
        LOG.debug("")
        atm += 1


def _is_root_reached(path: list) -> bool:
    """
    Checks if the root is reached in a path.

    Args:
        path (list): The path.

    Returns:
        bool: True if the root is reached, False otherwise.
    """
    last_instr = path[len(path) - 1]
    if last_instr.startswith("SEND") or last_instr == "MAIN ACTIVITY":
        return True
    return False


def _add_to_set_paths(set_paths: set, paths_to_add: tuple):
    """
    Adds paths to a set of paths.

    Args:
        set_paths (set): Set of paths.
        paths_to_add (tuple): Paths to add.

    Returns:
        None
    """
    for path_to_add in paths_to_add:
        set_paths.add(tuple(path_to_add))


def add_new_nodes(
    to_add: list,
    graph: nx.DiGraph,
    previous_node: list,
    analyzed_nodes,
    nodes_queue,
) -> list:
    """
    Adds new nodes to a graph.

    Args:
        to_add (list): Nodes to add.
        graph (nx.DiGraph): The graph.
        gaps: Object containing information about gaps.
        previous_node (list): The previous node.

    Returns:
        list: List of added nodes.
    """
    if len(to_add) == 0:
        return
    for i in range(len(to_add)):
        if to_add[i][-1] in analyzed_nodes:
            continue
        graph.add_edge(previous_node, to_add[i])
        nodes_queue.append(to_add[i])


def _find_icc_paths(
    last_instr, method_name, super_class, res, gaps, entry_points
):
    icc_comms = icc_analysis.find_icc_comm(last_instr, gaps, entry_points)

    # res += icc_comms
    if (
        "Activity" in super_class
        and (method_name in activity_life_cycle or len(res) == 0)
    ) or "Activity" not in super_class:
        res.extend(icc_comms)


def _find_next_paths(last_path: list, gaps, entry_points) -> list:
    """
    Finds the next paths.

    Args:
        last_path (list): The last path.
        gaps: Object containing information about gaps.
        subclass (bool, optional): Whether to consider subclasses. Defaults to True.

    Returns:
        list: List of found paths.
    """
    # print"\t...finding next paths...")
    last_instr = last_path[len(last_path) - 1]
    # print(last_instr)

    if last_instr == "PRESS MENU":
        last_instr = last_path[len(last_path) - 2]

    class_name, method_name = method_utils.get_class_and_method(
        last_instr, True
    )
    res = deque()

    super_classes = get_root_class_hierarchy(class_name, gaps)
    super_class = ""
    if len(super_classes) > 0:
        super_class = super_classes[-1]

    invocation_paths = _find_invocation_paths(last_instr, gaps)
    res.extend(invocation_paths)
    # print(f"\t{len(invocation_paths)} invocation paths")

    _find_icc_paths(
        last_instr, method_name, super_class, res, gaps, entry_points
    )

    # print(f"\t{len(res)} + icc paths")

    if len(res) > 0:
        return res

    if (
        "Activity" not in super_class
        and "BroadcastReceiver" not in super_class
        and "Service" not in super_class
    ):
        component_paths = _find_component_paths(
            last_instr,
            last_path,
            super_class,
            gaps,
        )
        res.extend(component_paths)
        # print(f"\t {len(component_paths)} component paths")

    if len(res) > 0:
        return res

    res.extend(_find_invocation_paths(last_instr, gaps, True))
    # print(f"\t {len(res)} + sub super classes invocations")
    if len(res) > 0:
        return res

    res.extend(
        _find_hierarchy_component_invocations(super_class, class_name, gaps)
    )
    # print(f"\t {len(res)} + component sub super classes invocations")

    return res


def _find_hierarchy_component_invocations(super_class, target_class, gaps):
    paths = deque()
    new_rest_signature = None
    if super_class.strip():
        if "Activity" in super_class:
            new_rest_signature = "onCreate(Landroid/os/Bundle;)V"
        if "BroadcastReceiver" in super_class:
            new_rest_signature = "onCreate()V"
        if "Service" in super_class:
            new_rest_signature = (
                "onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
            )
        if not new_rest_signature:
            return paths
        if new_rest_signature in gaps.all_methods:
            for signature in gaps.all_methods[new_rest_signature]:
                candidate_class = signature.split(";->")[0].split()[1]
                super_classes = get_root_class_hierarchy(candidate_class, gaps)
                if (
                    target_class in super_classes
                    and target_class != candidate_class
                ):
                    paths.append(tuple([signature]))
    return paths


def _find_invocation_paths(last_instr, gaps, class_hierarchy: bool = False):
    class_name, method_name = method_utils.get_class_and_method(
        last_instr, True
    )
    res = deque()
    paths_to_add = find_path_smali(
        method_name,
        gaps,
        target_class=class_name,
        target_instruction=last_instr.split()[1],
        consider_hierarchy=class_hierarchy,
    )

    res.extend(paths_to_add)
    return res


def _find_component_paths(last_instr, last_path, super_class, gaps) -> list:
    class_name, method_name = method_utils.get_class_and_method(
        last_instr, True
    )
    res = deque()
    if "AsyncTask" in super_class:
        async_task_paths = find_path_smali(
            "execute",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(async_task_paths)
        async_task_paths_2 = find_path_smali(
            "executeOnExecutor",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(async_task_paths_2)
        inits = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(inits)
        return res
    if "Handler" in super_class:
        handler_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(handler_paths)
        return res
    if "DialogInterface" in super_class:
        handler_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(handler_paths)
        return res
    if "DialogFragment" in super_class:
        target_instruction = (
            class_name
            + ";->show(Landroid/app/FragmentManager;Ljava/lang/String;)V"
        )
        dialog_fragment_paths = find_path_smali(
            "show",
            gaps,
            target_class=class_name,
            target_instruction=target_instruction,
            consider_hierarchy=False,
        )
        if len(dialog_fragment_paths) > 0:
            res.extend(dialog_fragment_paths)
        target_instruction = (
            class_name
            + ";->show(Landroid/app/FragmentTransaction;Ljava/lang/String;)I"
        )
        dialog_fragment_paths = find_path_smali(
            "show",
            gaps,
            target_class=class_name,
            target_instruction=target_instruction,
            consider_hierarchy=False,
        )
        if len(dialog_fragment_paths) > 0:
            res.extend(dialog_fragment_paths)
        return res
    if "Fragment" in super_class:
        fragment_paths = _get_fragment_paths(class_name, gaps)
        res.extend(fragment_paths)
        if len(fragment_paths) == 0:
            init_paths = find_path_smali(
                "<init>",
                gaps,
                target_class=class_name,
                consider_hierarchy=False,
            )
            res.extend(init_paths)
        return res
    if "Thread" in super_class or "TimerTask" in super_class:
        start_thread = find_path_smali(
            "start",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(start_thread)
        if len(start_thread) == 0:
            init_thread = find_path_smali(
                "<init>",
                gaps,
                target_class=class_name,
                consider_hierarchy=False,
            )
            res.extend(init_thread)
        return res
    if "SQLiteOpenHelper" in super_class:
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(init_paths)
        return res
    if "WebView" in super_class:
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        if len(init_paths) > 0:
            res.extend(init_paths)
            return res

    interfaces = str(_get_class_interfaces(class_name, gaps))
    if (
        "Runnable" in interfaces
        or "View" in interfaces
        or "Landroid" in interfaces
        or "Callable" in interfaces
        or "Listener" in interfaces
    ):
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(init_paths)
        return res
    if re.search(r".*\$.*Listener", class_name):
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(init_paths)
        return res

    reflection_key = class_name + ";->" + method_name
    if reflection_key in gaps.reflection_paths:
        res.extend(gaps.reflection_paths[reflection_key])

    method_arguments = ""
    if "(" in last_instr and ")" in last_instr:
        method_arguments = last_instr.split("(")[1].split(")")[0]

    if "Landroid/content/DialogInterface;" in method_arguments:
        dialog_paths = _get_alert_dialog_show_paths(last_path, gaps)
        res.extend(dialog_paths)
        return res

    if (
        "Landroid/widget" in super_class
        or "WebView" in super_class
        or "View" in super_class
        or "Layout" in super_class
    ):
        dollar_sign_class_name = class_name
        if "$" in class_name:
            dollar_sign_class_name = class_name.split("$")[0]
        dict_2_starting_points = {
            dollar_sign_class_name: gaps.object_instantiated[
                dollar_sign_class_name
            ]
        }
        object_used_paths = find_path_smali(
            dollar_sign_class_name + " used",
            gaps,
            starting_points=dict_2_starting_points,
        )
        if len(object_used_paths) > 0:
            res.extend(object_used_paths)
            return res

    if re.search(r".*\$\$.*Lambda", class_name):
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )

        res.extend(init_paths)
        return res

    # last desperate attempt
    if "Landroid" in super_class:
        init_paths = find_path_smali(
            "<init>",
            gaps,
            target_class=class_name,
            consider_hierarchy=False,
        )
        res.extend(init_paths)
        return res

    return res


def _get_content_provider_paths(
    operation_paths: list, content_provider_name: str, gaps
) -> list:
    """
    Retrieves content provider paths.

    Args:
        operation_paths (list): List of operation paths.
        content_provider_name (str): The content provider name.
        gaps: Object containing information about gaps.

    Returns:
        list: List of content provider paths.
    """
    if content_provider_name not in gaps.content_providers:
        return deque()
    res = deque()
    content_provider_authority = gaps.content_providers[content_provider_name]
    for operation_path in operation_paths:
        caller_args = data_flow_analysis.points_to_analysis(
            operation_path, 0, gaps, only_caller=True
        )
        for path in caller_args:
            for reg in caller_args[path]:
                if "instruction" in caller_args[path][reg]:
                    instruction = caller_args[path][reg]["instruction"]
                    instruction_index = caller_args[path][reg][
                        "instruction_index"
                    ]
                    if "invoke" in instruction.split()[0]:
                        path_queue = [path]
                        path_inst_index = instruction_index
                        for path_queued in path_queue:
                            provider_construction_args = (
                                data_flow_analysis.points_to_analysis(
                                    path_queued,
                                    path_inst_index,
                                    gaps,
                                    ignore_caller=True,
                                )
                            )
                            for new_path in provider_construction_args:
                                for reg in provider_construction_args[
                                    new_path
                                ]:
                                    if (
                                        "instruction"
                                        in provider_construction_args[
                                            new_path
                                        ][reg]
                                    ):
                                        new_instruction = (
                                            provider_construction_args[
                                                new_path
                                            ][reg]["instruction"]
                                        )
                                        new_instruction_index = (
                                            provider_construction_args[
                                                new_path
                                            ][reg]["instruction_index"]
                                        )
                                        if (
                                            "const"
                                            in new_instruction.split()[0]
                                        ):
                                            if (
                                                content_provider_authority
                                                in new_instruction
                                            ):
                                                res.append(new_path)
                                        if (
                                            "invoke"
                                            in new_instruction.split()[0]
                                        ):
                                            path_queue.append(new_path)
                                            path_inst_index = (
                                                new_instruction_index
                                            )

    return res


def _get_call_sequence(path: list) -> list:
    """
    Retrieves the call sequence from a path.

    Args:
        path (list): The path.

    Returns:
        list: List of the call sequence.
    """
    res = []
    for node in path:
        if ">" == node[0] or "CONDITIONAL" in node:
            res.append(node)
    return res


def _get_alert_dialog_show_paths(last_path: list, gaps) -> list:
    """
    Retrieves paths leading to the display of alert dialogues in Android applications.

    Args:
        last_path (list): The last path traversed.
        gaps: Gaps analysis object containing required data.

    Returns:
        list: List of paths leading to the display of alert dialogues.
    """
    last_instr = last_path[len(last_path) - 1]
    class_callback, _ = method_utils.get_class_and_method(last_instr, True)
    result = deque()
    target_instruction = (
        "Landroid/app/AlertDialog$Builder;->show()Landroid/app/AlertDialog;"
    )
    show_paths = find_path_smali(
        "show",
        gaps,
        target_class="Landroid/app/AlertDialog$Builder",
        target_instruction=target_instruction,
        consider_hierarchy=False,
    )
    target_instruction = "Landroid/app/AlertDialog;->show()V"
    show_paths2 = find_path_smali(
        "show",
        gaps,
        target_class="Landroid/app/AlertDialog",
        target_instruction=target_instruction,
        consider_hierarchy=False,
    )
    show_paths.extend(show_paths2)
    for show_path in show_paths:
        for i, instruction in enumerate(show_path):
            if instruction.startswith("invoke") and (
                "Landroid/app/AlertDialog$Builder;->setItems" in instruction
                or re.search(
                    r"Landroid/app/AlertDialog\$Builder;->set.*Button.*",
                    instruction,
                )
            ):
                array_index = -1
                if (
                    "Landroid/app/AlertDialog$Builder;->setItems"
                    in instruction
                ):
                    found_if = False
                    for j, instruction in enumerate(last_path):
                        instr_type = instruction.split()[0]
                        if "if" in instr_type:
                            found_if = True
                            if "if-eqz" == instr_type:
                                array_index = 0
                            if "if-eq" == instr_type:
                                const_parameters = (
                                    data_flow_analysis.points_to_analysis(
                                        last_path, j, gaps, ignore_caller=True
                                    )
                                )
                                for path_dfa in const_parameters:
                                    for reg in const_parameters[path_dfa]:
                                        if (
                                            "instruction"
                                            in const_parameters[path_dfa][reg]
                                        ):
                                            const_parameter = const_parameters[
                                                path_dfa
                                            ][reg]["instruction"]
                                            if (
                                                "const"
                                                in const_parameter.split()[0]
                                            ):
                                                array_index = int(
                                                    const_parameter.split()[-1]
                                                )
                        if found_if:
                            break
                registers = data_flow_analysis.get_registers(
                    show_path[i], ignore_caller=True
                )
                parameters = data_flow_analysis.points_to_analysis(
                    show_path, i, gaps, ignore_caller=True
                )
                for path_dfa in parameters:
                    dialog_text = ""
                    if registers[0] in parameters[path_dfa]:
                        if "instruction" in parameters[path_dfa][registers[0]]:
                            parameter = parameters[path_dfa][registers[0]][
                                "instruction"
                            ]
                            dialog_text = _get_alert_dialog_text(
                                parameter, array_index, gaps
                            )
                    if registers[1] in parameters[path_dfa]:
                        if "instruction" in parameters[path_dfa][registers[1]]:
                            parameter = parameters[path_dfa][registers[1]][
                                "instruction"
                            ]
                            if "get-object" in parameter.split()[0]:
                                (
                                    obj_class,
                                    obj_name,
                                ) = method_utils.get_class_and_method(
                                    parameter, True
                                )
                                target_instruction = (
                                    obj_class + ";->" + obj_name
                                )
                                variable_paths = find_path_smali(
                                    obj_name,
                                    gaps,
                                    target_class=obj_class,
                                    target_instruction=target_instruction,
                                    consider_hierarchy=False,
                                )

                                for variable_path in variable_paths:
                                    (
                                        class_name,
                                        method_name,
                                    ) = method_utils.get_class_and_method(
                                        variable_path[1], True
                                    )
                                    if (
                                        class_name == class_callback
                                        and method_name == "<init>"
                                    ):
                                        parameter = variable_path[1]
                            if class_callback in parameter:
                                # show_path = list(show_path)
                                if (
                                    "@@dialog"
                                    not in last_path[len(last_path) - 1]
                                ):
                                    last_path = list(last_path)
                                    last_path[len(last_path) - 1] += (
                                        ' {ID = "@@dialog", INFO = "'
                                        + dialog_text
                                        + '"}'
                                    )
                                    last_path = tuple(last_path)
                                result.append(tuple(show_path))
                                return result

    return result


def _get_alert_dialog_text(parameter: str, array_index: int, gaps) -> str:
    """
    Extracts the text content of alert dialogues based on Smali instructions.

    Args:
        parameter (str): Instruction parameter.
        array_index (int): Index of the array.
        gaps: Gaps analysis object containing required data.

    Returns:
        str: Text content of the alert dialogue.
    """
    dialog_text = ""
    array_arguments = None
    if "get-object" in parameter.split()[0]:
        (
            obj_class,
            obj_name,
        ) = method_utils.get_class_and_method(parameter, True)
        target_instruction = obj_class + ";->" + obj_name
        variable_paths = find_path_smali(
            obj_name,
            gaps,
            target_class=obj_class,
            target_instruction=target_instruction,
            consider_hierarchy=False,
        )

        for variable_path in variable_paths:
            var_parameters = data_flow_analysis.points_to_analysis(
                variable_path,
                0,
                gaps,
                only_caller=True,
            )
            for path_dfa in var_parameters:
                for var_reg in var_parameters[path_dfa]:
                    if "instruction" in var_parameters[path_dfa][var_reg]:
                        var_parameter = var_parameters[path_dfa][var_reg][
                            "instruction"
                        ]
                        if "fill" in var_parameter.split()[0]:
                            fill_index = var_parameters[path_dfa][var_reg][
                                "instruction_index"
                            ]
                            array_arguments = (
                                data_flow_analysis.points_to_analysis(
                                    variable_path,
                                    fill_index,
                                    gaps,
                                )
                            )

                            registers = data_flow_analysis.get_registers(
                                variable_path[fill_index]
                            )
                            if array_index != -1:
                                id_reg = registers[array_index]
                                for path_dfa in array_arguments:
                                    if (
                                        id_reg in array_arguments[path_dfa]
                                        and "instruction"
                                        in array_arguments[path_dfa][id_reg]
                                    ):
                                        parameter = array_arguments[path_dfa][
                                            id_reg
                                        ]["instruction"]
    if "const" in parameter.split()[0]:
        if array_arguments:
            for path_dfa in array_arguments:
                dialog_text = data_flow_analysis.get_const_value(
                    array_arguments[path_dfa][id_reg]["instruction"]
                )
        else:
            dialog_text = data_flow_analysis.get_const_value(parameter)
            if re.search(r"\d+", dialog_text):
                dialog_text = hex(int(dialog_text))
                dialog_text = ui_id_finder.get_ui_id_from_int(
                    dialog_text, gaps
                )
                dialog_text = ui_id_finder.get_string_xml(dialog_text, gaps)
        if dialog_text and '"' in dialog_text:
            dialog_text = dialog_text.replace('"', "")
        if not dialog_text:
            dialog_text = "?"
    return dialog_text


def _get_class_hierarchy(class_name: str, gaps) -> str:
    class_hierarchy = get_root_class_hierarchy(class_name, gaps)[
        :-1
    ] + _get_class_interfaces(class_name, gaps)
    return class_hierarchy


def _get_class_interfaces(class_name: str, gaps) -> list:
    """
    Retrieves interfaces implemented by a given class.

    Args:
        class_name (str): Name of the class.
        gaps: Gaps analysis object containing required data.

    Returns:
        list: Interfaces implemented by the class.
    """
    search_tag = "ci- " + class_name
    if search_tag in gaps.search_list:
        return gaps.search_list[search_tag]
    interfaces = []
    classes = get_root_class_hierarchy(class_name, gaps)
    classes.insert(0, class_name)
    for clazz in classes:
        class_analysis = _get_class_analysis(gaps, clazz + ";")
        if class_analysis:
            if len(class_analysis.implements) > 0:
                for interface in class_analysis.implements:
                    interfaces.append(str(interface).replace(";", ""))
                    if str(interface).startswith("Landroid"):
                        continue
    gaps.search_list[search_tag] = interfaces
    return interfaces


def get_root_class_hierarchy(class_name: str, gaps) -> list:
    """
    Retrieves the root class hierarchy of a given class.

    Args:
        class_name (str): Name of the class.
        gaps: Gaps analysis object containing required data.

    Returns:
        list: Root class hierarchy of the class.
    """
    if class_name in gaps.search_list:
        return gaps.search_list[class_name]
    super_class = class_name + ";"
    search_tag = "rc- " + super_class
    if search_tag in gaps.search_list:
        return gaps.search_list[search_tag]
    res = []
    roots = [
        "Landroid/.*",
        "Landroidx/.*",
        "Ljava/.*",
    ]
    combined = "(" + ")|(".join(roots) + ")"
    while True:
        class_analysis = _get_class_analysis(gaps, super_class)
        new_super_class = super_class
        if class_analysis:
            new_super_class = str(class_analysis.extends)
        if super_class == new_super_class:
            break
        super_class = new_super_class
        res.append(super_class.replace(";", ""))
        if re.match(combined, super_class):
            break
    gaps.search_list[search_tag] = res
    return res


def _get_fragment_paths(class_name: str, gaps) -> list:
    """
    Retrieves paths related to fragments in Android applications.

    Args:
        class_name (str): Name of the class.
        gaps: Gaps analysis object containing required data.

    Returns:
        list: Paths related to fragments.
    """
    if class_name in gaps.fragment_to_activity:
        return deque(gaps.fragment_to_activity[class_name])

    res = _find_fragment_paths(class_name, gaps)

    gaps.fragment_to_activity[class_name] = set(res)

    return res


def _find_fragment_paths(class_name, gaps):
    res = deque()
    # check dynamic
    fragment_transaction = "Landroid/app/FragmentTransaction"
    dynamic_frag_paths = find_path_smali(
        "commit",
        gaps,
        target_class=fragment_transaction,
        consider_hierarchy=False,
    )
    for dynamic_frag_path in dynamic_frag_paths:
        found = False
        for i, instruction in enumerate(dynamic_frag_path):
            class_instr, method_instr = method_utils.get_class_and_method(
                instruction, True
            )
            if re.search(fragment_transaction, class_instr) and (
                method_instr == "replace"
                or method_instr == "add"
                or method_instr == "show"
            ):
                parameters = data_flow_analysis.points_to_analysis(
                    dynamic_frag_path, i, gaps
                )
                for path_dfa in parameters:
                    for reg in parameters[path_dfa]:
                        if "instruction" in parameters[path_dfa][reg]:
                            parameter = parameters[path_dfa][reg][
                                "instruction"
                            ]
                            if "get-object" in parameter.split()[
                                0
                            ] and class_name == parameter.split()[-1].replace(
                                ";", ""
                            ):
                                res.append(path_dfa)
                                return res

    # check static
    java_class_name = class_name[1:].replace("/", ".")
    grep = subprocess.Popen(
        f'grep -r "<fragment.*android:name=\\"{java_class_name}\\"" "{gaps.tmp_path}/res"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    output_grep = grep.communicate()[0].decode("utf-8").split("\n")
    for output in output_grep:
        if output.strip():
            activity_id = output.split(".xml")[0].split("/")[-1]
            if "/navigation/" in output:
                grep_2 = subprocess.Popen(
                    f'grep -r "app:navGraph=\\"@navigation/{activity_id}\\"" "{gaps.tmp_path}/res"',
                    shell=True,
                    stdout=subprocess.PIPE,
                )
                output_grep_2 = (
                    grep_2.communicate()[0].decode("utf-8").split("\n")
                )
                for output_2 in output_grep_2:
                    if output_2.strip():
                        activity_id = output_2.split(".xml")[0].split("/")[-1]
                        break

                public_xml_path = gaps.tmp_path + "/res/values/public.xml"
                activity_hex_id = ui_id_finder.get_value_from_xml(
                    public_xml_path, "id", activity_id
                )
                if activity_hex_id:
                    activity_int_id = str(int(activity_hex_id, 16))
                    init_layout = find_path_smali(
                        "inflate",
                        gaps,
                        target_class="Landroidx/navigation/NavInflater",
                        consider_hierarchy=False,
                    )
                    for init_layout_path in init_layout:
                        parameters = data_flow_analysis.points_to_analysis(
                            init_layout_path, 0, gaps, ignore_caller=True
                        )
                        for path_dfa in parameters:
                            for reg in parameters[path_dfa]:
                                if "instruction" in parameters[path_dfa][reg]:
                                    parameter = parameters[path_dfa][reg][
                                        "instruction"
                                    ]
                                    if (
                                        activity_int_id in parameter
                                        or activity_id in parameter
                                    ):
                                        res.append(path_dfa)
                                        return res
            else:
                grep_3 = subprocess.Popen(
                    f'grep -r "{activity_id}" "{gaps.tmp_path}"',
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                output_grep_3 = (
                    grep_3.communicate()[0].decode("utf-8").split("\n")
                )
                activity_hex_id = None
                for output_3 in output_grep_3:
                    if output_3.strip() and ".smali" in output_3:
                        activity = output_3.strip().split(".smali")[0]
                        activity = activity.split(gaps.tmp_path)[1]
                        activity = "L" + "/".join(activity.split("/")[2:])
                        if "R$layout" not in activity:
                            res.append(
                                tuple(
                                    [
                                        f"> {activity};->onCreate(Landroid/os/Bundle;)V <"
                                    ]
                                )
                            )
                            return res
                        elif not activity_hex_id:
                            activity_hex_id = output_3.split()[-1]
                            grep_4 = subprocess.Popen(
                                f'grep -r "{activity_hex_id}" "{gaps.tmp_path}"',
                                shell=True,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                            )
                            output_grep_4 = (
                                grep_4.communicate()[0]
                                .decode("utf-8")
                                .split("\n")
                            )
                            for output_4 in output_grep_4:
                                if output_4.strip() and ".smali" in output_4:
                                    output_grep_3.insert(0, output_4)
    return res


def _get_class_analysis(gaps, class_name: str):
    """
    Retrieves analysis information related to a specific class.

    Args:
        gaps: Gap analysis object containing required data.
        class_name (str): Name of the class.

    Returns:
        Analysis information related to the class.
    """
    search_tag = "ca- " + class_name
    if search_tag in gaps.search_list:
        return gaps.search_list[search_tag]
    ca_obj = gaps.classes.get(class_name)
    gaps.search_list[search_tag] = ca_obj
    return ca_obj


def build_paths(
    partial_paths: list,
    gaps,
    conditional: bool,
    max_paths: int = 1000,
    store_paths: bool = False,
) -> list:
    """
    Builds paths in Android applications based on partial paths and analysis parameters.

    Args:
        partial_paths (list): List of partial paths.
        gaps: Gaps analysis object containing required data.
        conditional (bool): Flag indicating whether conditional paths should be generated.
        max_paths (int, optional): Maximum number of paths to generate. Defaults to 1000.
        store_paths (bool, optional): Flag indicating whether to store paths. Defaults to False.

    Returns:
        list: List of built paths.
    """
    set_paths = set()
    n_paths = 0
    # start from the paths found initially
    for partial_path in partial_paths:
        graph = nx.DiGraph()
        analyzed_nodes = set()
        nodes_queue = deque()
        nodes_queue.append(partial_path)
        entry_points = set()
        source_node = partial_path
        while len(nodes_queue) > 0:
            current_node = nodes_queue.popleft()
            if current_node[-1] in analyzed_nodes:
                continue
            analyzed_nodes.add(current_node[-1])
            if n_paths >= max_paths:
                return list(set_paths)
            # get the last instruction's class
            new_nodes = _find_next_paths(current_node, gaps, entry_points)
            # add any additional paths found to alternative paths
            add_new_nodes(
                new_nodes,
                graph,
                current_node,
                analyzed_nodes,
                nodes_queue,
            )
            if len(entry_points) > max_paths:
                n_paths += _get_paths(
                    graph,
                    source_node,
                    entry_points,
                    max_paths,
                    conditional,
                    store_paths,
                    set_paths,
                    nodes_queue,
                    gaps,
                )

        if len(entry_points) > 0:
            n_paths += _get_paths(
                graph,
                source_node,
                entry_points,
                max_paths,
                conditional,
                store_paths,
                set_paths,
                nodes_queue,
                gaps,
            )
        else:
            leaves = set(
                [
                    node
                    for node in graph.nodes()
                    if graph.in_degree(node) != 0
                    and graph.out_degree(node) == 0
                ]
            )
            for leaf in leaves:
                if gaps.loglevel == "debug" and conditional:
                    log_component_err(leaf, gaps)

    return list(set_paths)


def _get_paths(
    graph,
    source_node,
    entry_points,
    max_paths,
    conditional,
    store_paths,
    set_paths,
    nodes_queue,
    gaps,
):
    n_paths = 0
    leaves = set(
        [
            node
            for node in graph.nodes()
            if graph.in_degree(node) != 0 and graph.out_degree(node) == 0
        ]
    )
    for leaf in leaves:
        if leaf in entry_points:
            adding_paths = list(
                all_shortest_paths(
                    graph, source_node, leaf, max_paths // len(entry_points)
                )
            )

            n_paths += process_paths(
                adding_paths,
                conditional,
                store_paths,
                set_paths,
                gaps,
            )

            if n_paths > max_paths:
                return n_paths

            LOG.debug(f"\t[+] {n_paths} PATHS FOUND")

        elif gaps.loglevel == "debug" and leaf not in nodes_queue:
            log_component_err(leaf, gaps)

    if (
        len(leaves) == 0
        and gaps.loglevel == "debug"
        and source_node not in nodes_queue
    ):
        log_component_err(source_node, gaps)
    return n_paths


def process_paths(
    simple_paths,
    conditional,
    store_paths,
    set_paths,
    gaps,
):
    n_paths = 0
    call_sequences = set()
    for simple_path in simple_paths:
        call_sequence = _get_call_sequence(simple_path)
        imm_call_sequence = tuple(call_sequence)
        if imm_call_sequence in call_sequences:
            simple_paths.remove(simple_path)
            continue
        call_sequences.add(imm_call_sequence)
    if conditional:
        seen_keys = set()
        for simple_path in simple_paths:
            seen_solutions = set()
            complete_paths = deque(simple_path)
            conditional_paths = conditional_path_generation.find_conditional(
                simple_path, gaps
            )
            for conditional_key in conditional_paths:
                if conditional_key in seen_keys:
                    break
                seen_keys.add(conditional_key)
                for conditional_solutions in conditional_paths[
                    conditional_key
                ]:
                    for conditional_solution in conditional_solutions:
                        for grouped_paths in conditional_solution:
                            solutions = []
                            for solution in grouped_paths:
                                imm_solution = tuple(solution)
                                if imm_solution not in seen_solutions:
                                    solutions.append(
                                        tuple(["----- CONDITIONAL -----"])
                                    )
                                    solutions.append(solution)
                                seen_solutions.add(imm_solution)
                            if len(solutions) > 0:
                                complete_paths.extend(solutions)
            n_paths += len(complete_paths)
            if gaps.loglevel == "verbose":
                LOG.setLevel(logging.DEBUG)
                print_paths(complete_paths)
                LOG.setLevel(logging.INFO)
            # add path to the set
            if store_paths:
                _add_to_set_paths(set_paths, complete_paths)
            else:
                generate_instructions([complete_paths], gaps)
    else:
        complete_paths = simple_paths
        n_paths += len(complete_paths)
        if gaps.loglevel == "verbose":
            LOG.setLevel(logging.DEBUG)
            print_paths(complete_paths)
            LOG.setLevel(logging.INFO)
        # add path to the set
        if store_paths:
            _add_to_set_paths(set_paths, complete_paths)
        else:
            generate_instructions(complete_paths, gaps)
    return n_paths


def log_component_err(node, gaps):
    last_instr = node[len(node) - 1]
    class_name, _ = method_utils.get_class_and_method(last_instr, True)
    super_classes = get_root_class_hierarchy(class_name, gaps)
    super_class = ""
    if len(super_classes) > 0:
        super_class = super_classes[-1]
    interfaces = str(_get_class_interfaces(class_name, gaps))
    log = f"COMPONENT CONCAT {last_instr} extends {super_class}, implements {interfaces}\n"
    if log not in gaps.logs:
        gaps.logs += log


def all_shortest_paths(
    G, source, target, max_paths, weight=None, method="dijkstra"
) -> list:
    """
    Calculates all shortest paths between a source and target node in a graph.

    Args:
        G: Graph object.
        source: Source node.
        target: Target node.
        max_paths: Maximum number of paths to calculate.
        weight (optional): Weight for calculating shortest paths. Defaults to None.
        method (str, optional): Method for calculating shortest paths. Defaults to "dijkstra".

    Returns:
        list: List of all shortest paths.
    """
    method = "unweighted" if weight is None else method
    if method == "unweighted":
        pred = predecessor(G, source, target=target)
    elif method == "dijkstra":
        pred, dist = nx.dijkstra_predecessor_and_distance(
            G, source, weight=weight
        )
    elif method == "bellman-ford":
        pred, dist = nx.bellman_ford_predecessor_and_distance(
            G, source, weight=weight
        )
    else:
        raise ValueError(f"method not supported: {method}")

    return _build_paths_from_predecessors({source}, target, pred, max_paths)


def _build_paths_from_predecessors(sources, target, pred, max_paths):
    """
    Builds paths from predecessors in a graph.

    Args:
        sources: Source nodes.
        target: Target node.
        pred: Predecessor nodes.
        max_paths: Maximum number of paths to generate.

    Yields:
        list: List of paths.
    """
    n_paths = 0
    seen = {target}
    stack = [[target, 0]]
    top = 0
    while top >= 0:
        if n_paths > max_paths:
            break
        node, i = stack[top]
        if node in sources:
            n_paths += 1
            yield [p for p, n in reversed(stack[: top + 1])]
        if len(pred[node]) > i:
            stack[top][1] = i + 1
            next = pred[node][i]
            if next in seen:
                continue
            else:
                seen.add(next)
            top += 1
            if top == len(stack):
                stack.append([next, 0])
            else:
                stack[top][:] = [next, 0]
        else:
            seen.discard(node)
            top -= 1


def predecessor(G, source, target=None, cutoff=None, return_seen=None):
    """Returns dict of predecessors for the path from source to all nodes in G.

    Parameters
    ----------
    G : NetworkX graph

    source : node label
       Starting node for path

    target : node label, optional
       Ending node for path. If provided only predecessors between
       source and target are returned

    cutoff : integer, optional
        Depth to stop the search. Only paths of length <= cutoff are returned.

    return_seen : bool, optional (default=None)
        Whether to return a dictionary, keyed by node, of the level (number of
        hops) to reach the node (as seen during breadth-first-search).

    Returns
    -------
    pred : dictionary
        Dictionary, keyed by node, of predecessors in the shortest path.


    (pred, seen): tuple of dictionaries
        If `return_seen` argument is set to `True`, then a tuple of dictionaries
        is returned. The first element is the dictionary, keyed by node, of
        predecessors in the shortest path. The second element is the dictionary,
        keyed by node, of the level (number of hops) to reach the node (as seen
        during breadth-first-search).

    Examples
    --------
    >>> G = nx.path_graph(4)
    >>> list(G)
    [0, 1, 2, 3]
    >>> nx.predecessor(G, 0)
    {0: [], 1: [0], 2: [1], 3: [2]}
    >>> nx.predecessor(G, 0, return_seen=True)
    ({0: [], 1: [0], 2: [1], 3: [2]}, {0: 0, 1: 1, 2: 2, 3: 3})


    """
    if source not in G:
        raise nx.NodeNotFound(f"Source {source} not in G")

    level = 0  # the current level
    nextlevel = [source]  # list of nodes to check at next level
    seen = {source: level}  # level (number of hops) when seen in BFS
    pred = {source: deque()}  # predecessor dictionary
    while nextlevel:
        level = level + 1
        thislevel = nextlevel
        nextlevel = deque()
        for v in thislevel:
            for w in G[v]:
                if w not in seen:
                    pred[w] = [v]
                    seen[w] = level
                    nextlevel.append(w)
                elif seen[w] == level:  # add v to predecessor list if it
                    pred[w].append(v)  # is at the correct level
        if cutoff and cutoff <= level:
            break
        if target in seen:
            break

    if target is not None:
        if return_seen:
            if target not in pred:
                return (deque(), -1)  # No predecessor
            return (pred, seen[target])
        else:
            if target not in pred:
                return deque()  # No predecessor
            return pred
    else:
        if return_seen:
            return (pred, seen)
        else:
            return pred


def plot_graph(graph):
    """
    Plots a graph representation of the paths.

    Args:
        graph: Graph object.
    """

    plt.figure(figsize=(8, 6))
    nx.draw(
        graph,
        with_labels=True,
        node_size=10,
        node_color="black",
    )
    plt.title("Graph", size=15)
    plt.show()


def _is_unique_path(gaps, call_sequence):
    """
    Checks if a path is unique and updates statistics.

    Args:
        gaps: Gaps analysis object containing required data.
        path: Path to check.

    Returns:
        bool: True if the path is unique, False otherwise.
    """
    gaps.solved_methods[gaps.instruction] += 1
    if call_sequence in gaps.call_sequences:
        return False
    gaps.stats_row[6] += 1
    return True


def generate_instructions(paths: list, gaps):
    """
    Generates instructions for the paths and updates statistics.

    Args:
        paths (list): List of paths.
        gaps: Gaps analysis object containing required data.
    """
    for path in paths:
        conditional_found = False
        gaps.stats_row[3] += 1
        path_info = gaps.instruction
        complete_path = deque()
        for piece in path:
            complete_path.extend(piece)
        call_sequence = _get_call_sequence(complete_path)
        imm_call_sequence = tuple(call_sequence)
        if not _is_unique_path(gaps, imm_call_sequence):
            continue
        gaps.call_sequences.add(imm_call_sequence)
        path_j = deque()
        for j in range(len(path) - 1, -1, -1):
            node = path[j]
            if "MAIN ACTIVITY" in node[-1]:
                path_j.append(["main activity"])
                continue
            if node[-1].startswith("SEND"):
                action = node[-1].split('ACTION = "')[1].split('"')[0]
                action = action.replace('\\"', "").replace('"', "")
                type_action = node[-1].split('TYPE = "')[1].split('"')[0]
                path_j.append(["intent", action, type_action])
                continue
            if "CONDITIONAL" in node[0]:
                if not conditional_found:
                    gaps.stats_row[4] += 1
                    conditional_found = True

            str_path_piece = str(node)
            if re.search(
                r"\(.*Landroid/view.*\)", str_path_piece
            ) or re.search(r"\(.*Landroid/widget.*\)", str_path_piece):
                result = ui_id_finder.use_ui_id_finder_on_paths(node, gaps)
                for element_id, element_text in result:
                    if not element_id:
                        element_id = "<unknown>"
                    class_name, _ = method_utils.get_class_and_method(node[-1])
                    super_classes = get_root_class_hierarchy(class_name, gaps)
                    super_class = ""
                    if len(super_classes) > 0:
                        super_class = super_classes[-1]

                    if "Activity" not in super_class:
                        index_of_cs = call_sequence.index(node[-1])
                        for j in range(index_of_cs, len(call_sequence)):
                            class_name, _ = method_utils.get_class_and_method(
                                call_sequence[j]
                            )
                            super_classes = get_root_class_hierarchy(
                                class_name, gaps
                            )
                            super_class = ""
                            if len(super_classes) > 0:
                                super_class = super_classes[-1]
                            if "Activity" in super_class:
                                break
                    class_name = class_name[1:].replace("/", ".")
                    if "MenuItem" in node[-1]:
                        path_j.append(["press menu"])
                    path_j.append([class_name, element_id])
                    if element_text:
                        path_j[len(path_j) - 1] += [element_text]
        if len(path_j) > 0:
            filtered_path_j = [k for k, g in groupby(path_j)]
            if path_info not in gaps.json_output:
                gaps.json_output[path_info] = {}
            path_entry = {
                "call_sequence": call_sequence,
                "path": filtered_path_j,
            }
            gaps.json_output[path_info][f"path_{gaps.path_index}"] = path_entry
            gaps.path_index += 1
