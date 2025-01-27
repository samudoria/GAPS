import logging
import re
from collections import deque, defaultdict

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

if_zero = ["if-nez", "if-eqz", "if-ltz", "if-lez", "if-gtz", "if-gez"]

MAX_PATHS = 1

###############################################################################
# CODE
###############################################################################


def find_conditional(paths: list, gaps) -> defaultdict:
    """
    Finds conditional solutions for given paths.

    Args:
        paths (list): List of paths to analyze.
        gaps (object): Instance of GAPS.

    Returns:
        conditional_solutions (defaultdict): Dictionary containing the conditional solutions for the given paths.
    """
    gaps.condition_visited = set()

    conditional_solutions = defaultdict(list)

    copy_path = paths.copy()
    for path in copy_path:
        for i in range(len(path)):
            if_instr = path[i].split()[0]
            if "if" == if_instr[:2]:
                gaps.conditional_key = None
                if_regs = data_flow_analysis.get_registers(path[i])
                parameters = data_flow_analysis.points_to_analysis(
                    path, i, gaps
                )
                first_parameter = _get_conditional_key(
                    path, gaps, parameters, if_regs[0]
                )
                if if_instr in if_zero:
                    gaps.conditional_key = f"{if_instr} 0 {first_parameter}"
                    if not _check_condition_to_visit(paths, gaps):
                        continue
                    if (
                        gaps.conditional_key in gaps.conditional_paths
                        and gaps.conditional_key not in conditional_solutions
                    ):
                        conditional_solutions[gaps.conditional_key] = (
                            gaps.conditional_paths[gaps.conditional_key]
                        )
                        continue
                    (
                        first_parameter_assignments,
                        first_parameter_type,
                    ) = _get_argument_if(path, gaps, parameters, if_regs[0])
                    if first_parameter_assignments and first_parameter:
                        if first_parameter_type == "const":
                            continue
                        conditional_entry = _get_ifz_paths(
                            first_parameter_assignments, if_instr, paths, gaps
                        )
                        conditional_solutions[gaps.conditional_key].append(
                            conditional_entry
                        )
                        gaps.conditional_paths[gaps.conditional_key].append(
                            conditional_entry
                        )
                        if len(conditional_entry) > MAX_PATHS:
                            continue
                else:
                    second_parameter = _get_conditional_key(
                        path, gaps, parameters, if_regs[1]
                    )
                    gaps.conditional_key = (
                        f"{if_instr} {second_parameter} {first_parameter}"
                    )
                    if not _check_condition_to_visit(paths, gaps):
                        continue
                    if (
                        gaps.conditional_key in gaps.conditional_paths
                        and gaps.conditional_key not in conditional_solutions
                    ):
                        conditional_solutions[gaps.conditional_key] = (
                            gaps.conditional_paths[gaps.conditional_key]
                        )
                        continue
                    (
                        first_parameter_assignments,
                        first_parameter_type,
                    ) = _get_argument_if(path, gaps, parameters, if_regs[0])
                    (
                        second_parameter_assignments,
                        second_parameter_type,
                    ) = _get_argument_if(path, gaps, parameters, if_regs[1])
                    if (
                        second_parameter
                        and second_parameter_assignments
                        and first_parameter
                        and first_parameter_assignments
                    ):
                        if (
                            second_parameter_type == "const"
                            and first_parameter_type == "const"
                        ):
                            continue
                        conditional_entry = _get_if_paths(
                            first_parameter_assignments,
                            second_parameter_assignments,
                            if_instr,
                            paths,
                            gaps,
                        )
                        conditional_solutions[gaps.conditional_key].append(
                            conditional_entry
                        )
                        gaps.conditional_paths[gaps.conditional_key].append(
                            conditional_entry
                        )
                        if len(conditional_entry) > MAX_PATHS * 2:
                            continue
    return conditional_solutions


def _get_ifz_paths(first_parameter_assignments, if_instr, paths, gaps):
    conditional_entry = deque()
    for path_first in first_parameter_assignments:
        for first_val in first_parameter_assignments[path_first]:
            condition_satisfied = _is_condition_satisfied(
                if_instr,
                "0",
                first_val,
            )
            if condition_satisfied:
                if type(path_first[0]) is str:
                    res = _build_conditional_paths([path_first], paths, gaps)
                else:
                    for bb in path_first:
                        res = _build_conditional_paths([bb], paths, gaps)
                conditional_entry.append(res)
                if len(conditional_entry) > MAX_PATHS:
                    return conditional_entry
    return conditional_entry


def _get_if_paths(
    first_parameter_assignments,
    second_parameter_assignments,
    if_instr,
    paths,
    gaps,
):
    conditional_entry = deque()
    for path_second in second_parameter_assignments:
        for second_val in second_parameter_assignments[path_second]:
            for path_first in first_parameter_assignments:
                for first_val in first_parameter_assignments[path_first]:
                    condition_satisfied = _is_condition_satisfied(
                        if_instr,
                        second_val,
                        first_val,
                    )
                    if condition_satisfied:
                        paths_satisfying = [
                            path_second,
                            path_first,
                        ]
                        # blob of paths that satisfy
                        # a conditional statement
                        for bb in paths_satisfying:
                            if type(bb[0]) is str:
                                res = _build_conditional_paths(
                                    [bb], paths, gaps
                                )

                            else:
                                for bb_bb in bb:
                                    res = _build_conditional_paths(
                                        [bb_bb],
                                        paths,
                                        gaps,
                                    )

                            conditional_entry.append(res)
                            if len(conditional_entry) > MAX_PATHS * 2:
                                return conditional_entry
    return conditional_entry


def _get_conditional_key(
    path: list, gaps, parameters: dict, reg: str
) -> [str]:
    """
    Retrieves the conditional key for a given path.

    Args:
        path (list): The path to analyze.
        gaps (object): Instance of GAPS.
        parameters (dict): Dictionary containing parameters for analysis.
        reg (str): The register to analyze.

    Returns:
        parameter_str (str): The extracted conditional key.

    """
    parameter_str = None
    for path_dfa in parameters:
        if (
            reg in parameters[path_dfa]
            and "instruction" in parameters[path_dfa][reg]
        ):
            first_param = parameters[path_dfa][reg]["instruction"]
            if "invoke" in first_param.split()[0]:
                (
                    comp_class_name,
                    comp_method,
                ) = method_utils.get_class_and_method(first_param, True)
                caller_obj = None
                caller_arg = data_flow_analysis.points_to_analysis(
                    path,
                    parameters[path_dfa][reg]["instruction_index"],
                    gaps,
                    only_caller=True,
                )
                for path_caller in caller_arg:
                    for caller_reg in caller_arg[path_caller]:
                        if (
                            "instruction"
                            in caller_arg[path_caller][caller_reg]
                        ):
                            caller_obj = caller_arg[path_caller][caller_reg][
                                "instruction"
                            ]
                            if "get-object" in caller_obj.split()[0]:
                                caller_obj = caller_obj.split()[-2]
                if caller_obj:
                    invoke_method = None
                    if "is" == comp_method[:2]:
                        invoke_method = comp_method.replace("is", "set")
                    elif "get" == comp_method[:3]:
                        invoke_method = comp_method.replace("get", "set")
                    if invoke_method:
                        first_param = first_param.replace(
                            comp_method, invoke_method
                        )
                        parameter_str = f"{caller_obj}->{invoke_method}"
                    else:
                        first_param = comp_method
                        parameter_str = f"{caller_obj}->{comp_method}"

            elif "get" in first_param.split()[0]:
                parameter_str = first_param.split()[-2]

            elif "const" in first_param.split()[0]:
                const_value = data_flow_analysis.get_const_value(first_param)
                parameter_str = str(const_value)

    return parameter_str


def _get_argument_if(
    path: list, gaps, parameters: dict, reg: str
) -> [list, str]:
    """
    Retrieves the arguments for a given instruction.

    Args:
        path (list): The path to analyze.
        gaps (object): Instance of GAPS.
        parameters (dict): Dictionary containing parameters for analysis.
        reg (str): The register to analyze.

    Returns:
        parameter_assignments (dict): Dictionary containing parameter assignments.
        parameter_type (str): Type of parameter.
    """
    parameter_assignments, parameter_type = (None, None)
    for path_dfa in parameters:
        if (
            reg in parameters[path_dfa]
            and "instruction" in parameters[path_dfa][reg]
        ):
            first_param = parameters[path_dfa][reg]["instruction"]
            if "invoke" in first_param.split()[0]:
                (
                    comp_class_name,
                    comp_method,
                ) = method_utils.get_class_and_method(first_param, True)
                # get caller
                caller_arg = data_flow_analysis.points_to_analysis(
                    path,
                    parameters[path_dfa][reg]["instruction_index"],
                    gaps,
                    only_caller=True,
                )
                caller_obj = None
                for path_caller in caller_arg:
                    for caller_reg in caller_arg[path_caller]:
                        if (
                            "instruction"
                            in caller_arg[path_caller][caller_reg]
                        ):
                            caller_obj = caller_arg[path_caller][caller_reg][
                                "instruction"
                            ]
                            if "get-object" in caller_obj.split()[0]:
                                caller_obj = caller_obj.split()[-2]
                if caller_obj:
                    invoke_method = None
                    if "is" == comp_method[:2]:
                        invoke_method = comp_method.replace("is", "set")
                    elif "get" == comp_method[:3]:
                        invoke_method = comp_method.replace("get", "set")
                    if invoke_method:
                        first_param = first_param.replace(
                            comp_method, invoke_method
                        )
                        parameter_assignments = (
                            data_flow_analysis.constant_propagation(
                                first_param, gaps, caller_obj=caller_obj
                            )
                        )
                        parameter_type = "invoke"
                    else:
                        first_param = comp_method
                        parameter_assignments = data_flow_analysis.constant_propagation_return_values(
                            comp_method, gaps
                        )
                        parameter_type = "invoke"

            elif "get" in first_param.split()[0]:
                parameter_assignments = (
                    data_flow_analysis.constant_propagation(first_param, gaps)
                )
                parameter_type = "object/variable"

            elif "const" in first_param.split()[0]:
                parameter_assignments = {}
                parameter_assignments[tuple([tuple(path)])] = [
                    data_flow_analysis.get_const_value(first_param)
                ]
                parameter_type = "const"
    return parameter_assignments, parameter_type


def _check_condition_to_visit(paths: list, gaps) -> bool:
    """
    Checks if a condition has been visited.

    Args:
        paths (list): List of paths.
        gaps (object): Instance of GAPS.

    Returns:
        bool: Indicates whether the condition has been visited.
    """
    if gaps.conditional_key in gaps.condition_visited:
        return False
    gaps.condition_visited.add(gaps.conditional_key)
    return True


def _build_conditional_paths(partial_paths_to_add: list, paths: list, gaps):
    """
    Adds conditional paths to the existing paths.

    Args:
        partial_paths_to_add (list): Partial paths to add.
        paths (list): List of paths.
        gaps (object): Instance of GAPS.

    Returns:
        res: Resulting paths.
    """
    res = deque()
    for partial_path in partial_paths_to_add:
        if type(partial_path[0]) is tuple:
            partial_path = partial_path[0]

        conditional_paths_generated = path_generation.build_paths(
            [partial_path],
            gaps,
            False,
            max_paths=MAX_PATHS,
            store_paths=True,
        )
        if len(conditional_paths_generated) > MAX_PATHS:
            res = conditional_paths_generated[:MAX_PATHS]
            if len(res) >= MAX_PATHS:
                return res
    return res


def _is_condition_satisfied(
    if_instr: str, value_set: str, second_value_set: str
) -> bool:
    """
    Checks if a condition is satisfied.

    Args:
        if_instr (str): The instruction.
        value_set (str): First value set.
        second_value_set (str): Second value set.

    Returns:
        bool: Indicates whether the condition is satisfied.
    """
    condition_satisfied = False
    if "if-ne" in if_instr and second_value_set == value_set:
        condition_satisfied = True
    elif "if-eq" in if_instr and second_value_set != value_set:
        condition_satisfied = True
    if re.match(r"^\d+$", value_set) and re.match(r"^\d+$", second_value_set):
        if "if-lt" in if_instr and int(second_value_set) >= int(value_set):
            condition_satisfied = True
        elif "if-ge" in if_instr and int(second_value_set) < int(value_set):
            condition_satisfied = True
        elif "if-gt" in if_instr and int(second_value_set) <= int(value_set):
            condition_satisfied = True
        elif "if-le" in if_instr and int(second_value_set) > int(value_set):
            condition_satisfied = True
    return condition_satisfied
