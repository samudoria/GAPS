import logging
from collections import defaultdict
from collections import deque, defaultdict

from . import method_utils
from . import dalvik_disassembler
from . import path_generation

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")

###############################################################################
# GLOBALS
###############################################################################

MAX_LAYERS = 10

###############################################################################
# CODE
###############################################################################


def points_to_analysis(
    path_in: list,
    start_from: int,
    gaps,
    ignore_caller: bool = False,
    only_caller: bool = False,
    reg_map: dict = None,
    layers: int = 0,
) -> dict:
    """
    Conducts points-to analysis.

    Args:
        path_in (list): Path input.
        start_from (int): Starting index.
        gaps (object): Instance of GAPS (Global Android Pathfinding System).
        ignore_caller (bool): Flag to ignore caller.
        only_caller (bool): Flag to consider only caller.
        reg_map (dict): Map of registers and arguments.
        layers (int): Number of layers.

    Returns:
        dict: Points-to analysis result.
    """
    result = {}
    if ignore_caller and only_caller:
        LOG.error("bad call - either keep or remove the caller")
        return result
    if start_from < 0 or start_from > len(path_in) - 1:
        return result
    queue = [[tuple(path_in), start_from]]

    registers = None
    original_args_list = []
    if reg_map:
        registers = list(reg_map.keys())
        original_args_list = list(reg_map.values())
    else:
        if "(" in path_in[start_from] and not only_caller:
            original_arguments = path_in[start_from][
                path_in[start_from].find("(")
                + 1 : path_in[start_from].rfind(")")
            ]
            original_args_list = method_utils.extract_arguments(
                original_arguments
            )
        else:
            type_of = path_in[start_from].split()[-1]
            if ";" in type_of:
                type_of = type_of.replace(";", "")
            original_args_list = [type_of]

    for path, start_from in queue:
        layers += 1
        if layers > MAX_LAYERS:
            return result
        instr = path[start_from]
        if layers != 0:
            register = None
            if "put" in instr.split()[0]:
                ignore_caller = False
                only_caller = True
            else:
                ignore_caller = False
                only_caller = False
        if not registers:
            registers = list(
                set(get_registers(instr, ignore_caller, only_caller))
            )
        reg_to_args = generate_reg_args_map(instr)
        for reg in reg_to_args:
            arg = reg_to_args[reg]
            if arg not in original_args_list:
                if reg in registers:
                    registers.remove(reg)

        search_tag = "pta- " + str(path[start_from:]) + " " + str(registers)
        if search_tag in gaps.search_list:
            result[path] = gaps.search_list[search_tag]
            continue
        interprocedural = False
        to_translate = {}
        if type(path) is not tuple:
            path = tuple(path)
        for i in range(start_from + 1, len(path)):
            if len(registers) == 0:
                break
            instr = path[i].split()[0]
            to_remove = None
            instr_reg = get_registers(path[i])
            for register in instr_reg:
                if register in registers:
                    to_remove = None
                    const_instr = None
                    instr_index = -1
                    if "move-result" in instr:
                        if (
                            "get" in path[i + 1].split()[0]
                            or "invoke" in path[i + 1].split()[0]
                        ) and "this$" not in path[i + 1]:
                            const_instr = path[i + 1]
                            if "access$" in const_instr:
                                const_instr = (
                                    dalvik_disassembler.resolve_access_method(
                                        const_instr.split()[-1], gaps
                                    )
                                )
                            instr_index = i + 1
                            to_remove = register
                    elif (
                        "move" in instr or "-to-" in instr
                    ) and register == instr_reg[0]:
                        if register != instr_reg[len(instr_reg) - 1]:
                            registers.append(instr_reg[len(instr_reg) - 1])
                            to_remove = register
                            if register not in to_translate:
                                to_translate[instr_reg[len(instr_reg) - 1]] = (
                                    instr_reg[0]
                                )
                            else:
                                old_reg = to_translate[register]
                                to_translate[instr_reg[len(instr_reg) - 1]] = (
                                    old_reg
                                )
                                to_translate.pop(register)
                    elif (
                        (
                            "const" in instr
                            or "get" in instr
                            or "new" in instr
                            or "array-length" in instr
                            or "fill" in instr
                            or "mul" in instr
                            or "add" in instr
                            or "sub" in instr
                            or "div" in instr
                            or "rem" in instr
                            or "and" in instr
                            or "or" in instr
                            or "xor" in instr
                            or "shl" in instr
                            or "shr" in instr
                            or "return" in instr
                        )
                        and register == instr_reg[0]
                    ) and "this$" not in path[i]:
                        if "get" not in instr or (
                            "get" in instr and len(instr_reg) < 3
                        ):
                            to_remove = register
                        const_instr = path[i]
                        instr_index = i
                    elif (
                        register == instr_reg[0]
                        and "put" not in instr
                        and "monitor-enter" not in instr
                        and "check-cast" not in instr
                        and "instance-of" not in instr
                        and "throw" not in instr
                        and "switch" not in instr
                        and "cmp" not in instr
                        and "if" not in instr
                        and "invoke" not in instr
                    ):
                        const_instr = path[i]
                        instr_index = i
                        to_remove = register
                    elif (
                        len(instr_reg) > 2
                        and "put" in instr
                        and register == instr_reg[1]
                    ):
                        registers.append(instr_reg[0])
                        if register not in to_translate:
                            to_translate[instr_reg[0]] = instr_reg[1]
                    else:
                        const_instr = path[i]
                    if const_instr:
                        reg = register
                        if reg in to_translate:
                            reg = to_translate[reg]
                        if path not in result:
                            result[path] = {}
                        if reg not in result[path]:
                            result[path][reg] = {}
                        if to_remove:
                            if "instruction" in result[path][reg]:
                                how_many_before = 0
                                for prev_reg in result[path]:
                                    if reg + " " in prev_reg:
                                        how_many_before += 1
                                reg = reg + " " + str(how_many_before)
                                result[path][reg] = {}
                            result[path][reg]["instruction"] = const_instr
                            result[path][reg][
                                "instruction_index"
                            ] = instr_index
                        else:
                            if (
                                "additional_instructions"
                                not in result[path][reg]
                            ):
                                result[path][reg][
                                    "additional_instructions"
                                ] = []
                            result[path][reg][
                                "additional_instructions"
                            ].append(const_instr)
                    if to_remove and to_remove in registers:
                        registers.remove(to_remove)

                if len(registers) == 0 and path in result:
                    gaps.search_list[search_tag] = result[path]
                    break

        if len(registers) != 0:
            interprocedural = True

        registers = None
        if interprocedural:
            parent = path[len(path) - 1].split()[1]
            (
                parent_class,
                parent_method,
            ) = method_utils.get_class_and_method(parent, True)
            parent_calls = path_generation.find_path_smali(
                parent_method,
                gaps,
                target_class=parent_class,
                target_instruction=parent,
                consider_hierarchy=True,
                explore=True,
            )
            for parent_call in parent_calls:
                new_path = tuple(list(path) + list(parent_call))
                new_start_from = len(path)
                new_entry = [new_path, new_start_from]
                if new_entry not in queue:
                    if new_path not in result:
                        result[new_path] = {}
                    if path in result:
                        result[new_path].update(result[path])
                    queue.append(new_entry)

    return result


def get_registers(
    instr: str,
    ignore_caller: bool = False,
    only_caller: bool = False,
) -> list:
    """
    Retrieves registers from an instruction.

    Args:
        instr (str): Instruction string.
        ignore_caller (bool): Flag to ignore caller.
        only_caller (bool): Flag to consider only caller.

    Returns:
        list: List of registers.
    """
    if ";->" in instr:
        class_name, variable_name = method_utils.get_class_and_method(instr)
        if class_name.strip():
            splits = instr.split(class_name)[0].split()
        else:
            splits = []
    elif "," not in instr:
        splits = instr.split()
        if len(splits) > 1:
            res = []
            res.append(splits[-1])
            return res
    else:
        splits = instr.split()
    registers = []
    for split in splits:
        if "," in split:
            register = split.split(",")[0]
            if "..." in register:
                first_reg_val = register.split("...")[0].replace("v", "")
                last_reg_val = register.split("...")[1].replace("v", "")
                if len(first_reg_val) > 0 and len(last_reg_val) > 0:
                    for i in range(int(first_reg_val), int(last_reg_val) + 1):
                        registers.append("v" + str(i))
            else:
                registers.append(register)
        elif "v" == split[0]:
            registers.append(split)
    if (
        ignore_caller
        and "static" not in instr.split()[0]
        and len(registers) > 0
    ):
        registers = registers[1:]
    if not only_caller:
        return registers
    if len(registers) > 0 and "invoke-static" not in instr.split()[0]:
        return [registers[0]]
    return []


def constant_propagation(
    var_instr: str, gaps, caller_obj: str = None, layers: int = 0
) -> dict:
    """
    Conducts constant propagation.

    Args:
        var_instr (str): Instruction string.
        gaps (object): Instance of GAPS.
        caller_obj (str): Caller object.
        layers (int): Number of layers.

    Returns:
        dict: Constant propagation result.
    """
    result = defaultdict(list)
    queue = [var_instr]
    for var_instr in queue:
        if layers > MAX_LAYERS:
            return result
        layers += 1
        class_name, var_name = method_utils.get_class_and_method(
            var_instr, True
        )
        target_instruction = var_instr.split()[-2]
        if "invoke" in var_instr:
            target_instruction = None
        search_tag = "cp-" + class_name + "->" + var_name
        if caller_obj:
            search_tag = "cp-" + caller_obj + "->" + var_name
        if search_tag in gaps.search_list:
            result.update(gaps.search_list[search_tag])
            continue
        var_paths = path_generation.find_path_smali(
            var_name,
            gaps,
            target_class=class_name,
            target_instruction=target_instruction,
            consider_hierarchy=True,
        )
        for var_path in var_paths:
            if "put" in var_path[0].split()[0]:
                ignore_caller = False
                only_caller = True
            else:
                ignore_caller = True
                if caller_obj:
                    ignore_caller = False
                only_caller = False
            layers += 1
            res = points_to_analysis(
                var_path,
                0,
                gaps,
                ignore_caller=ignore_caller,
                only_caller=only_caller,
                layers=layers + 1,
            )
            accept = True
            caller_reg = None
            if caller_obj and "invoke-static" not in var_path[0]:
                accept = False
                caller_reg = get_registers(var_path[0], only_caller=True)
                if len(caller_reg) > 0:
                    caller_reg = caller_reg[0]
            for path in res:
                if caller_obj:
                    accept = False
                if caller_reg in res[path]:
                    if "instruction" in res[path][caller_reg]:
                        instruction = res[path][caller_reg]["instruction"]
                        method_caller = instruction.split()[-2]
                        if method_caller == caller_obj:
                            accept = True
                        res[path].pop(caller_reg)
                if not accept:
                    continue
                for reg in res[path]:
                    if "instruction" in res[path][reg]:
                        instruction = res[path][reg]["instruction"]
                        instruction_type = instruction.split()[0]
                        if "get" in instruction_type and "->" in instruction:
                            if instruction not in queue:
                                queue.append(instruction)
                        elif "const" in instruction_type:
                            result[path].append(get_const_value(instruction))
                        elif (
                            "invoke" in instruction_type
                            and "->" in instruction
                        ):
                            layers += 1
                            temp_result = constant_propagation_return_values(
                                instruction.split()[-1],
                                gaps,
                                layers=layers + 1,
                            )
                            for path_tmp in temp_result:
                                inter_path = [path, path_tmp]
                                inter_path = tuple(inter_path)
                                result[inter_path] = temp_result[path_tmp]
        gaps.search_list[search_tag] = result
    return result


def constant_propagation_return_values(
    method_name: str, gaps, layers: int = 0
) -> dict:
    """
    Conducts constant propagation for return values.

    Args:
        method_name (str): Method name.
        gaps (object): Instance of GAPS.
        layers (int): Number of layers.

    Returns:
        dict: Constant propagation result for return values.
    """
    result = defaultdict(list)
    queue = []
    queue.append(method_name)
    for method_name in queue:
        starting_points = defaultdict(set)
        if method_name not in gaps.return_by:
            if ";->" in method_name:
                rest_of_signature = ";->" + method_name.split(";->")[1]
                target_class = method_name.split(";->")[0]
                for method in gaps.return_by:
                    if rest_of_signature in method:
                        class_candidate = method.split(";->")[0]
                        if (
                            target_class
                            in path_generation.get_root_class_hierarchy(
                                class_candidate, gaps
                            )[:-1]
                        ):
                            starting_points["return"].update(
                                gaps.return_by[method]
                            )
        else:
            starting_points["return"].update(gaps.return_by[method_name])
        if len(starting_points) == 0:
            continue
        if layers > MAX_LAYERS:
            return result
        layers += 1
        search_tag = "cpr-" + method_name
        if search_tag in gaps.search_list:
            result.update(gaps.search_list[search_tag])
            continue
        return_type = method_name.split(")")[-1]
        return_paths = path_generation.find_path_smali(
            return_type,
            gaps,
            target_class=method_name,
            starting_points=starting_points,
            explore=True,
        )
        for return_path in return_paths:
            layers += 1
            params = points_to_analysis(
                return_path, 0, gaps, layers=layers + 1
            )
            for path_pta in params:
                for reg in params[path_pta]:
                    if "instruction" in params[path_pta][reg]:
                        instruction = params[path_pta][reg]["instruction"]
                        instruction_type = instruction.split()[0]
                        if "const" in instruction_type:
                            result[path_pta].append(
                                get_const_value(instruction)
                            )
                        elif "get" in instruction_type and "->" in instruction:
                            layers += 1
                            temp_result = constant_propagation(
                                instruction, gaps, layers=layers + 1
                            )
                            for path_tmp in temp_result:
                                inter_path = [return_path, path_tmp]
                                inter_path = tuple(inter_path)
                                result[inter_path].extend(
                                    temp_result[path_tmp]
                                )
                        elif (
                            "invoke" in instruction_type
                            and "->" in instruction
                        ):
                            new_method_name = instruction.split()[-1]
                            if (
                                new_method_name not in queue
                                and new_method_name in gaps.return_by
                            ):
                                queue.append(instruction.split()[-1])
                            if new_method_name not in gaps.return_by:
                                result[path_pta].append(new_method_name)
        gaps.search_list[search_tag] = result
    return result


def constant_propagation_through_invocations(
    path: list, instruction_index: int, gaps, layers: int = 0
) -> dict:
    """
    Conducts constant propagation through invocations.

    Args:
        path (list): Path list.
        instruction_index (int): Instruction index.
        gaps (object): Instance of GAPS.
        layers (int): Number of layers.

    Returns:
        dict: Constant propagation result through invocations.
    """
    result = {}
    queue = []
    queue.append([path, instruction_index])
    for path, instruction_index in queue:
        if layers > MAX_LAYERS:
            return result
        layers += 1
        method_args = points_to_analysis(
            path, instruction_index, gaps, layers=layers + 1
        )
        if instruction_index < 0 or instruction_index > len(path) - 1:
            continue
        method_regs = get_registers(path[instruction_index])
        for path_pta in method_args:
            if (
                method_regs[0] in method_args[path_pta]
                and "instruction" in method_args[path_pta][method_regs[0]]
            ):
                instruction = method_args[path_pta][method_regs[0]][
                    "instruction"
                ]
                instruction_type = instruction.split()[0]
                if "const" in instruction_type:
                    result[path_pta] = get_const_value(instruction)
                elif "invoke" in instruction_type:
                    new_instruction_index = method_args[path_pta][
                        method_regs[0]
                    ]["instruction_index"]
                    new_search = [path_pta, new_instruction_index]
                    if new_search not in queue:
                        queue.append(new_search)
                elif "get" in instruction_type and "->" in instruction:
                    layers += 1
                    temp_result = constant_propagation(
                        instruction, gaps, layers=layers + 1
                    )
                    for path_tmp in temp_result:
                        inter_path = [path, path_tmp]
                        inter_path = tuple(inter_path)
                        result[inter_path] = temp_result[path_tmp]
    return result


def get_const_value(instruction: str) -> str:
    """
    Retrieves the constant value from an instruction.

    Args:
        instruction: Instruction string.

    Returns:
        str: Constant value.
    """
    if "const-class" in instruction.split()[0]:
        return instruction.split()[-1]
    split_instructions = instruction.split()
    return " ".join(split_instructions[2:])


def generate_reg_args_map(instruction: str) -> dict:
    """
    Generates register arguments map from an instruction.

    Args:
        instruction (str): Instruction string.

    Returns:
        dict: Register arguments map.
    """
    reg_args_map = {}
    if (
        not instruction.strip()
        or "invoke" not in instruction.split()[0]
        or "(" not in instruction
    ):
        return reg_args_map

    regs_list = get_registers(instruction, ignore_caller=True)
    arguments = instruction[instruction.find("(") + 1 : instruction.rfind(")")]
    args_list = method_utils.extract_arguments(arguments)

    i = 0
    j = 0
    while i < len(regs_list):
        reg = regs_list[i]
        if j > len(args_list) - 1:
            # amount of registers > number of parameters
            reg_args_map[reg] = "?"
        else:
            reg_args_map[reg] = args_list[j]
            if args_list[j] == "long" or args_list[j] == "double":
                next_reg = regs_list[i + 1]
                reg_args_map[next_reg] = reg
                regs_list.remove(next_reg)

            j += 1
        i += 1
    return reg_args_map
