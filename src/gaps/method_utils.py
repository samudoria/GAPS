import re
from collections import deque


def get_class_and_method(
    instruction: str, subclass: bool = False
) -> [str, str]:
    """
    Parse an instruction to extract class name and method name.

    Args:
        instruction (str): The instruction string.
        subclass (bool): Flag to indicate if the class is a subclass.

    Returns:
        [str, str]: A list containing the class name and method name.
    """
    class_name = ""
    method_name = ""
    if ";->" in instruction:
        class_name = instruction.split(";->")[0].split()[-1]
        if "$" in class_name and not subclass:
            class_name = class_name.split("$")[0]
        method_name = instruction.split(";->")[1]
        if "(" in method_name:
            method_name = method_name.split("(")[0]
        else:
            method_splits = method_name.split()
            if len(method_splits) > 0:
                method_name = method_splits[0]
    return class_name, method_name


def is_method(instr: str) -> bool:
    """
    Check if a given instruction is a method.

    Args:
        instr (str): The instruction string.

    Returns:
        bool: True if the instruction is a method, False otherwise.
    """
    return re.search(r"L[\w/$]+;->[\w]+\((.*)\)", instr)


def is_smali_class(class_name: str) -> bool:
    """
    Check if a given class name is in Smali format.

    Args:
        class_name (str): The class name.

    Returns:
        bool: True if the class name is in Smali format, False otherwise.
    """
    return re.search(r"L[\w/$]+", class_name)


def is_java_class(class_name: str) -> bool:
    """
    Check if a given class name is in Java format.

    Args:
        class_name (str): The class name.

    Returns:
        bool: True if the class name is in Java format, False otherwise.
    """
    return re.search(r"[\w\.$]+", class_name)


def convert_java_class_to_smali(class_name: str) -> str:
    """
    Convert a Java class name to Smali format.

    Args:
        class_name (str): The Java class name.

    Returns:
        str: The class name in Smali format.
    """
    if '"' in class_name:
        class_name = class_name.replace('"', "")
    return "L" + class_name.replace(".", "/")


def convert_smali_class_to_java(class_name: str) -> str:
    """
    Convert a Smali class name to Java format.

    Args:
        class_name (str): The Smali class name.

    Returns:
        str: The class name in Java format.
    """
    return class_name.replace("/", ".")[1:]


def extract_arguments(method_arg):
    """
    Extract arguments from a method signature.

    Args:
        method_arg: The method signature.

    Returns:
        list: A list of extracted arguments.
    """
    i = 0
    args = deque()
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
                args.append(method_arg[i : method_arg.find(";")])

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
