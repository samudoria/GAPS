from androguard.decompiler import decompiler
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import (
    Analysis,
    ClassAnalysis,
    ExternalClass,
    REF_TYPE,
)
from enum import IntEnum
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


class Operand(IntEnum):
    """
    Enumeration used for the operand type of opcodes
    """

    REGISTER = 0
    LITERAL = 1
    RAW = 2
    OFFSET = 3
    KIND = 0x100


class Kind(IntEnum):
    """
    This Enum is used to determine the kind of argument
    inside an Dalvik instruction.

    It is used to reference the actual item instead of the refernece index
    from the :class:`ClassManager` when disassembling the bytecode.
    """

    # Indicates a method reference
    METH = 0
    # Indicates that opcode argument is a string index
    STRING = 1
    # Indicates a field reference
    FIELD = 2
    # Indicates a type reference
    TYPE = 3
    # indicates a prototype reference
    PROTO = 9
    # indicates method reference and proto reference (invoke-polymorphic)
    METH_PROTO = 10
    # indicates call site item
    CALL_SITE = 11

    VARIES = 4
    # inline lined stuff
    INLINE_METHOD = 5
    # static linked stuff
    VTABLE_OFFSET = 6
    FIELD_OFFSET = 7
    RAW_STRING = 8


def AnalyzeAPK(_file, raw=False):
    """
    Analyze an android application and setup all stuff for a more quickly
    analysis!
    If session is None, no session is used at all. This is the default
    behaviour.
    If you like to continue your work later, it might be a good idea to use a
    session.
    A default session can be created by using :meth:`~get_default_session`.

    :param _file: the filename of the android application or a buffer which represents the application
    :type _file: string (for filename) or bytes (for raw)
    :param raw: boolean if raw bytes are supplied instead of a filename
    :rtype: return the :class:`~androguard.core.apk.APK`, list of :class:`~androguard.core.dvm.DEX`, and :class:`~androguard.core.analysis.analysis.Analysis` objects
    """
    a = APK(_file, raw=raw)
    dx = myAnalysis()
    for dex_bytes in a.get_all_dex():
        df = DalvikVMFormat(dex_bytes, using_api=a.get_target_sdk_version())
        dx.add(df)

    # dx.create_xref()

    return a, dx


class myAnalysis(Analysis):
    def create_xref(self) -> None:
        """
        Create Method crossreferences
        for all classes in the Analysis.

        If you are using multiple DEX files, this function must
        be called when all DEX files are added.
        If you call the function after every DEX file, it will only work
        for the first time.
        """

        with ThreadPoolExecutor() as e:

            futures = deque()

            for vm in self.vms:
                for current_class in vm.get_classes():
                    futures.append(e.submit(self._create_xref, current_class))

        for future in as_completed(futures):
            pass

    def _create_xref(self, current_class):
        """
        Create the xref for `current_class`

        There are four steps involved in getting the xrefs:
        * Xrefs for class instantiation and static class usage
        *       for method calls
        *       for string usage
        *       for field manipulation

        All these information are stored in the *Analysis Objects.

        Note that this might be quite slow, as all instructions are parsed.

        :param androguard.core.bytecodes.dvm.ClassDefItem current_class: The class to create xrefs for
        """
        cur_cls_name = current_class.get_name()

        for current_method in current_class.get_methods():
            cur_meth = self.get_method(current_method)
            cur_cls = self.classes[cur_cls_name]

            for off, instruction in current_method.get_instructions_idx():
                op_value = instruction.get_op_value()

                if (0x6E <= op_value <= 0x72) or (0x74 <= op_value <= 0x78):
                    idx_meth = instruction.get_ref_kind()
                    method_info = instruction.cm.vm.get_cm_method(idx_meth)
                    if not method_info:
                        continue

                    class_info = method_info[0].lstrip("[")
                    if class_info[0] != "L":
                        # Need to make sure, that we get class types and not other types
                        # If another type, like int is used, we simply skip it.
                        continue

                    # Resolve the second MethodAnalysis
                    oth_meth = self._resolve_method(
                        class_info, method_info[1], method_info[2]
                    )

                    oth_cls = self.classes[class_info]

                    # FIXME: we could merge add_method_xref_* and add_xref_*
                    cur_cls.add_method_xref_to(
                        cur_meth, oth_cls, oth_meth, off
                    )
                    oth_cls.add_method_xref_from(
                        oth_meth, cur_cls, cur_meth, off
                    )
                    # Internal xref related to class manipulation
                    cur_cls.add_xref_to(
                        REF_TYPE(op_value), oth_cls, oth_meth, off
                    )
                    oth_cls.add_xref_from(
                        REF_TYPE(op_value), cur_cls, cur_meth, off
                    )


def _get_operands(operands):
    """
    Return strings with color coded operands
    """
    for operand in operands:
        if operand[0] == Operand.REGISTER:
            yield "v{}".format(operand[1])

        elif operand[0] == Operand.LITERAL:
            yield "{}".format(operand[1])

        elif operand[0] == Operand.RAW:
            yield "{}".format(operand[1])

        elif operand[0] == Operand.OFFSET:
            yield "%d" % (operand[1])

        elif operand[0] & Operand.KIND:
            if operand[0] == (Operand.KIND + Kind.STRING):
                yield "{}".format(operand[2])
            elif operand[0] == (Operand.KIND + Kind.METH):
                yield "{}".format(operand[2])
            elif operand[0] == (Operand.KIND + Kind.FIELD):
                yield "{}".format(operand[2])
            elif operand[0] == (Operand.KIND + Kind.TYPE):
                yield "{}".format(operand[2])
            else:
                yield "{}".format(repr(operands[2]))
        else:
            yield "{}".format(repr(operands[1]))


def get_whole_method(basic_blocks):
    """
    Extract the whole method body from basic blocks.

    Args:
        basic_blocks: List of basic blocks.

    Returns:
        list: List of strings representing the method body.
    """
    idx = 0
    body = deque()
    for nb, i in enumerate(basic_blocks):
        header = "label: {}".format(i.get_name())
        body.append(header)
        instructions = list(i.get_instructions())
        for ins in instructions:
            content = ""
            content += "%s" % (ins.get_name())

            operands = ins.get_operands()
            content += " %s" % ", ".join(_get_operands(operands))

            op_value = ins.get_op_value()
            if ins == instructions[-1] and i.childs:
                # packed/sparse-switch
                if (op_value == 0x2B or op_value == 0x2C) and len(
                    i.childs
                ) > 1:
                    values = i.get_special_ins(idx).get_values()
                    content += "[ D:%s " % (i.childs[0][2].get_name())
                    content += (
                        " ".join(
                            "%d:%s"
                            % (values[j], i.childs[j + 1][2].get_name())
                            for j in range(0, len(i.childs) - 1)
                        )
                        + " ]"
                    )
                else:
                    if len(i.childs) == 2:
                        content += "[ {} ".format(
                            i.childs[0][2].get_name(),
                        )
                        content += (
                            " ".join(
                                "%s" % c[2].get_name() for c in i.childs[1:]
                            )
                            + " ]"
                        )
                    else:
                        content += (
                            "[ "
                            + " ".join(
                                "%s" % c[2].get_name() for c in i.childs
                            )
                            + " ]"
                        )
            body.append(content)
            idx += ins.get_length()
    return body
