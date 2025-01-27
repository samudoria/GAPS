import argparse
import sys
import logging
import os

from .gaps import GAPS

###############################################################################
# LOGGING
###############################################################################

LOG = logging.getLogger("gaps")
logging.getLogger("androguard").setLevel(logging.WARNING)
logging.basicConfig(format="%(message)s")

###############################################################################
# CODE
###############################################################################


def start_gaps(
    dalvik_path: str,
    target_method: str,
    class_name: str,
    parent_class: str,
    signature: str,
    seed_file: str,
    custom_seed_file: str,
    output: str,
    conditional: bool,
    loglevel: str,
    max_paths: int,
):
    """
    Initializes and starts the path finding process.

    Args:
        dalvik_path (str): Path to the Dalvik file.
        target_method (str): Target method name.
        class_name (str): Class name.
        parent_class (str): Parent class name.
        signature (str): Method signature.
        seed_file (str): Path to the seed file.
        custom_seed_file (str): Path to the custom seed file.
        output (str): output directory path.
        conditional (bool): Flag indicating whether to consider conditional paths.
        loglevel (str): Log level.
        max_paths (int): Maximum number of paths to consider.
    """
    if dalvik_path is None:
        LOG.error("ERROR: Missing DALVIK path.")
        sys.exit(1)

    # from pyinstrument import Profiler

    # profiler = Profiler()
    # profiler.start()

    gaps = GAPS(
        dalvik_path,
        target_method,
        class_name,
        parent_class,
        signature,
        seed_file,
        custom_seed_file,
        output,
        conditional,
        loglevel,
        max_paths,
    )

    gaps.start_path_finding()

    # profiler.stop()
    # profiler.print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", help="APK/DEX path file to disassemble", required=True
    )
    parser.add_argument(
        "-m", "--method", help="Target method to generate paths from"
    )
    parser.add_argument(
        "-cls", "--class_name", help="Target class to generate paths from"
    )
    parser.add_argument(
        "-sig", "--signature", help="Target signature to generate paths from"
    )
    parser.add_argument(
        "-seed", "--seed_file", help="Path to file containing seeds"
    )
    parser.add_argument("-o", "--output", help="Path to output directory")
    parser.add_argument(
        "-custom_seed",
        "--custom_seed_file",
        help="Path to file containing custom seeds",
    )
    parser.add_argument(
        "-cond",
        "--conditional",
        help="Consider conditional behaviour to generate satisfiable paths",
        action="store_true",
    )
    parser.add_argument(
        "-p_cls",
        "--parent_class",
        help="Focus search in the parent class",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose output",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Output for debug purposes",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    parser.add_argument(
        "-l",
        "--path_limit",
        help="Limit the number of paths generated to an upperbound (default: 1000)",
        type=int,
        default=1000,
    )
    parser.add_argument(
        "-up",
        "--unconstrained_paths",
        help="Generate paths without a limit",
        action="store_true",
    )
    args = parser.parse_args(sys.argv[1:])
    if not args.loglevel:
        args.loglevel = 0
    logging.basicConfig(level=args.loglevel)
    LOG.setLevel(args.loglevel)

    if not args.input:
        LOG.error("[-] ERROR: NO INPUT")
        sys.exit(1)

    LOG.info(f"[+] LOADING {args.input}")
    if args.method:
        LOG.info(f"[+] LOOKING FOR {args.method}")
    if args.class_name:
        LOG.info(f"[+] LOOKING IN {args.class_name}")
    if args.parent_class:
        LOG.info(f"[+] USED IN {args.parent_class}")
    if args.signature:
        LOG.info(f"[+] LOOKING FOR {args.signature}")
    if args.seed_file:
        LOG.info(f"[+] USING SEED FILE {args.seed_file}")
    if args.conditional:
        LOG.info("[+] CONDITIONAL PATHS GENERATION")
    if args.path_limit <= 0:
        LOG.error("[-] NO PATHS CAN BE GENERATED: MAX PATHS <= 0")
    if args.unconstrained_paths:
        LOG.info("[+] UNCONSTRAINED PATH RECONSTRUCTION")
        args.path_limit = sys.maxsize
    if args.path_limit:
        LOG.info(f"[+] PATH LIMIT: {args.path_limit}")
    output = "./out"
    if args.output:
        output = args.output
    LOG.info(f"[+] OUTPUT DIRECTORY: {output}")
    if not os.path.exists(output):
        os.mkdir(output)
    if args.input:
        start_gaps(
            args.input,
            args.method,
            args.class_name,
            args.parent_class,
            args.signature,
            args.seed_file,
            args.custom_seed_file,
            output,
            args.conditional,
            args.loglevel,
            args.path_limit,
        )
