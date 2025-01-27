from guardian import Guardian
import argparse
import os
import sys

if __name__ == "__main__":
    # parse cmdline args, including apk_name, testing_obejctive, and max_test_step
    parser = argparse.ArgumentParser(description="Guardian")
    parser.add_argument(
        "-a", "--apk_path", type=str, help="Path to apk file", required=True
    )
    parser.add_argument(
        "-t",
        "--testing_objective",
        type=str,
        help="testing objective",
        required=True,
    )
    parser.add_argument(
        "-m", "--max_test_step", type=int, help="max test step", default=30
    )
    parser.add_argument(
        "-c", "--target_activity", type=str, help="target activity"
    )
    parser.add_argument("-id", "--target_id", type=str, help="target id")
    args = parser.parse_args()

    if not os.path.exists(args.apk_path):
        print("[-] APK does not exist")
        sys.exit(1)

    guardian = Guardian(
        args.apk_path,
        args.testing_objective,
        args.max_test_step,
        args.target_activity,
        args.target_id,
    )
    test_case = guardian.genTestCase()
