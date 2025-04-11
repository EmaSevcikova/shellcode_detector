import argparse
import os


def parse_arguments():
    """Parse command-line arguments for the exploit analyzer"""
    parser = argparse.ArgumentParser(description="Binary Analysis Tool")

    parser.add_argument("binary_path",
                        help="Path to the binary to analyze")

    parser.add_argument("-a", "--arch",
                        choices=["32", "64"],
                        required=True,
                        help="Architecture: 32 or 64 bit")

    parser.add_argument("-o", "--output",
                        help="Output file for the report (JSON)",
                        default="exploit_report.json")

    payload_group = parser.add_mutually_exclusive_group(required=True)
    payload_group.add_argument("-s", "--string",
                               help="Payload as a string")
    payload_group.add_argument("-p", "--python",
                               help="Path to Python script that generates payload")

    parser.add_argument("--size",
                        type=int,
                        help="Size of the payload in bytes")

    parser.add_argument("-f", "--function",
                        help="Name of the function to analyze")

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        help="Enable verbose output")

    parser.add_argument("--interactive",
                        action="store_false",
                        help="Enable interactive GDB mode")

    args = parser.parse_args()

    if not os.path.isfile(args.binary_path):
        print(f"[!] Error: Binary file '{args.binary_path}' not found")
        return None

    if args.python and not os.path.isfile(args.python):
        print(f"[!] Error: Python script '{args.python}' not found")
        return None

    return args


def get_payload(args):
    """Construct payload string from arguments"""
    if args.python:
        return f"$(python3 {args.python})"
    else:
        return args.string