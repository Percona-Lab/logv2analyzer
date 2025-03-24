import argparse
import re
import os
import yaml
import pathspec
import pathlib
import json
from dataclasses import dataclass, asdict, is_dataclass

DEFAULT_CONFIG_PATH = "logv2analyzer.yaml"

def fatal(msg, exit_code=1):
    print(f"Error: {msg}")
    exit(exit_code)

def build_parser():
    parser = argparse.ArgumentParser(
        description="Analyze usage of LOGV2 macro IDs in MongoDB codebase."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output during scan.",
    )
    parser.add_argument(
        "paths", nargs="*", default=["."], help="Paths of the codebase to scan."
    )
    parser.add_argument(
        "-c",
        "--config",
        nargs="?",
        default=None,
        help="""Path to a configuration file in YAML format. 
                By default, the script will look for a 'logv2analyzer.yaml' 
                file in the current directory. Options from this file are 
                loaded first, any options passed as command line arguments 
                will override the options in the configuration file.""",
    )
    parser.add_argument(
        "--ext",
        nargs="+",
        default=[".cpp", ".h", ".hpp"],
        help="File extensions to scan (default: .cpp, .h, .hpp)",
    )
    parser.add_argument(
        "--ignore",
        nargs="+",
        default=[],
        help="Patterns to ignore during scan (e.g. 'build', 'third_party')",
    )
    parser.add_argument(
        "--use-gitignore",
        default=False,
        dest="use_gitignore",
        action="store_true",
        help="Use .gitignore file to ignore directories during scan if exists.",
    )
    parser.add_argument(
        "--range",
        nargs=2,
        type=int,
        metavar=("START", "END"),
        help="Only check for IDs within the specified range (END is exclusive).",
    )
    parser.add_argument(
        "--duplicates",
        default=True,
        dest="duplicates",
        action="store_true",
        help="Check duplicate log IDs.",
    )
    parser.add_argument(
        "--no-duplicates",
        default=True,
        dest="duplicates",
        action="store_false",
        help="Don't Check duplicate log IDs.",
    )
    parser.add_argument(
        "--ignore-duplicates",
        nargs="+",
        default=[],
        dest="ignore_duplicates",
        help="Ignore duplicate log IDs in the scan in format <ID>:<gitwildmatch>.",
    )
    parser.add_argument(
        "--output",
        nargs="?",
        default=None,
        help="Path to output the results of the scan.",
    )

    return parser


def create_duplicates_filter(duplicates):
    patterns = {}
    for duplicate in duplicates:
        log_id, pattern = duplicate.split(":")
        log_id = int(log_id)
        if log_id not in patterns:
            patterns[log_id] = []
        patterns[log_id].append(pattern)

    filter = {}
    for log_id, pattern in patterns.items():
        filter[log_id] = pathspec.PathSpec.from_lines("gitwildmatch", pattern)
    return filter


def parse_args(parser):
    def enforce_argument_types(parser, args):
        for action in parser._actions:
            arg_name = action.dest
            if hasattr(args, arg_name):
                value = getattr(args, arg_name)
                if action.nargs in ("*", "+") and not isinstance(value, list):
                    setattr(args, arg_name, [value] if value is not None else [])
                elif action.nargs is None and action.type and value is not None:
                    setattr(args, arg_name, action.type(value))

    try:
        args = parser.parse_args()

        if args.config is None and os.path.exists(DEFAULT_CONFIG_PATH):
            args.config = DEFAULT_CONFIG_PATH

        if args.config is not None:
            with open(args.config, "r") as f:
                config_from_file = yaml.safe_load(f)
                parser.set_defaults(**config_from_file)
                args = parser.parse_args()

        enforce_argument_types(parser, args)
    except FileNotFoundError as e:
        fatal(f"Configuration file not found - {e}")
    except yaml.YAMLError as e:
        fatal(f"Failed to parse YAML configuration file - {e}")
    except Exception as e:
        fatal(f"Unexpected error while parsing arguments: {e}")

    return args


def get_pathspec(args):
    patterns = []
    if args.use_gitignore:
        if os.path.exists(".gitignore"):
            with open(".gitignore", "r") as f:
                patterns.extend(f.read().splitlines())

    patterns.extend(args.ignore)

    return pathspec.PathSpec.from_lines("gitwildmatch", patterns)


class Analyzer:
    def __init__(self, args, path_spec, duplicates_filter):
        self.args = args
        self.path_spec = path_spec
        self.duplicates_filter = duplicates_filter
        self.root = pathlib.Path(".").resolve()
        self.usages = {}
        self.duplicates = {}

    # Regex to match any LOGV2 macro variant and capture the log ID
    LOG_MACRO_REGEX = re.compile(r"\bLOGV2\w*\s*\(\s*(\d+)", re.MULTILINE)

    @dataclass
    class LogUsageInfo:
        id: int
        path: str
        line_number: int

    def id_in_range(self, id):
        if not self.args.range:
            return True
        start, end = self.args.range
        return start <= id < end

    def analyze_file(self, path):
        if self.args.verbose:
            print(f"Analyzing '{path.relative_to(self.root)}'...")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    matches = self.LOG_MACRO_REGEX.findall(line)
                    for match in matches:
                        log_id = int(match)
                        if not self.id_in_range(log_id):
                            continue
                        if log_id not in self.usages:
                            self.usages[log_id] = []
                        self.usages[log_id].append(
                            self.LogUsageInfo(
                                log_id, str(path.relative_to(self.root)), line_number
                            )
                        )
        except FileNotFoundError as e:
            fatal(f"File not found - {e}")
        except PermissionError as e:
            fatal(f"Permission denied when accessing file - {e}")
        except Exception as e:
            fatal(f"Unexpected error while analyzing file '{path}': {e}")

    def check_file(self, path):
        if path.suffix not in self.args.ext:
            return
        rel_path = path.relative_to(self.root)
        if self.path_spec.match_file(rel_path):
            return

        self.analyze_file(path)

    def scan_dir(self, path):
        try:
            for file in path.rglob("*"):
                self.check_file(file)
        except PermissionError as e:
            fatal(f"Permission denied when accessing directory '{path}': {e}")
        except Exception as e:
            fatal(f"Unexpected error while scanning directory '{path}': {e}")

    def scan(self):
        for path_str in self.args.paths:
            path = pathlib.Path(path_str).resolve()
            if path.is_file():
                self.scan_file(path)
            elif path.is_dir():
                self.scan_dir(path)

    def get_duplicates(self, log_id, usages):
        if len(usages) < 2:
            return None
        log_id_filter = self.duplicates_filter.get(log_id)
        if not log_id_filter:
            return usages
        duplicates = []
        for usage in usages:
            if not log_id_filter.match_file(usage.path):
                duplicates.append(usage)
        return duplicates

    def check_duplicates(self):
        self.duplicates = {}
        for log_id, usages in self.usages.items():
            if self.args.verbose:
                print(f"Checking for duplicates of log ID {log_id}...")
            log_id_duplicates = self.get_duplicates(log_id, usages)
            if log_id_duplicates:
                self.duplicates[log_id] = self.get_duplicates(log_id, usages)

    def analyze(self):
        self.scan()
        if self.args.duplicates:
            self.check_duplicates()

    def get_usages_result(self):
        results = [asdict(usage) for usages in self.usages.values() for usage in usages]
        return sorted(
            results,
            key=lambda usage: (usage["id"], usage["path"], usage["line_number"]),
        )

    def get_duplicates_result(self):
        def as_duplicate_dict(obj):
            d = asdict(obj)
            del d["id"]
            return d

        results = {}
        for duplicate in self.duplicates:
            results[duplicate] = [
                as_duplicate_dict(usage) for usage in self.duplicates[duplicate]
            ]
        return results

    def results(self):
        results = {
            "config": vars(self.args),
            "usages": self.get_usages_result(),
        }

        if self.args.duplicates:
            results["duplicates"] = self.get_duplicates_result()

        return results


def main():
    args = parse_args(build_parser())
    path_spec = get_pathspec(args)
    duplicates_filter = create_duplicates_filter(args.ignore_duplicates)

    analyzer = Analyzer(args, path_spec, duplicates_filter)
    analyzer.analyze()
    results = analyzer.results()

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(json.dumps(results, indent=1))
        except IOError as e:
            print(f"Error: Failed to write output to file '{args.output}' - {e}")
            exit(1)

    exit_code = 0
    if args.verbose or not args.output:
        if len(results["usages"]):
            print("Found the following log ID usages:")
        for usage in results["usages"]:
            print(f"{usage['id']} in {usage['path']}:{usage['line_number']}")
        if args.duplicates:
            if len(results["duplicates"]):
                exit_code = 1
                print("\nFound the following duplicate log ID usages:")
            for duplicate in results["duplicates"]:
                print(f"Duplicate log ID {duplicate}:")
                for usage in results["duplicates"][duplicate]:
                    print(f"  {usage['path']}:{usage['line_number']}")

        print("Summary:")
        print(f"Log IDs range: [{args.range[0]}, {args.range[1]})")
        print(f"Found {len(results['usages'])} log ID usages.")
        if args.duplicates:
            print(f"Found {len(results['duplicates'])} duplicate log ID usages.")

    exit(exit_code)


if __name__ == "__main__":
    main()
