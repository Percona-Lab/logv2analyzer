# logv2analyzer

The `logv2analyzer.py` is a utility for analyzing log IDs in a MongoDB codebase. It specifically scans for `LOGV2` family macros to identify their usage and checks for duplicates. The tool supports filtering by log ID ranges, ignoring specific files or directories and output results in both human-readable and JSON formats.

## Usage

Basic usage:

```bash
python logv2analyzer.py [options] [paths...]
```

Print help for more options:

```bash
python logv2analyzer.py --help
```

### Examples

1. Scan the current directory for log ID usages, use `logv2analyzer.yaml` configuration file if exists:

   ```bash
   python logv2analyzer.py
   ```

2. Scan specific directories/files with verbose output:

   ```bash
   python logv2analyzer.py -v src/module1 src/module2/file.cpp
   ```

3. Analyze log IDs only in a specific range:

   ```bash
   python logv2analyzer.py --range 29000 30000
   ```

4. Use `.gitignore` file if exists to ignore specified files, ignore files with additional patterns and output results to a file in JSON format.

   ```bash
   python logv2analyzer.py --use-gitignore --ignore 'src/third_party' 'src/**/*.h' --output results.json
   ```

5. Use a custom configuration file:

   ```bash
   python logv2analyzer.py -c custom_config.yaml
   ```

## Configuration

The script supports a YAML configuration file to specify default options. Example:

```yaml
use_gitignore: true
ignore:
  - src/module/**/*.h
  - src/third_party
range:
  - 29000
  - 30000
duplicates: true
ignore_duplicates:
  - "1234:src/module1/file.cpp"
  - "5678:src/module2/*.cpp"
```

## Output

If no `--output` option is provided the script outputs the results in a human readable format, with short summary.

If `--output <path>` option is provided the script outputs the results in JSON format, including:

- Configuration used for the scan.
- Log ID usages with file paths and line numbers.
- Duplicate log IDs (if enabled).

Example output:

```json
{
  "config": {
    "ignore": [
      "src/module/**/*.h",
      "src/third_party"
    ],
    "range": [29000, 30000],
    "duplicates": true,
    "ignore_duplicates": [
      "1234:src/module1/file.cpp"
      "5678:src/module2/*.cpp"
    ]
  },
  "usages": [
    {
      "id": 1234,
      "path": "src/file.cpp",
      "line_number": 42
    },
    {
      "id": 5678,
      "path": "include/header.h",
      "line_number": 10
    }
  ],
  "duplicates": {
    "1234": [
      {
        "path": "src/file.cpp",
        "line_number": 42
      },
      {
        "path": "src/another_file.cpp",
        "line_number": 50
      }
    ]
  }
}
```

## TODO

- Scan for config file if not running from project's root dir
- Scan for `.gitignore` file if not running from project's root dir
- Add some additional filters for duplicates e.g. ignore if duplicates are in the same function
