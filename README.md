# Shellcode Detection Tool

A command-line utility for analyzing binary files for detecting shellcode and vulnerabilities exploitation.

## Overview

A PoC detection tool designed to detect stack based buffer overflow exploits with a shellcode injected to the stack.

## Features

- Support for both 32-bit and 64-bit binary analysis
- Payload injection via direct string input or Python script generation
- Integrated debugging with breakpoint support
- Comprehensive reports in JSON format

## Installation

Clone the repository and ensure you have the required dependencies:

```bash
cd shellcode_detector
pip install -r requirements.txt
```

After installing the requirements, the [rootfs](https://github.com/qilingframework/rootfs) from the Qiling framework repository needs to be cloned into `/behavior_analysis` directory.
### Prerequisites

- Python 3.+
- GDB
- using a virtual environment is reccomended

## Usage

```
usage: sudo main.py [-h] -a {32,64} [-o OUTPUT] (-s STRING | -p PYTHON)
                         [--size SIZE] [-b BREAKP] [--interactive]
                         binary_path
```
- `sudo` is required to run the tool as the analysis modules access `/proc` structures of the analyzed program

### Arguments

#### Required Arguments:
- `binary_path`: Path to the binary file you want to analyze, test programs are included in `test_data/vulnerable_programs`
- `-a {32,64}, --arch {32,64}`: Architecture of the binary (32 or 64 bit)
- One of the following payload options:
  - `-s STRING, --string STRING`: Direct string payload
  - `-p PYTHON, --python PYTHON`: Path to Python script that generates payload, for this purpose `utils/payload_generator.py` can be used, for which a `payload_config.json` needs to be created with payload parameters

#### Optional Arguments:
- `-h, --help`: Show the help message and exit
- `-o OUTPUT, --output OUTPUT`: Output file for the JSON report (default: exploit_report.json)
- `--size SIZE`: Size of the payload in bytes
- `-b BREAKP, --breakp BREAKP`: Set breakpoint for analysis, use either function name or address
- `--interactive`: Enable interactive GDB mode

## Examples

Basic string payload injection for a 64-bit binary:
```bash
sudo .venv/bin/python main.py /path/to/vuln64 -a 64 -s "$(python -c 'print("A"*100)')"  -b "func" --size 100
```

Using a Python script to generate a payload for a 32-bit binary:
```bash
sudo .venv/bin/python main.py /path/to/vuln32 -a 32 -p ./payload_generator.py -b "func" --size 256
```

## Output

The tool generates a JSON report containing:
- results od signature-based analysis
- results od behavior-based analysis
- results od anomaly-based analysis

## Shellcode Database
The repository also contains database of shellcodes in the form of byte strings, which are located in the `/test_data` directory. The shellcodes were collected from [ShellStorm](https://shell-storm.org/shellcode/index.html) and [Exploit Db](https://www.exploit-db.com/search?type=shellcode&platform=linux).

## Security Considerations

This tool is intended for legitimate security research and educational purposes only.