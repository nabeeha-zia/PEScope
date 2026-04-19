# PEScope — PE Malware Analyzer

A static analysis tool for detecting malware in 
Windows PE files without executing them.

## Features
- PE structure parsing
- SHA256 file hashing
- Section entropy analysis
- Suspicious API detection
- String extraction
- Threat scoring (LOW/MEDIUM/HIGH/CRITICAL)

## Installation
pip install -r requirements.txt

## Usage
python main.py suspicious.exe

## Example Output
File: cmd.exe
Risk Level: HIGH
Suspicious APIs: IsDebuggerPresent, VirtualAlloc

## Modules
| Module | Description |
|--------|-------------|
| pe_parser.py | Parses PE file structure |
| hasher.py | SHA256 hash calculator |
| entropy.py | Section entropy analysis |
| api_scanner.py | Suspicious API detector |
| string_extractor.py | String extractor |
| report_generator.py | Report generator |

## Author
NABEEHA ZIA - PUNJAB UNIVERSITY