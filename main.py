import sys
import os
from src.pe_parser          import parse_pe
from src.hasher             import calculate_sha256
from src.entropy            import analyse_sections
from src.api_scanner        import scan_apis
from src.string_extractor   import extract_strings
from src.timestamp_checker  import check_timestamp
from src.report_generator   import generate_report


def main():
    # Check if user provided a file
    if len(sys.argv) < 2:
        print("_"*50)
        print("        PESCOPE - PE Malware Analyzer")
        print("_"*50)
        print("\n Usage: python main.py <path_to_file>")
        print("Example: python main.py suspicious.exe\n")
        sys.exit(1)

    file_path = sys.argv[1]

    # Check if file exists
    if not os.path.exists(file_path):
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    print("_"*60)
    print("        PESCOPE - PE Malware Analyzer")
    print("_"*60)
    print(f"\n[*] Analysing: {file_path}\n")

    # Step 1 - Parse PE structure
    pe_info = parse_pe(file_path)
    if not pe_info:
        print("[ERROR] Not a valid PE file!")
        sys.exit(1)

    # Step 2 - Calculate SHA256
    sha256 = calculate_sha256(file_path)

    # Step 3 - Entropy analysis
    entropy_results = analyse_sections(pe_info["pe"])

    # Step 4 - API scanning
    api_results = scan_apis(pe_info["pe"])

    # Step 5 - String extraction
    string_results = extract_strings(file_path)

    # Step 6 - Timestamp check
    timestamp_result = check_timestamp(pe_info["timestamp"])

    # Step 7 - Generate final report
    print("\n" + "_"*50)
    print("        GENERATING FINAL REPORT")
    print("_"*50)

    risk = generate_report(
        file_path        = file_path,
        sha256           = sha256,
        pe_info          = pe_info,
        entropy_results  = entropy_results,
        api_results      = api_results,
        string_results   = string_results,
        timestamp_result = timestamp_result
    )

    print(f"\n FINAL RISK LEVEL: {risk}")
    print(" Analysis Complete!\n")


if __name__ == "__main__":
    main()