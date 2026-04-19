import re

# Only checking for the most obvious suspicious patterns
# Patterns we want to use as suspicious
SUSPICIOUS_PATTERNS = {
    "URL"     : rb'https?://[^\s]{4,}',
    "IP"      : rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    "CMD"     : rb'cmd\.exe|powershell|/c\s',
    "Registry": rb'HKEY_[A-Z_]+',
}


def extract_strings(file_path):
    print("\n[+] STRING EXTRACTION")
    print(f"    {'_'*50}")

    # Read raw bytes of the file
    with open(file_path, "rb") as f:
        raw = f.read()

    # Extract all readable strings
    all_strings = re.findall(rb'[\x20-\x7e]{4,}', raw)

    print(f"    Total readable strings found: {len(all_strings)}")

    # Now check for suspicious patterns
    print("\n[+] SUSPICIOUS STRINGS FOUND")
    print(f"    {'_'*50}")

    found = []

    for label, pattern in SUSPICIOUS_PATTERNS.items():
        matches = re.findall(pattern, raw)
        for match in matches:
            text = match.decode(errors='replace')
            print(f"    [{label}] {text}")
            found.append({
                "type"  : label,
                "value" : text
            })

    if not found:
        print("    No suspicious strings found")

    print(f"\n    Total Suspicious Strings: {len(found)}")
    return found