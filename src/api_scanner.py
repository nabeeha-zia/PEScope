# Dangerous APIs that are commonly used by malware
SUSPICIOUS_APIS = [
    "CreateRemoteThread",
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "IsDebuggerPresent",
    "RegSetValueEx",
    "WSAStartup",
    "URLDownloadToFile",
    "SetWindowsHookEx",
    "ShellExecute",
]


def scan_apis(pe):
    print("\n[+] SUSPICIOUS API SCAN")
    print(f"    {'_'*40}")

    found = []

    # Loop through all imported functions
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors='replace')

                    # Check if this function is in our suspicious list
                    if name in SUSPICIOUS_APIS:
                        print(f"    [!] SUSPICIOUS: {name}")
                        found.append(name)

    except AttributeError:
        print("  No imports found")

    
    if not found:
        print("  No suspicious APIs found")

    print(f"\n   Total Suspicious APIs: {len(found)}")
    return found