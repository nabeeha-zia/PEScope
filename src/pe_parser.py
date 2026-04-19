import pefile


def parse_pe(file_path):
    print("\n" + "_"*50)
    print("        PE FILE ANALYSIS")
    print("_"*50)

    #Try to laod  the file as a PE
    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        print(f"[ERROR] Could not parse file: {e}")
        return None

    print("\n[+] BASIC INFORMATION")
    print(f"    Machine Type      : {hex(pe.FILE_HEADER.Machine)}")
    print(f"    Compile Time      : {pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value']}")
    print(f"    Number of Sections: {pe.FILE_HEADER.NumberOfSections}")

    #printing each section with its size and address
    print("\n[+] SECTIONS FOUND")
    print(f"    {'Name':<12} {'Size':<12} {'Virtual Address'}")
    print(f"    {'-'*40}")

    #showing what dlls the file import
    for section in pe.sections:
        name    = section.Name.decode(errors='replace').strip()
        size    = section.SizeOfRawData
        address = hex(section.VirtualAddress)
        print(f"    {name:<12} {size:<12} {address}")

    print("\n[+] IMPORTED LIBRARIES")
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            lib_name = entry.dll.decode(errors='replace')
            print(f"    [DLL] {lib_name}")
    except AttributeError:
        print("    No imports found")

    print("\n" + "_"*50)

    return {
        "pe"          : pe,
        "machine"     : hex(pe.FILE_HEADER.Machine),
        "timestamp"   : pe.FILE_HEADER.TimeDateStamp,
        "num_sections": pe.FILE_HEADER.NumberOfSections,
        "sections"    : pe.sections
    }