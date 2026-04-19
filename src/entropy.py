import math
from collections import Counter


def calculate_entropy(data):
    if not data:
        return 0.0
    
    # Count how many times each byte appears
    counts = Counter(data)
    total  = len(data)
    
    # calculate entropy score
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    
    return round(entropy, 4)


def analyse_sections(pe):
    print("\n[+] SECTION ENTROPY ANALYSIS")
    print(f"    {'Section':<12} {'Size':<12} {'Entropy':<10} {'Status'}")
    print(f"    {'_'*50}")

    results = []

    for section in pe.sections:
        #get name and data
        name    = section.Name.decode(errors='replace').strip()
        data    = section.get_data()
        size    = section.SizeOfRawData
        entropy = calculate_entropy(data)

        # not 100% sure these thresholds are perfect but they work okay
        if entropy > 7.0:
            status = "SUSPICIOUS (packed/encrypted)"
        elif entropy > 6.0:
            status = "NOTABLE"
        else:
            status = "Normal"

        print(f"    {name:<12} {size:<12} {entropy:<10} {status}")

        results.append({
            "name"   : name, "size"   : size, "entropy": entropy, "status" : status
        })

    return results