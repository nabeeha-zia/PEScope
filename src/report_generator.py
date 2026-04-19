import os
import datetime


def calculate_score(entropy_results, api_results, string_results):
    score = 0

    # Entropy scoring
    for section in entropy_results:
        if section["entropy"] > 7.0:
            score += 30
        elif section["entropy"] > 6.0:
            score += 10

    # API scoring
    score += len(api_results) * 15

    # String scoring
    score += len(string_results) * 10

    return score


def get_risk_level(score):
    if score >= 91:
        return "CRITICAL"
    elif score >= 61:
        return "HIGH"
    elif score >= 31:
        return "MEDIUM"
    else:
        return "LOW"


def generate_report(file_path, sha256, pe_info, entropy_results, api_results, string_results):

    score      = calculate_score(entropy_results, api_results, string_results)
    risk_level = get_risk_level(score)
    now        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # making report
    report  = ""
    report += "="*60 + "\n"
    report += "        PE MALWARE ANALYSIS REPORT\n"
    report += "="*60 + "\n"
    report += f"  Date        : {now}\n"
    report += f"  File        : {file_path}\n"
    report += f"  SHA256      : {sha256}\n"
    report += f"  Sections    : {pe_info['num_sections']}\n"
    report += f"  Threat Score: {score}\n"
    report += f"  Risk Level  : {risk_level}\n"
    report += "="*60 + "\n"

    # Entropy section
    report += "\n[+] ENTROPY ANALYSIS\n"
    report += f"    {'Section':<12} {'Entropy':<10} {'Status'}\n"
    report += f"    {'-'*40}\n"
    for s in entropy_results:
        report += f"    {s['name']:<12} {s['entropy']:<10} {s['status']}\n"

    # API section
    report += "\n[+] SUSPICIOUS APIS\n"
    if api_results:
        for api in api_results:
            report += f"    [!] {api}\n"
    else:
        report += "    [✓] No suspicious APIs found\n"

    # Strings section
    report += "\n[+] SUSPICIOUS STRINGS\n"
    if string_results:
        for s in string_results:
            report += f"    [{s['type']}] {s['value']}\n"
    else:
        report += "    [✓] No suspicious strings found\n"

    report += "\n" + "="*60 + "\n"

    # Print to terminal
    print(report)

    # Save to reports
    os.makedirs("reports", exist_ok=True)
    filename    = os.path.basename(file_path) + "_report.txt"
    output_path = os.path.join("reports", filename)

    with open(output_path, "w") as f:
        f.write(report)

    print(f"[✓] Report saved to: {output_path}")
    return risk_level