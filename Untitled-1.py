# main.py - simple regex-based vulnerability scanner
import re
import sys
from pathlib import Path

# simple regex patterns and associated severity
patterns = {
    "sql_injection": {
        "pattern": r"SELECT .* FROM .*",
        "severity": "HIGH"
    },
    "eval_usage": {
        "pattern": r"\beval\(",
        "severity": "MEDIUM"
    },
    "aws_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "LOW"
    }
}

def regex_scan(code, filename):
    findings = []
    for name, info in patterns.items():
        pat = info["pattern"]
        for match in re.finditer(pat, code, flags=re.IGNORECASE):
            findings.append({
                "type": name,
                "severity": info["severity"],
                "file": str(filename),
                "position": match.start(),
                "snippet": code[max(0, match.start()-30):match.end()+30].replace("\n", " ")
            })
    return findings

def scan_folder(path):
    results = []
    for file in Path(path).rglob("*.py"):  # scan Python files only for now
        try:
            code = file.read_text(errors="ignore")
        except Exception:
            continue
        results.extend(regex_scan(code, file))
    return results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: py main.py <folder>")
        sys.exit(1)

    folder = sys.argv[1]
    results = scan_folder(folder)

    if not results:
        print("✅ No obvious vulnerabilities found.")
    else:
        for r in results:
            print(f"[{r['severity']}] {r['type'].upper()} in {r['file']} at {r['position']} → {r['snippet']}")
