import re
import ast

# -------------------------
# 1. REGEX BASED CHECKS
# -------------------------
REGEX_PATTERNS = {
    "Hardcoded password": r"password\s*=\s*['\"].+['\"]",
    "SQL Injection risk": r"(SELECT|INSERT|DELETE|UPDATE).+",  # naive check
    "Eval/Exec usage": r"\b(eval|exec)\s*\(",
}

def regex_scan(code):
    findings = []
    for vuln_type, pattern in REGEX_PATTERNS.items():
        for match in re.finditer(pattern, code, re.IGNORECASE):
            findings.append({
                "type": vuln_type,
                "line": code.count("\n", 0, match.start()) + 1,
                "snippet": match.group()
            })
    return findings


# -------------------------
# 2. AST BASED CHECKS
# -------------------------
class ASTScanner(ast.NodeVisitor):
    def __init__(self):   # ✅ fixed
        self.findings = []

    def visit_Call(self, node):
        # Check for dangerous function calls
        if isinstance(node.func, ast.Name) and node.func.id in ["eval", "exec"]:
            self.findings.append({
                "type": "Dangerous function",
                "line": node.lineno,
                "snippet": node.func.id
            })

        # Check for os.system usage
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "system":
                try:
                    self.findings.append({
                        "type": "OS command execution",
                        "line": node.lineno,
                        "snippet": f"{node.func.value.id}.system(...)"
                    })
                except AttributeError:
                    self.findings.append({
                        "type": "OS command execution",
                        "line": node.lineno,
                        "snippet": "system(...)"
                    })

        self.generic_visit(node)


def ast_scan(code):
    findings = []
    try:
        tree = ast.parse(code)
        scanner = ASTScanner()
        scanner.visit(tree)
        findings = scanner.findings
    except SyntaxError as e:
        findings.append({"type": "Parse error", "line": e.lineno, "snippet": str(e)})
    return findings


# -------------------------
# 3. COMBINE BOTH
# -------------------------
def scan_file(filename):
    with open(filename, "r") as f:
        code = f.read()

    results = []
    results.extend(regex_scan(code))
    results.extend(ast_scan(code))

    return results


# -------------------------
# TEST IT
# -------------------------
if __name__ == "__main__":
    test_file = "test_many_vulns.py"  # replace with your source file
    findings = scan_file(test_file)

    print("\n🔎 Vulnerability Report")
    for f in findings:
        print(f"Line {f['line']}: {f['type']} → {f['snippet']}")
