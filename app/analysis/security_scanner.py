import ast
import re
import os


def scan_security(repository_path: str):
    findings = []

    for root, dirs, files in os.walk(repository_path):

        # Ignore unnecessary folders
        dirs[:] = [
            d for d in dirs
            if d not in {
                ".git",
                "__pycache__",
                "venv",
                ".venv",
                "node_modules"
            }
        ]

        for filename in files:

            if not filename.endswith(".py"):
                continue

            file_path = os.path.join(root, filename)

            try:
                with open(
                    file_path,
                    "r",
                    encoding="utf-8"
                ) as f:
                    code = f.read()

                relative_path = os.path.relpath(
                    file_path,
                    repository_path
                )

                # --------------------------------
                # AST SECURITY CHECKS
                # --------------------------------

                try:
                    tree = ast.parse(code)

                    for node in ast.walk(tree):

                        # eval / exec
                        if isinstance(node, ast.Call):

                            if isinstance(
                                node.func,
                                ast.Name
                            ):

                                function_name = node.func.id

                                if function_name in {
                                    "eval",
                                    "exec"
                                }:

                                    findings.append({
                                        "file": relative_path,
                                        "line": node.lineno,
                                        "severity": "High",
                                        "type": "Code Execution",
                                        "message": (
                                            f"Dangerous function "
                                            f"'{function_name}()' "
                                            "can execute arbitrary code."
                                        )
                                    })

                                # subprocess
                                if function_name in {
                                    "system",
                                    "popen"
                                }:

                                    findings.append({
                                        "file": relative_path,
                                        "line": node.lineno,
                                        "severity": "High",
                                        "type": "Command Execution",
                                        "message": (
                                            f"Dangerous command execution "
                                            f"using '{function_name}()'."
                                        )
                                    })

                        # Imports
                        if isinstance(
                            node,
                            ast.Import
                        ):

                            for alias in node.names:

                                if alias.name in {
                                    "pickle",
                                    "subprocess"
                                }:

                                    findings.append({
                                        "file": relative_path,
                                        "line": node.lineno,
                                        "severity": "Medium",
                                        "type": "Risky Import",
                                        "message": (
                                            f"Potentially risky "
                                            f"library imported: "
                                            f"'{alias.name}'."
                                        )
                                    })

                        if isinstance(
                            node,
                            ast.ImportFrom
                        ):

                            if node.module in {
                                "pickle",
                                "subprocess"
                            }:

                                findings.append({
                                    "file": relative_path,
                                    "line": node.lineno,
                                    "severity": "Medium",
                                    "type": "Risky Import",
                                    "message": (
                                        f"Potentially risky "
                                        f"library imported: "
                                        f"'{node.module}'."
                                    )
                                })

                except SyntaxError:
                    pass

                # --------------------------------
                # SECRET DETECTION
                # --------------------------------

                secret_patterns = [
                    (
                        r"(?i)(api[_-]?key|secret[_-]?key|password)"
                        r"\s*=\s*[\"'][^\"']+[\"']",
                        "Possible hardcoded secret"
                    ),
                    (
                        r"(?i)token\s*=\s*[\"'][^\"']+[\"']",
                        "Possible hardcoded token"
                    )
                ]

                lines = code.splitlines()

                for line_number, line in enumerate(
                    lines,
                    start=1
                ):

                    for pattern, message in secret_patterns:

                        if re.search(pattern, line):

                            findings.append({
                                "file": relative_path,
                                "line": line_number,
                                "severity": "Critical",
                                "type": "Hardcoded Secret",
                                "message": message
                            })

            except (
                UnicodeDecodeError,
                PermissionError,
                OSError
            ):
                continue

    # --------------------------------
    # SUMMARY
    # --------------------------------

    severity_count = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0
    }

    for finding in findings:

        severity = finding["severity"]

        if severity in severity_count:
            severity_count[severity] += 1

    return {
        "total_findings": len(findings),
        "severity_summary": severity_count,
        "findings": findings
    }