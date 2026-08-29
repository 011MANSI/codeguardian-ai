from pathlib import Path
import ast


def extract_repository_knowledge(repo_path: str):
    """
    Extract structured knowledge from all Python files
    in a repository.
    """

    repo = Path(repo_path)
    knowledge = []

    for file_path in repo.rglob("*.py"):

        # Ignore virtual environments and cache folders
        if any(part in {"venv", "__pycache__", ".git"} for part in file_path.parts):
            continue

        try:
            code = file_path.read_text(
                encoding="utf-8",
                errors="ignore"
            )

            tree = ast.parse(code)

            functions = []
            classes = []
            imports = []

            for node in ast.walk(tree):

                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        "name": node.name,
                        "line": node.lineno
                    })

                elif isinstance(node, ast.ClassDef):
                    classes.append({
                        "name": node.name,
                        "line": node.lineno
                    })

                elif isinstance(node, ast.Import):
                    for name in node.names:
                        imports.append(name.name)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            knowledge.append({
                "file": str(file_path.relative_to(repo)),
                "lines": len(code.splitlines()),
                "functions": functions,
                "classes": classes,
                "imports": imports,
                "code": code
            })

        except Exception as e:
            knowledge.append({
                "file": str(file_path.relative_to(repo)),
                "error": str(e)
            })

    return knowledge


def create_repository_context(knowledge):
    """
    Convert repository knowledge into a compact
    context that can be provided to an AI model.
    """

    context = []

    for item in knowledge:

        context.append(
            f"""
FILE: {item["file"]}
LINES: {item.get("lines", 0)}

FUNCTIONS:
{item.get("functions", [])}

CLASSES:
{item.get("classes", [])}

IMPORTS:
{item.get("imports", [])}

CODE:
{item.get("code", "")}
"""
        )

    return "\n".join(context)