import ast
from pathlib import Path

from app.rag.vector_store import RepositoryVectorStore


def extract_repository_knowledge(repository_path: str) -> list:
    """Extract structural knowledge from Python files."""

    knowledge = []

    root = Path(repository_path)

    for file_path in root.rglob("*.py"):

        if any(
            ignored in file_path.parts
            for ignored in ["venv", ".venv", "__pycache__", ".git"]
        ):
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
                    functions.append(node.name)

                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)

                elif isinstance(node, ast.Import):
                    for name in node.names:
                        imports.append(name.name)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module)

            knowledge.append({
                "file": str(file_path.relative_to(root)),
                "lines": len(code.splitlines()),
                "functions": functions,
                "classes": classes,
                "imports": imports,
                "code": code
            })

        except Exception as e:

            knowledge.append({
                "file": str(file_path.relative_to(root)),
                "error": str(e)
            })

    return knowledge


def create_repository_context(knowledge: list) -> str:
    """Create readable repository context."""

    if not knowledge:
        return "No Python files were found."

    context = "CODEGUARDIAN AI REPOSITORY KNOWLEDGE\n\n"

    for item in knowledge:

        context += f"FILE: {item['file']}\n"
        context += f"LINES: {item.get('lines', 0)}\n"

        context += (
            "FUNCTIONS: "
            + ", ".join(item.get("functions", []))
            + "\n"
        )

        context += (
            "CLASSES: "
            + ", ".join(item.get("classes", []))
            + "\n"
        )

        context += (
            "IMPORTS: "
            + ", ".join(item.get("imports", []))
            + "\n\n"
        )

        context += "CODE:\n"
        context += item.get("code", "")
        context += "\n\n"
        context += "-" * 60
        context += "\n\n"

    return context


def create_vector_store(knowledge: list):
    """Create a FAISS vector store from repository files."""

    documents = []

    for item in knowledge:

        document = (
            f"FILE: {item['file']}\n"
            f"FUNCTIONS: {', '.join(item.get('functions', []))}\n"
            f"CLASSES: {', '.join(item.get('classes', []))}\n"
            f"IMPORTS: {', '.join(item.get('imports', []))}\n\n"
            f"CODE:\n{item.get('code', '')}"
        )

        documents.append(document)

    store = RepositoryVectorStore()
    store.add_documents(documents)

    return store