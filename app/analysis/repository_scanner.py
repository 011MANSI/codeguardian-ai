import os
import shutil
import tempfile
import zipfile

from app.rag.rag_engine import (
    extract_repository_knowledge,
    create_repository_context
)


def scan_repository(zip_path: str) -> dict:
    """Extract and analyze a ZIP repository."""

    temp_dir = tempfile.mkdtemp()

    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_dir)

        knowledge = extract_repository_knowledge(temp_dir)

        total_python_files = len(knowledge)

        total_lines = sum(
            item.get("lines", 0)
            for item in knowledge
        )

        total_functions = sum(
            len(item.get("functions", []))
            for item in knowledge
        )

        total_classes = sum(
            len(item.get("classes", []))
            for item in knowledge
        )

        files = [
            {
                "file": item["file"],
                "lines": item.get("lines", 0)
            }
            for item in knowledge
        ]

        context = create_repository_context(knowledge)

        return {
            "total_python_files": total_python_files,
            "total_lines": total_lines,
            "total_functions": total_functions,
            "total_classes": total_classes,
            "files": files,
            "repository_context": context
        }

    finally:
        shutil.rmtree(
            temp_dir,
            ignore_errors=True
        )