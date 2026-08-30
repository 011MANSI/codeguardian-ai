import ast
import os
import re
import shutil
import tempfile
import zipfile

from fastapi import FastAPI, Body, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from app.ai.code_reviewer import review_code
from app.ai.fix_generator import (
    generate_fix,
    ensure_required_imports,
    clean_ai_code,
    local_fix
)
from app.ai.repository_reviewer import review_repository

from app.analysis.security_scanner import scan_security
from app.analysis.repository_scanner import scan_repository

from app.rag.rag_engine import (
    extract_repository_knowledge,
    create_repository_context
)

from app.database import (
    create_table,
    save_scan,
    get_history
)


# ==================================================
# APP
# ==================================================

app = FastAPI(
    title="CodeGuardian AI",
    description="AI-powered code analysis, security scanning and repository review",
    version="1.0.0"
)

create_table()


# ==================================================
# CORS - LOCAL DEVELOPMENT
# ==================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================================================
# GLOBAL REPOSITORY STATE
# ==================================================

repository_context = ""
repository_security_report = {}
repository_scan_result = {}


# ==================================================
# HOME
# ==================================================

@app.get("/")
def home():

    return {
        "message": "CodeGuardian AI is running!"
    }


@app.head("/")
def health_check():
    return


# ==================================================
# DETECT CODE ISSUES
# ==================================================

def detect_issues(code: str):

    issues = []

    # ------------------------------------------
    # Parse Python Code
    # ------------------------------------------

    try:

        tree = ast.parse(code)

    except SyntaxError as e:

        return None, [
            {
                "type": "Syntax Error",
                "severity": "Critical",
                "message": str(e)
            }
        ]

    # ------------------------------------------
    # AST Analysis
    # ------------------------------------------

    for node in ast.walk(tree):

        # --------------------------------------
        # Unnecessary pass
        # --------------------------------------

        if isinstance(node, ast.Pass):

            issues.append({
                "type": "Warning",
                "severity": "Low",
                "message": (
                    f"Unnecessary 'pass' statement "
                    f"at line {node.lineno}"
                )
            })

        # --------------------------------------
        # Function Calls
        # --------------------------------------

        if isinstance(node, ast.Call):

            if isinstance(node.func, ast.Name):

                # print()

                if node.func.id == "print":

                    issues.append({
                        "type": "Suggestion",
                        "severity": "Low",
                        "message": (
                            f"Print statement found "
                            f"at line {node.lineno}"
                        )
                    })

                # Dangerous functions

                if node.func.id in ["eval", "exec"]:

                    issues.append({
                        "type": "Security Vulnerability",
                        "severity": "High",
                        "message": (
                            f"Dangerous function "
                            f"'{node.func.id}()' found "
                            f"at line {node.lineno}"
                        )
                    })

    # ------------------------------------------
    # Long Functions
    # ------------------------------------------

    for node in ast.walk(tree):

        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef
            )
        ):

            start = node.lineno

            end = getattr(
                node,
                "end_lineno",
                start
            )

            length = end - start + 1

            if length > 20:

                issues.append({
                    "type": "Code Quality",
                    "severity": "Medium",
                    "message": (
                        f"Function '{node.name}' "
                        f"is too long ({length} lines)"
                    )
                })

    # ------------------------------------------
    # TODO / FIXME
    # ------------------------------------------

    for line_number, line in enumerate(
        code.splitlines(),
        start=1
    ):

        if "TODO" in line or "FIXME" in line:

            issues.append({
                "type": "Maintenance",
                "severity": "Low",
                "message": (
                    f"TODO/FIXME comment found "
                    f"at line {line_number}"
                )
            })

    # ------------------------------------------
    # Hardcoded Secrets
    # ------------------------------------------

    secret_pattern = re.compile(
        r'(?im)^\s*'
        r'(password|passwd|pwd|secret|api_key|apikey|token|access_token)'
        r'\s*=\s*'
        r'(["\'])(.*?)\2'
    )

    for match in secret_pattern.finditer(code):

        variable = match.group(1)

        line_number = (
            code[:match.start()].count("\n") + 1
        )

        issues.append({
            "type": "Security Vulnerability",
            "severity": "High",
            "message": (
                f"Hardcoded secret detected "
                f"in variable '{variable}' "
                f"at line {line_number}"
            )
        })

    return tree, issues


# ==================================================
# CALCULATE CODE SCORE
# ==================================================

def calculate_score(issues):

    score = 100

    severity_weights = {
        "Critical": 30,
        "High": 20,
        "Medium": 10,
        "Low": 5
    }

    for issue in issues:

        severity = issue.get(
            "severity",
            "Low"
        )

        score -= severity_weights.get(
            severity,
            5
        )

    return max(0, score)


# ==================================================
# ANALYZE CODE
# ==================================================

@app.post("/analyze")
def analyze_code(
    code: str = Body(
        ...,
        media_type="text/plain"
    )
):

    tree, issues = detect_issues(code)

    # Syntax Error

    if tree is None:

        return {
            "status": "error",
            "score": 0,
            "issues": issues,
            "ai_analysis": (
                "Fix the syntax error first."
            )
        }

    # Calculate score

    score = calculate_score(issues)

    # Save history

    try:

        save_scan(
            code=code,
            issues_count=len(issues),
            risk_score=score
        )

    except Exception as e:

        print(
            f"Database save error: {e}"
        )

    # AI Review

    try:

        ai_analysis = review_code(code)

    except Exception:

        ai_analysis = (
            "AI analysis is temporarily unavailable. "
            "The local code analysis completed successfully."
        )

    return {
        "status": "success",
        "message": f"{len(issues)} issue(s) found!",
        "score": score,
        "issues": issues,
        "ai_analysis": ai_analysis
    }


# ==================================================
# SCAN HISTORY
# ==================================================

@app.get("/history")
def scan_history():

    try:

        history = get_history()

        return {
            "status": "success",
            "total": len(history),
            "history": history
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }


# ==================================================
# FIX SINGLE CODE
# ==================================================

@app.post("/fix")
def fix_code(
    code: str = Body(
        ...,
        media_type="text/plain"
    )
):

    tree, issues = detect_issues(code)

    # Syntax error

    if tree is None:

        return {
            "status": "error",
            "message": (
                "Cannot generate fix because "
                "the code contains a syntax error."
            ),
            "issues": issues
        }

    # No issues

    if not issues:

        return {
            "status": "success",
            "message": "No issues detected.",
            "issues": [],
            "original_code": code,
            "fixed_code": code
        }

    # AI Fix

    try:

        fixed_code = generate_fix(
            code,
            issues
        )

        fixed_code = clean_ai_code(
            fixed_code
        )

        fixed_code = ensure_required_imports(
            fixed_code
        )

        # Validate fixed code

        ast.parse(fixed_code)

        return {
            "status": "success",
            "message": "AI fix generated successfully!",
            "issues": issues,
            "original_code": code,
            "fixed_code": fixed_code
        }

    except Exception:

        # Local fallback

        try:

            fixed_code = local_fix(
                code,
                issues
            )

            fixed_code = ensure_required_imports(
                fixed_code
            )

            ast.parse(fixed_code)

            return {
                "status": "success",
                "message": "Local fix generated successfully.",
                "issues": issues,
                "original_code": code,
                "fixed_code": fixed_code
            }

        except Exception as e:

            return {
                "status": "error",
                "message": (
                    f"Unable to generate fix: {str(e)}"
                ),
                "issues": issues,
                "original_code": code
            }


# ==================================================
# SCAN REPOSITORY
# ==================================================

@app.post("/scan-repository")
async def scan_uploaded_repository(
    file: UploadFile = File(...)
):

    global repository_context
    global repository_security_report
    global repository_scan_result

    # Validate ZIP

    if (
        not file.filename
        or not file.filename.lower().endswith(".zip")
    ):

        return {
            "status": "error",
            "message": "Please upload a ZIP file."
        }

    temp_zip = None
    extract_folder = None

    try:

        # ------------------------------------------
        # Save ZIP
        # ------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".zip"
        ) as temp:

            temp.write(
                await file.read()
            )

            temp_zip = temp.name

        # ------------------------------------------
        # Scan Repository
        # ------------------------------------------

        result = scan_repository(
            temp_zip
        )

        repository_scan_result = result

        # ------------------------------------------
        # Extract ZIP
        # ------------------------------------------

        extract_folder = tempfile.mkdtemp()

        with zipfile.ZipFile(
            temp_zip,
            "r"
        ) as zip_ref:

            zip_ref.extractall(
                extract_folder
            )

        # ------------------------------------------
        # Security Scan
        # ------------------------------------------

        security_report = scan_security(
            extract_folder
        )

        repository_security_report = (
            security_report
        )

        # ------------------------------------------
        # Calculate Security Risk
        # ------------------------------------------

        severity_weights = {
            "Critical": 40,
            "High": 25,
            "Medium": 15,
            "Low": 5
        }

        risk_points = 0

        for finding in security_report.get(
            "findings",
            []
        ):

            severity = finding.get(
                "severity",
                "Low"
            )

            risk_points += severity_weights.get(
                severity,
                0
            )

        security_risk_score = min(
            100,
            risk_points
        )

        # ------------------------------------------
        # Extract Repository Knowledge
        # ------------------------------------------

        knowledge = extract_repository_knowledge(
            extract_folder
        )

        repository_context = (
            create_repository_context(
                knowledge
            )
        )

        return {
            "status": "success",
            "message": (
                "Repository scanned successfully!"
            ),
            "repository": result,
            "security_report": security_report,
            "security_risk_score": security_risk_score
        }

    except zipfile.BadZipFile:

        return {
            "status": "error",
            "message": (
                "The uploaded file is not "
                "a valid ZIP file."
            )
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

    finally:

        if (
            temp_zip
            and os.path.exists(temp_zip)
        ):

            try:

                os.remove(temp_zip)

            except Exception:

                pass

        if extract_folder:

            shutil.rmtree(
                extract_folder,
                ignore_errors=True
            )


# ==================================================
# SEARCH REPOSITORY
# ==================================================

@app.post("/search-repository")
def search_repository(
    query: str = Body(
        ...,
        media_type="text/plain"
    )
):

    global repository_context

    # Validate query

    if not query.strip():

        return {
            "status": "error",
            "message": (
                "Search query cannot be empty."
            )
        }

    # Check repository

    if not repository_context:

        return {
            "status": "error",
            "message": (
                "No repository has been scanned yet. "
                "Please scan a repository first."
            )
        }

    # Lightweight search

    query_words = query.lower().split()

    matching_lines = []

    for line in repository_context.splitlines():

        line_lower = line.lower()

        if any(
            word in line_lower
            for word in query_words
        ):

            matching_lines.append(line)

    results = matching_lines[:20]

    return {
        "status": "success",
        "query": query,
        "total_results": len(results),
        "results": results
    }


# ==================================================
# LOCAL REPOSITORY ANSWER
# ==================================================

def local_repository_answer(
    question: str
):

    global repository_security_report
    global repository_scan_result
    global repository_context

    question_lower = question.lower()

    findings = repository_security_report.get(
        "findings",
        []
    )

    # ------------------------------------------
    # SECURITY
    # ------------------------------------------

    if any(
        keyword in question_lower
        for keyword in [
            "security",
            "risk",
            "vulnerability",
            "vulnerabilities",
            "secure"
        ]
    ):

        if not findings:

            return (
                "✅ No security findings were detected "
                "by the CodeGuardian security scanner."
            )

        answer = (
            f"⚠️ CodeGuardian detected "
            f"{len(findings)} security finding(s):\n\n"
        )

        for index, finding in enumerate(
            findings,
            start=1
        ):

            answer += (
                f"{index}. **"
                f"{finding.get('type', 'Security Issue')}"
                f"**\n"
                f"Severity: **"
                f"{finding.get('severity', 'Unknown')}"
                f"**\n"
                f"File: `"
                f"{finding.get('file', 'Unknown file')}"
                f"`\n"
                f"Line: "
                f"{finding.get('line', 'Unknown')}\n"
                f"{finding.get('message', '')}"
                f"\n\n"
            )

        return answer

    # ------------------------------------------
    # FUNCTIONS
    # ------------------------------------------

    if (
        "function" in question_lower
        or "method" in question_lower
    ):

        functions = []

        for item in repository_scan_result.get(
            "files",
            []
        ):

            for function in item.get(
                "functions",
                []
            ):

                functions.append(function)

        if functions:

            return (
                "🔧 **Functions found in the repository:**\n\n"
                +
                "\n".join(
                    f"• `{function}`"
                    for function in functions
                )
            )

        return (
            "🔧 No functions were detected "
            "in the repository."
        )

    # ------------------------------------------
    # ARCHITECTURE
    # ------------------------------------------

    if any(
        keyword in question_lower
        for keyword in [
            "architecture",
            "structure",
            "project structure",
            "files"
        ]
    ):

        files = repository_scan_result.get(
            "files",
            []
        )

        if files:

            answer = (
                "🏗️ **Repository Architecture**\n\n"
                f"The repository contains "
                f"{len(files)} analyzed file(s).\n\n"
            )

            for item in files:

                file_name = item.get(
                    "file",
                    item.get(
                        "path",
                        "Unknown file"
                    )
                )

                answer += f"• `{file_name}`\n"

            return answer

        return (
            "🏗️ Repository architecture "
            "information is unavailable."
        )

    # ------------------------------------------
    # GENERAL EXPLANATION
    # ------------------------------------------

    if any(
        keyword in question_lower
        for keyword in [
            "explain",
            "code",
            "repository",
            "project"
        ]
    ):

        if repository_context:

            lines = repository_context.splitlines()

            preview = "\n".join(
                lines[:15]
            )

            return (
                "💡 **Repository Overview**\n\n"
                "The repository was successfully scanned.\n\n"
                f"{preview}"
            )

        return (
            "💡 Repository information is available "
            "but detailed context could not be generated."
        )

    return (
        "✅ Repository was successfully scanned.\n\n"
        "Try asking questions like:\n"
        "• What security vulnerabilities were found?\n"
        "• What functions are present?\n"
        "• Explain the project architecture.\n"
        "• Explain this repository."
    )


# ==================================================
# ASK REPOSITORY
# ==================================================

@app.post("/ask-repository")
def ask_repository_question(
    question: str = Body(
        ...,
        media_type="text/plain"
    )
):

    global repository_scan_result

    # Check repository

    if not repository_scan_result:

        return {
            "status": "error",
            "message": (
                "No repository has been scanned yet. "
                "Please scan a repository first."
            )
        }

    # Validate question

    if not question.strip():

        return {
            "status": "error",
            "message": (
                "Question cannot be empty."
            )
        }

    # Local answer

    answer = local_repository_answer(
        question
    )

    return {
        "status": "success",
        "question": question,
        "answer": answer,
        "sources": []
    }


# ==================================================
# AI REPOSITORY REVIEW
# ==================================================

@app.post("/review-repository")
async def review_uploaded_repository(
    file: UploadFile = File(...)
):

    if (
        not file.filename
        or not file.filename.lower().endswith(".zip")
    ):

        return {
            "status": "error",
            "message": "Please upload a ZIP file."
        }

    temp_zip = None
    extract_folder = None

    try:

        # Save ZIP

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".zip"
        ) as temp:

            temp.write(
                await file.read()
            )

            temp_zip = temp.name

        # Extract ZIP

        extract_folder = tempfile.mkdtemp()

        with zipfile.ZipFile(
            temp_zip,
            "r"
        ) as zip_ref:

            zip_ref.extractall(
                extract_folder
            )

        # Extract knowledge

        knowledge = extract_repository_knowledge(
            extract_folder
        )

        repository_context_local = (
            create_repository_context(
                knowledge
            )
        )

        # AI Review

        try:

            ai_review = review_repository(
                repository_context_local
            )

        except Exception:

            ai_review = (
                "⚠️ AI repository review is "
                "temporarily unavailable."
            )

        return {
            "status": "success",
            "message": (
                "AI repository review completed!"
            ),
            "files_analyzed": len(knowledge),
            "ai_review": ai_review
        }

    except zipfile.BadZipFile:

        return {
            "status": "error",
            "message": (
                "The uploaded file is not "
                "a valid ZIP file."
            )
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

    finally:

        if (
            temp_zip
            and os.path.exists(temp_zip)
        ):

            try:

                os.remove(temp_zip)

            except Exception:

                pass

        if extract_folder:

            shutil.rmtree(
                extract_folder,
                ignore_errors=True
            )


# ==================================================
# FIX ENTIRE REPOSITORY
# ==================================================

@app.post("/fix-repository")
async def fix_repository(
    file: UploadFile = File(...)
):

    # Validate ZIP

    if (
        not file.filename
        or not file.filename.lower().endswith(".zip")
    ):

        return {
            "status": "error",
            "message": "Please upload a ZIP file."
        }

    temp_zip = None
    extract_folder = None
    fixed_folder = None
    output_zip = None

    try:

        # ------------------------------------------
        # Save ZIP
        # ------------------------------------------

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=".zip"
        ) as temp:

            temp.write(
                await file.read()
            )

            temp_zip = temp.name

        # ------------------------------------------
        # Extract Repository
        # ------------------------------------------

        extract_folder = tempfile.mkdtemp()

        with zipfile.ZipFile(
            temp_zip,
            "r"
        ) as zip_ref:

            zip_ref.extractall(
                extract_folder
            )

        # ------------------------------------------
        # Create Fixed Repository
        # ------------------------------------------

        fixed_folder = tempfile.mkdtemp()

        shutil.copytree(
            extract_folder,
            fixed_folder,
            dirs_exist_ok=True
        )

        # ------------------------------------------
        # Process Python Files
        # ------------------------------------------

        for root, dirs, files in os.walk(
            extract_folder
        ):

            # Ignore unnecessary folders

            dirs[:] = [
                directory
                for directory in dirs
                if directory not in {
                    "__pycache__",
                    ".git",
                    ".venv",
                    "venv",
                    "env",
                    "node_modules"
                }
            ]

            for filename in files:

                if not filename.lower().endswith(
                    ".py"
                ):

                    continue

                original_path = os.path.join(
                    root,
                    filename
                )

                relative_path = os.path.relpath(
                    original_path,
                    extract_folder
                )

                fixed_path = os.path.join(
                    fixed_folder,
                    relative_path
                )

                # ----------------------------------
                # Read Python File
                # ----------------------------------

                try:

                    with open(
                        original_path,
                        "r",
                        encoding="utf-8"
                    ) as python_file:

                        original_code = (
                            python_file.read()
                        )

                except UnicodeDecodeError:

                    try:

                        with open(
                            original_path,
                            "r",
                            encoding="latin-1"
                        ) as python_file:

                            original_code = (
                                python_file.read()
                            )

                    except Exception:

                        continue

                except Exception:

                    continue

                # ----------------------------------
                # Detect Issues
                # ----------------------------------

                try:

                    tree, issues = detect_issues(
                        original_code
                    )

                except Exception:

                    continue

                # Skip syntax errors

                if tree is None:

                    continue

                # Skip clean files

                if not issues:

                    continue

                # ----------------------------------
                # Generate Fix
                # ----------------------------------

                try:

                    fixed_code = generate_fix(
                        original_code,
                        issues
                    )

                    fixed_code = clean_ai_code(
                        fixed_code
                    )

                    fixed_code = ensure_required_imports(
                        fixed_code
                    )

                    # Validate AI output

                    ast.parse(
                        fixed_code
                    )

                except Exception:

                    # Local fallback

                    try:

                        fixed_code = local_fix(
                            original_code,
                            issues
                        )

                        fixed_code = (
                            ensure_required_imports(
                                fixed_code
                            )
                        )

                        ast.parse(
                            fixed_code
                        )

                    except Exception:

                        continue

                # ----------------------------------
                # Write Fixed File
                # ----------------------------------

                try:

                    with open(
                        fixed_path,
                        "w",
                        encoding="utf-8"
                    ) as python_file:

                        python_file.write(
                            fixed_code
                        )

                except Exception:

                    continue

        # ------------------------------------------
        # Create Output ZIP
        # ------------------------------------------

        output_zip = tempfile.mktemp(
            suffix=".zip"
        )

        with zipfile.ZipFile(
            output_zip,
            "w",
            zipfile.ZIP_DEFLATED
        ) as zip_ref:

            for root, dirs, files in os.walk(
                fixed_folder
            ):

                for filename in files:

                    full_path = os.path.join(
                        root,
                        filename
                    )

                    archive_path = os.path.relpath(
                        full_path,
                        fixed_folder
                    )

                    zip_ref.write(
                        full_path,
                        archive_path
                    )

        # ------------------------------------------
        # Return Fixed Repository
        # ------------------------------------------

        return FileResponse(
            output_zip,
            media_type="application/zip",
            filename="CodeGuardian_Fixed_Repository.zip"
        )

    except zipfile.BadZipFile:

        return {
            "status": "error",
            "message": (
                "The uploaded file is not "
                "a valid ZIP file."
            )
        }

    except Exception as e:

        return {
            "status": "error",
            "message": str(e)
        }

    finally:

        # Remove temporary input ZIP

        if temp_zip:

            try:

                if os.path.exists(temp_zip):

                    os.remove(temp_zip)

            except Exception:

                pass

        # Remove extraction folders

        if extract_folder:

            shutil.rmtree(
                extract_folder,
                ignore_errors=True
            )

        if fixed_folder:

            shutil.rmtree(
                fixed_folder,
                ignore_errors=True
            )


# ==================================================
# END
# ==================================================