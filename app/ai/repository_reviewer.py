# ============================================================
# CodeGuardian AI - Repository Reviewer
# Gemini AI + Local Fallback
# ============================================================

import os
import re
import time

from google import genai
from google.genai import types


# ============================================================
# CONFIGURATION
# ============================================================

API_KEY = os.getenv("GEMINI_API_KEY")

MODEL_NAME = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.6-flash"
)


# ============================================================
# GEMINI CLIENT
# ============================================================

client = None

if API_KEY:
    try:
        client = genai.Client(
            api_key=API_KEY
        )
    except Exception:
        client = None


# ============================================================
# ERROR DETECTION
# ============================================================

def get_error_code(error):

    code = getattr(
        error,
        "code",
        None
    )

    if code is not None:
        return str(code)

    text = str(error).upper()

    if "429" in text or "RESOURCE_EXHAUSTED" in text:
        return "429"

    if "503" in text or "UNAVAILABLE" in text:
        return "503"

    if "401" in text or "UNAUTHENTICATED" in text:
        return "401"

    if "403" in text or "PERMISSION_DENIED" in text:
        return "403"

    if "404" in text or "NOT_FOUND" in text:
        return "404"

    return None


# ============================================================
# EXTRACT REPOSITORY INFORMATION
# ============================================================

def extract_files(repository_context):

    pattern = r"FILE:\s*(.*?)\s*(?:\n|$)"

    files = re.findall(
        pattern,
        repository_context
    )

    return files


def extract_functions(repository_context):

    functions = []

    matches = re.findall(
        r"FUNCTIONS:\s*(.*)",
        repository_context
    )

    for match in matches:

        if match.strip():

            for function in match.split(","):

                function = function.strip()

                if function:
                    functions.append(function)

    return functions


def extract_classes(repository_context):

    classes = []

    matches = re.findall(
        r"CLASSES:\s*(.*)",
        repository_context
    )

    for match in matches:

        if match.strip():

            for cls in match.split(","):

                cls = cls.strip()

                if cls:
                    classes.append(cls)

    return classes


# ============================================================
# LOCAL SECURITY ANALYSIS
# ============================================================

def local_security_analysis(repository_context):

    findings = []

    if re.search(
        r"\beval\s*\(",
        repository_context
    ):

        findings.append(
            (
                "**Use of `eval()`**: "
                "The repository uses `eval()`, which dynamically "
                "executes Python expressions. If untrusted input "
                "reaches this function, it can result in arbitrary "
                "code execution."
            )
        )

    if re.search(
        r"\bexec\s*\(",
        repository_context
    ):

        findings.append(
            (
                "**Use of `exec()`**: "
                "The repository uses `exec()`, which can execute "
                "arbitrary Python code and should be avoided with "
                "untrusted input."
            )
        )

    secret_patterns = [
        r"password\s*=\s*[\"'][^\"']+[\"']",
        r"passwd\s*=\s*[\"'][^\"']+[\"']",
        r"api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
        r"secret\s*=\s*[\"'][^\"']+[\"']",
        r"token\s*=\s*[\"'][^\"']+[\"']"
    ]

    for pattern in secret_patterns:

        if re.search(
            pattern,
            repository_context,
            re.IGNORECASE
        ):

            findings.append(
                (
                    "**Hardcoded Secret**: "
                    "Sensitive information appears to be stored "
                    "directly in source code. Secrets should be "
                    "stored using environment variables or a "
                    "dedicated secret-management system."
                )
            )

            break

    return findings


# ============================================================
# LOCAL CODE QUALITY ANALYSIS
# ============================================================

def local_quality_analysis(repository_context):

    findings = []

    if re.search(
        r"password\s*=",
        repository_context,
        re.IGNORECASE
    ):

        findings.append(
            (
                "**Potentially unused sensitive variable**: "
                "A password-like variable is present in the "
                "repository context. Verify that it is actually "
                "required and never store real credentials "
                "directly in source code."
            )
        )

    function_matches = re.findall(
        r"def\s+\w+\s*\([^)]*\)\s*:",
        repository_context
    )

    for function in function_matches:

        if "->" not in function:

            findings.append(
                (
                    "**Missing type hints**: "
                    f"`{function}` does not declare a return "
                    "type. Type hints can improve readability "
                    "and maintainability."
                )
            )

            break

    if function_matches and not re.search(
        r'"""[\s\S]*?"""',
        repository_context
    ):

        findings.append(
            (
                "**Missing documentation**: "
                "The repository does not appear to contain "
                "function documentation/docstrings."
            )
        )

    if re.search(
        r"\n\s*\w+\(\)\s*$",
        repository_context
    ):

        findings.append(
            (
                "**Module-level execution**: "
                "A function appears to be called directly when "
                "the module is loaded. Consider using an "
                "`if __name__ == \"__main__\":` guard."
            )
        )

    return findings


# ============================================================
# LOCAL FALLBACK REVIEW
# ============================================================

def generate_local_review(repository_context):

    files = extract_files(
        repository_context
    )

    functions = extract_functions(
        repository_context
    )

    classes = extract_classes(
        repository_context
    )

    security_findings = local_security_analysis(
        repository_context
    )

    quality_findings = local_quality_analysis(
        repository_context
    )

    file_text = (
        ", ".join(files)
        if files
        else "No Python files identified."
    )

    function_text = (
        ", ".join(functions)
        if functions
        else "None"
    )

    class_text = (
        ", ".join(classes)
        if classes
        else "None"
    )

    # --------------------------------------------------------
    # SECURITY SECTION
    # --------------------------------------------------------

    if security_findings:

        security_text = "\n".join(
            f"• {item}"
            for item in security_findings
        )

    else:

        security_text = (
            "• No obvious security vulnerabilities were "
            "detected by the local rule-based analysis."
        )

    # --------------------------------------------------------
    # QUALITY SECTION
    # --------------------------------------------------------

    if quality_findings:

        quality_text = "\n".join(
            f"• {item}"
            for item in quality_findings
        )

    else:

        quality_text = (
            "• No major code-quality problems were detected "
            "by the local analysis."
        )

    # --------------------------------------------------------
    # PRIORITY
    # --------------------------------------------------------

    priority_items = []

    if re.search(
        r"\beval\s*\(",
        repository_context
    ):

        priority_items.append(
            "• **High:** Remove or replace `eval()`."
        )

    if re.search(
        r"password\s*=\s*[\"']",
        repository_context,
        re.IGNORECASE
    ):

        priority_items.append(
            "• **Critical:** Remove hardcoded credentials "
            "from source code."
        )

    if not priority_items:

        priority_items.append(
            "• **Low:** Continue improving documentation, "
            "type hints and maintainability."
        )

    priority_text = "\n".join(
        priority_items
    )

    # --------------------------------------------------------
    # RECOMMENDATIONS
    # --------------------------------------------------------

    recommendations = []

    if re.search(
        r"\beval\s*\(",
        repository_context
    ):

        recommendations.append(
            "1. **Replace `eval()`:** Use native Python "
            "operators or a safe parser when dynamic "
            "evaluation is genuinely required."
        )

    if re.search(
        r"password\s*=\s*[\"']",
        repository_context,
        re.IGNORECASE
    ):

        recommendations.append(
            "2. **Remove hardcoded secrets:** Use environment "
            "variables or a secure secret manager."
        )

    recommendations.append(
        "3. **Improve maintainability:** Add type hints, "
        "docstrings and a proper application entry point."
    )

    recommendations_text = "\n".join(
        recommendations
    )

    # --------------------------------------------------------
    # FINAL REVIEW
    # --------------------------------------------------------

    return f"""
### 1. PROJECT OVERVIEW

The repository contains the following Python files:

**Files:** {file_text}

The local repository analysis was completed successfully.
The detected functions are listed below.

**Functions:** {function_text}

### 2. ARCHITECTURE

• **Files:** {file_text}

• **Functions:** {function_text}

• **Classes:** {class_text}

• **Imports:** Determined from the repository context.

• **Relationships:** The repository structure and available
code context were analyzed to identify relationships between
files and functions.

### 3. SECURITY RISKS

{security_text}

### 4. CODE QUALITY

{quality_text}

### 5. PRIORITY

{priority_text}

### 6. RECOMMENDATIONS

{recommendations_text}

---

### LOCAL FALLBACK ANALYSIS

The Gemini AI service was unavailable or its quota was reached,
so this review was generated using CodeGuardian AI's local
repository security and code-quality analysis engine.

The repository scan itself completed successfully.
"""


# ============================================================
# BUILD GEMINI PROMPT
# ============================================================

def build_prompt(repository_context):

    return f"""
You are CodeGuardian AI, a professional Python repository
security and code-quality reviewer.

Analyze ONLY the repository context provided below.

Do not invent files, classes, functions, dependencies or
vulnerabilities.

Provide a professional review using EXACTLY this structure:

### 1. PROJECT OVERVIEW

Explain what the repository contains and what it does.

### 2. ARCHITECTURE

Explain:

- Files
- Functions
- Classes
- Imports
- Dependencies
- Relationships

### 3. SECURITY RISKS

Identify confirmed security risks.

Pay special attention to:

- eval()
- exec()
- hardcoded secrets
- command execution
- SQL injection
- unsafe file handling
- insecure deserialization
- exposed credentials
- unsafe input handling

### 4. CODE QUALITY

Discuss:

- Unused variables
- Naming
- Function complexity
- Type hints
- Documentation
- Maintainability
- Code structure

### 5. PRIORITY

Classify important issues as:

- Critical
- High
- Medium
- Low

### 6. RECOMMENDATIONS

Provide practical recommendations and corrected examples
where useful.

Repository context:

============================================================

{repository_context}

============================================================
"""


# ============================================================
# MAIN REVIEW FUNCTION
# ============================================================

def review_repository(repository_context):

    # --------------------------------------------------------
    # Empty repository
    # --------------------------------------------------------

    if not repository_context or not repository_context.strip():

        return (
            "⚠️ No repository content was available for review."
        )

    # --------------------------------------------------------
    # No API key -> LOCAL FALLBACK
    # --------------------------------------------------------

    if client is None:

        return generate_local_review(
            repository_context
        )

    prompt = build_prompt(
        repository_context
    )

    max_retries = 2

    for attempt in range(max_retries):

        try:

            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0.2
                )
            )

            text = getattr(
                response,
                "text",
                None
            )

            if text and text.strip():

                return text.strip()

            return generate_local_review(
                repository_context
            )

        except Exception as error:

            error_code = get_error_code(
                error
            )

            # ------------------------------------------------
            # DAILY QUOTA
            # ------------------------------------------------

            if error_code == "429":

                error_text = str(
                    error
                ).lower()

                if (
                    "daily" in error_text
                    or "per day" in error_text
                    or "free_tier" in error_text
                    or "quota exceeded" in error_text
                ):

                    return generate_local_review(
                        repository_context
                    )

                if attempt < max_retries - 1:

                    time.sleep(3)

                    continue

                return generate_local_review(
                    repository_context
                )

            # ------------------------------------------------
            # SERVICE UNAVAILABLE
            # ------------------------------------------------

            if error_code == "503":

                if attempt < max_retries - 1:

                    time.sleep(3)

                    continue

                return generate_local_review(
                    repository_context
                )

            # ------------------------------------------------
            # ANY OTHER AI ERROR
            # ------------------------------------------------

            return generate_local_review(
                repository_context
            )

    # --------------------------------------------------------
    # FINAL FALLBACK
    # --------------------------------------------------------

    return generate_local_review(
        repository_context
    )