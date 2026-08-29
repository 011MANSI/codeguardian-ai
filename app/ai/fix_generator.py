import os
import re

from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = None

if api_key:
    client = genai.Client(api_key=api_key)


# =========================================================
# ENSURE REQUIRED IMPORTS
# =========================================================

def ensure_required_imports(code: str) -> str:
    """
    Makes sure required imports exist in the generated code.

    Currently guarantees:
        import os
    when os.getenv() is used.
    """

    code = code.strip()

    # -----------------------------------------------------
    # If os.getenv() is used, guarantee import os
    # -----------------------------------------------------

    if "os.getenv(" in code:

        # Already has: import os
        has_import_os = re.search(
            r"(?m)^\s*import\s+os\s*$",
            code
        )

        # Already has: from os import ...
        has_from_os = re.search(
            r"(?m)^\s*from\s+os\s+import\s+",
            code
        )

        if not has_import_os and not has_from_os:

            code = "import os\n\n" + code

    return code


# =========================================================
# REMOVE MARKDOWN FROM AI RESPONSE
# =========================================================

def clean_ai_code(text: str) -> str:
    """
    Removes Markdown code fences accidentally returned by Gemini.
    """

    if not text:
        return ""

    code = text.strip()

    # ```python ... ```
    match = re.search(
        r"```(?:python|py)?\s*([\s\S]*?)```",
        code,
        flags=re.IGNORECASE
    )

    if match:
        code = match.group(1).strip()

    else:

        # Remove opening fence if closing fence is missing
        code = re.sub(
            r"^```(?:python|py)?\s*",
            "",
            code,
            flags=re.IGNORECASE
        )

        code = re.sub(
            r"\s*```$",
            "",
            code
        )

    return code.strip()


# =========================================================
# LOCAL FIX
# =========================================================

def local_fix(code: str, issues: list) -> str:
    """
    Generates a safe local fix when Gemini is unavailable.

    Handles:
    - eval()
    - exec()
    - hardcoded passwords
    - hardcoded secrets
    - API keys
    - tokens
    """

    fixed_code = code

    # -----------------------------------------------------
    # 1. Replace simple eval("number + number")
    # -----------------------------------------------------

    pattern = r'eval\(\s*"(\d+)\s*\+\s*(\d+)"\s*\)'

    def replace_addition(match):

        a = match.group(1)
        b = match.group(2)

        return f"{a} + {b}"

    fixed_code = re.sub(
        pattern,
        replace_addition,
        fixed_code
    )

    # -----------------------------------------------------
    # 2. Replace simple eval('number + number')
    # -----------------------------------------------------

    pattern_single = r"eval\(\s*'(\d+)\s*\+\s*(\d+)'\s*\)"

    def replace_addition_single(match):

        a = match.group(1)
        b = match.group(2)

        return f"{a} + {b}"

    fixed_code = re.sub(
        pattern_single,
        replace_addition_single,
        fixed_code
    )

    # -----------------------------------------------------
    # 3. Remove dangerous exec()
    # -----------------------------------------------------

    fixed_code = re.sub(
        r"exec\(\s*[^)]*\)",
        "# Removed unsafe exec() call",
        fixed_code
    )

    # -----------------------------------------------------
    # 4. Replace hardcoded secrets
    # -----------------------------------------------------
    #
    # Example:
    #
    # password = "MySecret123"
    #
    # becomes:
    #
    # password = os.getenv("PASSWORD")
    #
    # -----------------------------------------------------

    secret_pattern = re.compile(
        r'(?im)^(\s*)'
        r'(password|passwd|pwd|secret|api_key|apikey|token|access_token)'
        r'(\s*=\s*)'
        r'(["\'])(.*?)\4\s*$'
    )

    def replace_secret(match):

        indentation = match.group(1)
        variable = match.group(2)
        equals = match.group(3)

        env_name = variable.upper()

        return (
            f'{indentation}'
            f'{variable}'
            f'{equals}'
            f'os.getenv("{env_name}")'
        )

    fixed_code = secret_pattern.sub(
        replace_secret,
        fixed_code
    )

    # -----------------------------------------------------
    # 5. GUARANTEE import os
    # -----------------------------------------------------

    fixed_code = ensure_required_imports(
        fixed_code
    )

    return fixed_code.strip()


# =========================================================
# AI FIX GENERATOR
# =========================================================

def generate_fix(code: str, issues: list) -> str:

    # -----------------------------------------------------
    # No Gemini client
    # -----------------------------------------------------

    if client is None:

        return local_fix(
            code,
            issues
        )

    # -----------------------------------------------------
    # Prepare issue information
    # -----------------------------------------------------

    issue_text = "\n".join(
        f"- {issue.get('type', 'Issue')} "
        f"({issue.get('severity', 'Unknown')}): "
        f"{issue.get('message', '')}"
        for issue in issues
    )

    # -----------------------------------------------------
    # AI prompt
    # -----------------------------------------------------

    prompt = f"""
You are CodeGuardian AI, an expert Python security engineer.

Detected issues:

{issue_text}

Original code:

{code}

Generate a completely corrected and safer version.

IMPORTANT RULES:

1. Never use eval().
2. Never use exec().
3. Remove hardcoded passwords.
4. Remove hardcoded API keys.
5. Remove hardcoded secrets.
6. Use os.getenv() for sensitive configuration.
7. If os.getenv() is used, ALWAYS include:
   import os
8. Preserve the original functionality.
9. Preserve function names where possible.
10. Do not invent unnecessary functionality.
11. Return complete valid Python code.
12. Return ONLY Python code.
13. Do NOT use Markdown code fences.
14. Do NOT include explanations.
"""

    try:

        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt
        )

        # -------------------------------------------------
        # Gemini returned code
        # -------------------------------------------------

        if response and response.text:

            fixed_code = clean_ai_code(
                response.text
            )

            # -------------------------------------------------
            # GUARANTEE REQUIRED IMPORTS EVEN FOR GEMINI
            # -------------------------------------------------

            fixed_code = ensure_required_imports(
                fixed_code
            )

            return fixed_code

        # -------------------------------------------------
        # Empty Gemini response
        # -------------------------------------------------

        return local_fix(
            code,
            issues
        )

    except Exception as e:

        error_message = str(e).upper()

        # -------------------------------------------------
        # 429 QUOTA / RATE LIMIT
        # -------------------------------------------------

        if (
            "429" in error_message
            or "RESOURCE_EXHAUSTED" in error_message
            or "QUOTA" in error_message
            or "RATE LIMIT" in error_message
        ):

            print(
                "⚠️ Gemini quota/rate limit reached."
            )

            print(
                "➡️ Using local security fixer."
            )

            return local_fix(
                code,
                issues
            )

        # -------------------------------------------------
        # 503 SERVICE UNAVAILABLE
        # -------------------------------------------------

        if (
            "503" in error_message
            or "UNAVAILABLE" in error_message
            or "SERVICE UNAVAILABLE" in error_message
        ):

            print(
                "⚠️ Gemini service unavailable."
            )

            print(
                "➡️ Using local security fixer."
            )

            return local_fix(
                code,
                issues
            )

        # -------------------------------------------------
        # OTHER GEMINI ERROR
        # -------------------------------------------------

        print(
            f"⚠️ Gemini fix generation failed: {e}"
        )

        return local_fix(
            code,
            issues
        )