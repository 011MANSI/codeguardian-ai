import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

client = None

if api_key:
    client = genai.Client(api_key=api_key)


def review_code(code: str) -> str:

    if client is None:
        return "AI review unavailable: Gemini API key is not configured."

    prompt = f"""
You are CodeGuardian AI, an expert Python software engineer.

Analyze this Python code:

{code}

Provide a concise review using these sections:

### Overall Assessment

### Bugs and Logic Problems

### Security Concerns

### Performance

### Code Quality

### Improvement Suggestions

### Improved Code

Explain everything clearly for a computer science student.
"""

    try:

        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt
        )

        if response.text:
            return response.text

        return "AI review completed, but no response was returned."

    except Exception as e:

        error_message = str(e)

        if "429" in error_message or "RESOURCE_EXHAUSTED" in error_message:
            return (
                "⚠️ Gemini free-tier limit reached. "
                "Local CodeGuardian analysis is still available. "
                "Please try AI analysis again after the quota resets."
            )

        if "503" in error_message or "UNAVAILABLE" in error_message:
            return (
                "⚠️ Gemini is temporarily unavailable. "
                "Local CodeGuardian analysis is still available."
            )

        return "⚠️ AI review temporarily unavailable."