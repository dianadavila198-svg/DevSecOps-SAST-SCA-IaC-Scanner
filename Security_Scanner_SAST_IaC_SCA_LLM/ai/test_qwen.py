# TO BE DELETED FOR API LLM Model TESTING ONLY

"""
Test OpenRouter connection with model fallback.
Tries each model in order; falls back to the next on rate-limit or unavailability.
"""

import os
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not API_KEY:
    sys.exit("ERROR: OPENROUTER_API_KEY not found. Did you create your .env file?")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"


# Models tried in priority order. OpenAI is tried first as it's the most
# responsive on the free tier; Qwen-Coder is the secondary fallback; 
# Llama is a last resort. All end in :free to stay on the free tier.
MODELS = [
    "openai/gpt-oss-20b:free",
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",
]
MAX_RETRIES_PER_MODEL = 2   # quick retries on 429 before moving to next model
BASE_WAIT = 2

test_code = (
    "def login(user):\n"
    "    query = \"SELECT * FROM users WHERE name = '\" + user + \"'\"\n"
    "    return db.execute(query)"
)

prompt = (
    "You are a security code reviewer. "
    "Identify any security vulnerability in the following Python code "
    "and name the vulnerability type in one short sentence:\n\n"
    f"{test_code}"
)


def call_model(model):
    """Make one request to a given model."""
    return requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )


def try_model(model):
    """Try one model with a couple of quick retries. Returns the answer text, or None to fall back."""
    for attempt in range(1, MAX_RETRIES_PER_MODEL + 1):
        response = call_model(model)

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]

        # Rate-limited: brief wait, then retry this same model
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            wait = int(retry_after) if retry_after else BASE_WAIT * attempt
            print(f"  {model}: rate-limited (429), waiting {wait}s (attempt {attempt})...")
            time.sleep(wait)
            continue

        # Unavailable / not free anymore: don't retry, fall back to next model
        if response.status_code in (402, 404):
            print(f"  {model}: unavailable ({response.status_code}) - falling back.")
            return None

        # Any other error: show it and fall back
        print(f"  {model}: error {response.status_code} - falling back. ({response.text[:120]})")
        return None

    # Exhausted retries on 429
    print(f"  {model}: still rate-limited after {MAX_RETRIES_PER_MODEL} attempts - falling back.")
    return None


def main():
    print("Trying models in priority order...\n")
    for model in MODELS:
        print(f"Trying {model} ...")
        answer = try_model(model)
        if answer:
            print(f"\n--- Success with {model} ---\n")
            print("MODEL RESPONSE:\n")
            print(answer)
            return

    sys.exit("\nAll models failed. The free tier may be busy - try again later.")


if __name__ == "__main__":
    main()