"""AI enrichment (plain-language explanations) """

import os
import time
import requests
import sys
from dotenv import load_dotenv


load_dotenv()

API_KEY = os.environ.get("OPENROUTER_API_KEY")
if not API_KEY:
    sys.exit("ERROR: OPENROUTER_API_KEY not found. Confir is created in .env file")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Models tried in priority order. OpenAI is tried first as it's the most
# responsive on the free tier; Qwen-Coder is the secondary fallback; 
# Llama is a last resort. All end in :free to stay on the free tier.
FALLBACK_MODELS = [
    "openai/gpt-oss-20b:free",
    "qwen/qwen3-coder:free",
    "meta-llama/llama-3.3-70b-instruct:free",

]

#API Retry
MAX_RETRIES_PER_MODEL = 2   # quick retries on a busy (429) model before falling back
BASE_WAIT = 2               # base seconds for backoff


def build_prompt(finding):
    """Turn one Finding object into a prompt asking the model to enrich it."""
    return (
        "You are a security code reviewer. A static analysis scanner has "
        "flagged the following issue. Write a short, plain-language "
        "explanation (2-3 sentences) of why this matters, followed by a "
        "concrete code fix.\n\n"
        f"Rule: {finding.rule_id}\n"
        f"Severity: {finding.severity}\n"
        f"File: {finding.file_path}, line {finding.line}\n"
        f"Standard: {finding.standard_ref}\n"
        f"Finding: {finding.message}\n"
    )
    


#API Key authorization
def _call_model(model, prompt, api_key):
    """Make one request to a single model. Returns the requests.Response."""
    return requests.post(
        OPENROUTER_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,  
        },
        timeout=15,  #  15 s it fails fast and moves to the fallback
    )

#Try on different models according to availability 
def _try_model(model, prompt, api_key):
    """Try one model, with brief retries on rate-limit.

    Returns the answer text on success, or None to signal 'fall back'.
    """
    for attempt in range(1, MAX_RETRIES_PER_MODEL + 1):
        try:
            response = _call_model(model, prompt, api_key)
            if response.status_code == 200:
                data = response.json()
                #Fall secure, in case LLM output dont respond
                if "choices" in data and data["choices"]:
                    return data ["choices"][0]["message"]["content"].strip()
                else:
                    print(f"  {model}: response missing 'choices' - falling back. ({str(data)[:120]})")
                    return None
                
             # Busy: wait and retry the same model
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait = int(retry_after) if retry_after else BASE_WAIT * attempt
                time.sleep(wait)
                continue

        # Unavailable / paid-only / other error: don't retry, fall back
            return None
        
        except (requests.exceptions.RequestException, TimeoutError) as e:
            continue
            
    return None  # exhausted retries on 429

def enrich_finding(finding):
    """
    Try every model in order for one Finding. Always returns a dict
    combining the finding's own fields with the enrichment result —
    never returns None, and never lets enrichment failure block the
    underlying finding from being reported (additive, never load-bearing).
    """
    finding_dict = {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "attack_type_exposure": finding.attack_type_exposure,
        "file_path": finding.file_path,
        "line": finding.line,
        "message": finding.message,
        "standard_ref": finding.standard_ref,
    }

    if not API_KEY:
        return {**finding_dict, "ai_explanation": None,
                "ai_note": "No API key set; skipped AI enrichment."}

    prompt = build_prompt(finding)
    for model in FALLBACK_MODELS:
        answer = _try_model(model, prompt, API_KEY)
        if answer:
            return {**finding_dict, "ai_explanation": answer, "ai_model": model}

    # Every model failed — return the finding unchanged, with a note
    return {**finding_dict, "ai_explanation": None,
            "ai_note": "All AI models unavailable; rule-based finding only."}


def enrich_findings(findings):
    """Enrich a list of Findings. Always returns one dict per finding."""
    return [enrich_finding(f) for f in findings]
