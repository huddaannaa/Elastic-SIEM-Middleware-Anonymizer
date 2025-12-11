import os
import json
import re
import hashlib
import logging
from copy import deepcopy
from typing import Any, Dict, List

import yaml
from flask import Flask, request, jsonify
from openai import OpenAI

# ---------- Config loading ----------

def load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise RuntimeError(f"Config file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

CONFIG_PATH = os.getenv("APP_CONFIG_FILE", "/config/config.yaml")
CONFIG = load_yaml(CONFIG_PATH)

# ---------- Logging ----------

logging.basicConfig(
    level=getattr(
        logging,
        str(CONFIG.get("server", {}).get("log_level", "INFO")).upper(),
        10,
    ),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger("siem-gpt-middleware")

logger.info(f"Loading main config from {CONFIG_PATH}")

# ---------- OpenAI client ----------

OPENAI_MODEL = CONFIG.get("openai", {}).get("model", "gpt-4.1-mini")
OPENAI_TEMPERATURE = float(CONFIG.get("openai", {}).get("temperature", 0.2))
OPENAI_TIMEOUT = int(CONFIG.get("openai", {}).get("timeout_seconds", 15))

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ---------- Auth config (API key) ----------

AUTH_HEADER_NAME = CONFIG.get("auth", {}).get("header_name", "X-API-Key")
REQUIRED_API_KEY = os.getenv("MIDDLEWARE_API_KEY")  # do NOT put key in YAML

if not REQUIRED_API_KEY:
    logger.warning(
        "MIDDLEWARE_API_KEY is not set. /analyze_alert will accept all requests. "
        "Set this env var in production!"
    )

# ---------- Anonymization config ----------

anonym_cfg = CONFIG.get("anonymization", {})
SENSITIVE_FIELDS_FILE = anonym_cfg.get("sensitive_fields_file", "/config/sensitive_fields.yaml")
REGEX_PATTERNS_FILE = anonym_cfg.get("regex_patterns_file", "/config/regex_patterns.yaml")
FREE_TEXT_FIELDS = anonym_cfg.get(
    "free_text_fields", ["message", "log.original", "event.original"]
)

ALLOWED_FIELDS = anonym_cfg.get("allowed_fields", [])
if not ALLOWED_FIELDS:
    logger.warning(
        "No anonymization.allowed_fields configured. "
        "All anonymized fields may be included in the model prompt. "
        "Configure an allow-list for tighter privacy."
    )

# Sensitive fields (structured)
sensitive_cfg = load_yaml(SENSITIVE_FIELDS_FILE)
_raw_sensitive_fields = sensitive_cfg.get("sensitive_fields", [])
SENSITIVE_FIELDS: List[Dict[str, str]] = []

for entry in _raw_sensitive_fields:
    if isinstance(entry, str):
        SENSITIVE_FIELDS.append(
            {"path": entry, "prefix": entry.split(".")[0].upper()}
        )
    elif isinstance(entry, dict) and "path" in entry:
        SENSITIVE_FIELDS.append(
            {
                "path": entry["path"],
                "prefix": entry.get("prefix", entry["path"].split(".")[0].upper()),
            }
        )

logger.info(
    f"Loaded {len(SENSITIVE_FIELDS)} sensitive fields from {SENSITIVE_FIELDS_FILE}"
)

# Regex patterns for free-text
regex_cfg = load_yaml(REGEX_PATTERNS_FILE)
_raw_patterns = regex_cfg.get("patterns", [])
REGEX_RULES = []

for pat in _raw_patterns:
    try:
        compiled = re.compile(pat["pattern"])
        prefix = pat.get("token_prefix", pat.get("name", "TOKEN").upper())
        REGEX_RULES.append(
            {
                "name": pat.get("name", "unnamed"),
                "regex": compiled,
                "prefix": prefix,
            }
        )
    except Exception as e:
        logger.error(f"Failed to compile regex pattern {pat}: {e}")

logger.info(f"Loaded {len(REGEX_RULES)} regex rules from {REGEX_PATTERNS_FILE}")

# ---------- Prompt config ----------

PROMPT_SYSTEM = CONFIG.get("prompt", {}).get(
    "system", "You are a helpful SOC assistant."
)
PROMPT_TEMPLATE = CONFIG.get("prompt", {}).get("template", "Alert:\n{alert_json}")

# ---------- Helpers ----------

def token_for(value: str, prefix: str) -> str:
    """
    Deterministic, non-reversible token.
    Same input -> same token for a given prefix.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{prefix}_{digest}"

def anonymize_text(text: str) -> str:
    """Apply regex-based PII scrubbing based on REGEX_RULES config."""
    if not text:
        return text

    def make_repl(prefix: str):
        def _repl(m: re.Match) -> str:
            return token_for(m.group(0), prefix)
        return _repl

    new_text = text
    for rule in REGEX_RULES:
        regex = rule["regex"]
        prefix = rule["prefix"]
        new_text = regex.sub(make_repl(prefix), new_text)

    return new_text

def _get_nested(d: Dict[str, Any], path: str):
    parts = path.split(".")
    cur = d
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur

def _set_nested(d: Dict[str, Any], path: str, value: Any):
    parts = path.split(".")
    cur = d
    for p in parts[:-1]:
        if p not in cur or not isinstance(cur[p], dict):
            cur[p] = {}
        cur = cur[p]
    cur[parts[-1]] = value

def anonymize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clone alert, anonymize known structured sensitive fields and configured
    free-text fields.
    """
    safe = deepcopy(alert)

    # Structured fields
    for field in SENSITIVE_FIELDS:
        path = field["path"]
        prefix = field["prefix"]
        val = _get_nested(safe, path)
        if isinstance(val, str) and val.strip():
            _set_nested(safe, path, token_for(val, prefix))

    # Free-text fields
    for key in FREE_TEXT_FIELDS:
        val = _get_nested(safe, key)
        if isinstance(val, str) and val.strip():
            _set_nested(safe, key, anonymize_text(val))

    return safe

def build_allowed_view(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a new dict that only contains fields from ALLOWED_FIELDS.
    This is the ONLY object that will be serialized and sent to the model.
    """
    if not ALLOWED_FIELDS:
        # No allow-list configured, fall back to full alert (anonymized)
        return alert

    filtered: Dict[str, Any] = {}
    for path in ALLOWED_FIELDS:
        val = _get_nested(alert, path)
        if val is not None:
            _set_nested(filtered, path, val)
    return filtered

def build_prompt(anonymized_alert: Dict[str, Any]) -> str:
    # Apply hard allow-list here
    alert_for_model = build_allowed_view(anonymized_alert)
    alert_str = json.dumps(alert_for_model, indent=2, sort_keys=True)
    return PROMPT_TEMPLATE.format(alert_json=alert_str)

def check_api_key() -> bool:
    """
    Enforce simple header-based API key auth on /analyze_alert.
    If no REQUIRED_API_KEY is set, this returns True (for dev).
    """
    if not REQUIRED_API_KEY:
        # No key configured: effectively disabled (dev mode)
        return True

    provided = request.headers.get(AUTH_HEADER_NAME)
    if not provided:
        logger.warning("Unauthorized request: missing API key header")
        return False

    if provided != REQUIRED_API_KEY:
        logger.warning("Unauthorized request: invalid API key")
        return False

    return True

# ---------- Flask app ----------

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/analyze_alert", methods=["POST"])
def analyze_alert():
    """
    Entry point for Elastic webhook / Logstash HTTP output.

    Expected body: JSON alert (Elastic document or rule payload).
    Returns: anonymized alert + GPT analysis.
    """

    # --- API key auth ---
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        incoming = request.get_json(force=True, silent=False)
    except Exception:
        logger.warning("Received invalid JSON")
        return jsonify({"error": "Invalid JSON"}), 400

    if not isinstance(incoming, dict):
        return jsonify({"error": "Expected JSON object"}), 400

    # Some environments send { "alert": {...} }
    alert = incoming.get("alert", incoming)

    anonymized = anonymize_alert(alert)
    prompt = build_prompt(anonymized)

    try:
        completion = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": PROMPT_SYSTEM},
                {"role": "user", "content": prompt},
            ],
            temperature=OPENAI_TEMPERATURE,
            timeout=OPENAI_TIMEOUT,
        )
        analysis = completion.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}")
        return jsonify(
            {
                "error": "OpenAI API call failed",
                "details": str(e),
                "anonymized_alert": anonymized,
            }
        ), 500

    response_body: Dict[str, Any] = {
        # full anonymized alert back to Elastic (only tokens, no raw)
        "anonymized_alert": anonymized,
        # model’s analysis (based only on allowed fields)
        "analysis": analysis,
    }

    for key in ["kibana.alert.uuid", "event.id", "alert.id"]:
        val = incoming.get(key) or alert.get(key)
        if val:
            response_body["alert_id"] = val
            break

    return jsonify(response_body), 200

if __name__ == "__main__":
    host = CONFIG.get("server", {}).get("host", "0.0.0.0")
    port = int(CONFIG.get("server", {}).get("port", 8000))
    app.run(host=host, port=port)

