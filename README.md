# SIEM → ChatGPT Anonymizing Middleware

> Privacy-preserving middleware for sending SIEM alerts to ChatGPT / OpenAI.  
> Anonymizes alerts, enforces a strict field allow-list, and protects access with an API key.  
> Works with Elastic, Wazuh, and any SIEM that can POST JSON.

---

## ✨ What this does

This service sits between your **SIEM** and **ChatGPT**:

1. Receives alerts as **JSON over HTTP**.
2. **Authenticates** the request using an API key.
3. **Anonymizes** sensitive fields:
   - user names, IPs, hosts, emails, URLs, etc.
   - via configured field paths + regex rules.
4. Applies a **hard outbound field allow-list** so only approved fields ever reach the model.
5. Builds a prompt and calls the **OpenAI Chat Completions API**.
6. Returns:
   - the **anonymized alert**, and
   - the **model’s analysis** (summary, severity, next steps, etc.).

Designed for SOC teams who want AI assistance without leaking sensitive data.

---

## 🧱 Architecture

```text
[ SIEM / Logstash / Wazuh / Elastic / Other ]
                     │
                     │  HTTP POST (JSON alert, API key)
                     ▼
      [ This Middleware (Flask + Gunicorn + Docker) ]
        - API key auth
        - Anonymization (fields + regex)
        - Outbound field allow-list
        - Prompt building
        - OpenAI API call
                     │
                     ▼
               [ ChatGPT / OpenAI ]
````

Any system that can POST JSON with a header can use this.

---

## 📁 Project Structure

```text
siem-gpt-middleware/
├── docker-compose.yml
├── .env.example                 # Example environment variables (no real keys)
│
├── config/
│   ├── config.yaml              # Main config (model, allow-list, prompt, etc.)
│   ├── sensitive_fields.yaml    # Structured fields to anonymize
│   └── regex_patterns.yaml      # Regex rules for free-text anonymization
│
└── app/
    ├── Dockerfile               # Image for Flask + Gunicorn
    ├── requirements.txt         # Python dependencies
    └── app.py                   # Middleware application
```

---

## ⚙️ Configuration

### 1. Environment variables (`.env`)

Create `.env` next to `docker-compose.yml`:

```env
OPENAI_API_KEY=sk-your-openai-key
MIDDLEWARE_API_KEY=super-secret-token
APP_PORT=8000
```

> **Important:**
>
> * Never commit real keys.
> * Add `.env` to `.gitignore`.

---

### 2. Main config (`config/config.yaml`)

Controls OpenAI, logging, anonymization and the prompt:

```yaml
openai:
  model: gpt-4.1-mini
  temperature: 0.2
  timeout_seconds: 15

server:
  host: 0.0.0.0
  port: 8000
  log_level: INFO

auth:
  header_name: "X-API-Key"

anonymization:
  sensitive_fields_file: "/config/sensitive_fields.yaml"
  regex_patterns_file: "/config/regex_patterns.yaml"
  free_text_fields:
    - message
    - log.original
    - event.original

  # Only these fields are allowed to reach the model
  allowed_fields:
    - "@timestamp"
    - "event.action"
    - "event.category"
    - "event.type"
    - "rule.name"
    - "rule.id"
    - "kibana.alert.severity"
    - "kibana.alert.risk_score"
    - "host.name"
    - "source.ip"
    - "destination.ip"
    - "user.name"
    - "message"

prompt:
  system: "You are a helpful SOC assistant."
  template: |
    You are a senior SOC analyst assistant.

    You receive an anonymized SIEM alert in JSON.
    All usernames, IPs, hosts and emails are replaced with tokens like USER_xxx, IP_xxx, HOST_xxx.

    Tasks:
    1. Briefly explain what this alert is about (1–2 sentences).
    2. Assess the severity (Low/Medium/High/Critical) and justify.
    3. Suggest 3–5 next investigation steps.
    4. Suggest 2–3 hardening ideas based on the pattern.

    Respond in clear bullet points and keep it concise.

    Alert JSON:
    {alert_json}
```

You can adapt `allowed_fields` to your SIEM’s schema (Elastic ECS, Wazuh, etc.).

---

### 3. Structured sensitive fields (`config/sensitive_fields.yaml`)

Define which JSON paths should be replaced with deterministic tokens:

```yaml
sensitive_fields:
  - path: "user.name"
    prefix: "USER"
  - path: "user.email"
    prefix: "EMAIL"
  - path: "host.name"
    prefix: "HOST"
  - path: "source.ip"
    prefix: "SRCIP"
  - path: "destination.ip"
    prefix: "DSTIP"
  - path: "client.ip"
    prefix: "CLIENTIP"
  - path: "server.ip"
    prefix: "SERVERIP"
  - path: "url.full"
    prefix: "URL"
```

Same input + same prefix → same token every time (useful for correlation).

---

### 4. Regex patterns (`config/regex_patterns.yaml`)

For scrubbing free-text fields (e.g. `message`):

```yaml
patterns:
  - name: email
    pattern: "[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+"
    token_prefix: "EMAIL"

  - name: ip
    pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b"
    token_prefix: "IP"

  - name: host
    pattern: "\\b[a-zA-Z0-9-]{3,}\\.(local|lan|internal|corp|com|net|org)\\b"
    token_prefix: "HOST"
```

Extend with hashes, ticket IDs, phone numbers, internal URLs, etc. as needed.

---

## 🐍 Application

### `app/requirements.txt`

```text
flask==3.0.3
openai==1.55.3
httpx==0.28.1
gunicorn==23.0.0
PyYAML==6.0.2
```

### `app/Dockerfile`

```dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
```

---

## 🐳 Running with Docker Compose

### `docker-compose.yml`

```yaml
version: "3.9"

services:
  siem-gpt-middleware:
    build:
      context: ./app
      dockerfile: Dockerfile
    container_name: siem-gpt-middleware
    environment:
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      MIDDLEWARE_API_KEY: ${MIDDLEWARE_API_KEY}
      APP_CONFIG_FILE: "/config/config.yaml"
    volumes:
      - ./config:/config:ro
    ports:
      - "${APP_PORT:-8000}:8000"
    restart: unless-stopped
```

### Start it

```bash
cp .env.example .env   # then edit with your keys
docker compose up -d --build

curl http://localhost:8000/health
# {"status":"ok"}
```

---

## 🔌 API

### `GET /health`

Simple health check.

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

---

### `POST /analyze_alert`

Main endpoint for your SIEM / pipeline.

* **Auth:** requires `X-API-Key` (or whatever you configured as `auth.header_name`)
* **Body:** a JSON alert, either:

  * wrapped: `{ "alert": { ...alert... } }`, or
  * raw: `{ ...alert... }`

The middleware will pick `incoming["alert"]` if present, otherwise use the whole object.

Example:

```bash
curl -X POST http://localhost:8000/analyze_alert \
  -H "Content-Type: application/json" \
  -H "X-API-Key: super-secret-token" \
  -d '{
    "alert": {
      "@timestamp": "2025-01-01T10:00:00Z",
      "rule": { "name": "Suspicious RDP", "id": "rdp-001" },
      "source": { "ip": "10.0.0.5" },
      "destination": { "ip": "203.0.113.10" },
      "user": { "name": "alice" },
      "message": "User alice logged in via RDP from 10.0.0.5 to 203.0.113.10"
    }
  }'
```

Sample response (simplified):

```json
{
  "alert_id": "…if present…",
  "anonymized_alert": {
    "@timestamp": "2025-01-01T10:00:00Z",
    "rule": { "name": "Suspicious RDP", "id": "rdp-001" },
    "source": { "ip": "SRCIP_2f1a..." },
    "destination": { "ip": "DSTIP_4c9e..." },
    "user": { "name": "USER_0f3d..." },
    "message": "User USER_0f3d... logged in via RDP from SRCIP_2f1a... to DSTIP_4c9e..."
  },
  "analysis": "• Short summary...\n• Severity: High...\n• Next steps: ...",
}
```

---

## 🧩 Integration Examples

### Example A – Wazuh Manager Integration

Integration script on Wazuh manager:

```python
#!/usr/bin/env python3
# /var/ossec/integrations/gpt_middleware.py
import sys
import json
import requests

def main():
    alert_raw = sys.stdin.read()
    try:
        alert = json.loads(alert_raw)
    except Exception:
        return

    try:
        requests.post(
            "http://siem-gpt-middleware:8000/analyze_alert",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "super-secret-token",
            },
            json={"alert": alert},
            timeout=5,
        )
    except Exception:
        # Don't break Wazuh if middleware is down
        pass

if __name__ == "__main__":
    main()
```

`ossec.conf`:

```xml
<integration>
  <name>gpt_middleware</name>
  <hook_url>not_used</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

### Example B – Elastic Security HTTP Connector

In Elastic / Kibana:

1. Create an HTTP connector:

   * URL: `http://siem-gpt-middleware:8000/analyze_alert`
   * Method: `POST`
   * Header: `X-API-Key: super-secret-token`

2. In the rule action body:

```json
{
  "alert": {{#toJson}}context{{/toJson}}
}
```

(Adjust `context` / `ctx` based on version.)

---

## 🔐 Security Notes

This middleware is designed around:

* **Data minimization**
  Only fields in `anonymization.allowed_fields` are serialized into the model prompt. New / unexpected fields are dropped by default.

* **Anonymization**
  Structured sensitive fields are tokenized (e.g., `USER_ab12cd34ef`), and regex rules scrub PII from free-text.

* **API-key auth**
  `/analyze_alert` is protected by a shared secret in the header.

For production, you may also want:

* Network-level restrictions (firewall / IP allow-lists).
* Rate limiting and circuit breakers for noisy rules.
* Secret detectors (JWTs, API keys, cloud credentials) that block rather than tokenize.

---

## 🧭 Roadmap Ideas

* Optional indexing of analysis into Elasticsearch / OpenSearch.
* Per-source rate limiting and usage metrics.
* Better default patterns for secrets and tokens.
* Test suite with sample SIEM / Wazuh / ECS alerts.

---
