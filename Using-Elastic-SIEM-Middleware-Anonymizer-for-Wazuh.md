## Title

**Using Wazuh Alerts Safely with ChatGPT: Anonymized AI Triage for SOCs**

## Subtitle

How I built a privacy-preserving gateway between Wazuh and ChatGPT so SOC teams can get AI help without leaking sensitive data.

---

### Why I Wanted ChatGPT Inside My Wazuh Workflows

Wazuh already gives us a powerful, open-source SIEM and XDR platform.

But as alert volume grows, SOC analysts are still stuck with the same reality:

* Too many alerts
* Too little time
* Not enough context per event

LLMs like ChatGPT can help explain alerts, suggest next steps, and even highlight related techniques or hypotheses. The problem is obvious:

> **You can’t just dump raw Wazuh alerts into a public LLM API and hope for the best.**

Those alerts might contain:

* Internal IPs and hostnames
* Usernames and emails
* URLs, paths, ticket IDs, and other sensitive details

So the question became:

> *How can I safely send Wazuh alerts to ChatGPT, in a way that keeps identities and infrastructure details private?*

---

### The Idea: A Privacy Gateway Between Wazuh and ChatGPT

Instead of sending alerts directly to OpenAI, I built a small middleware service that sits in the middle:

```text
Wazuh agents → Wazuh manager → [Middleware] → ChatGPT (OpenAI API)
```

The middleware:

1. Receives Wazuh alerts as JSON over HTTP
2. Authenticates the request using an API key
3. **Anonymizes** sensitive fields (user, IP, host, URL, etc.)
4. Applies a **hard allow-list** so only approved fields are ever sent to ChatGPT
5. Builds a prompt and calls the OpenAI API
6. Returns:

   * the anonymized alert, and
   * ChatGPT’s analysis (summary, severity, next steps, hardening ideas)

The full source code is on GitHub:

> 🔗 **GitHub repo:**
> `https://github.com/huddaannaa/Huds-Elastic-SIEM-GPT-Middleware`

The repo is SIEM-generic, but in this article I’ll focus on the Wazuh integration.

---

### What the Middleware Actually Does

At a high level, the middleware implements three safety layers:

#### 1. Authentication

Every request to `POST /analyze_alert` must include an API key header, for example:

```http
X-API-Key: super-secret-token
```

The key is configured via environment variable (`MIDDLEWARE_API_KEY`), not hard-coded.

#### 2. Anonymization

Two mechanisms are used:

* **Structured fields**: specific JSON paths are tokenized:

  * `agent.name` → `AGENT_3a9f...`
  * `agent.ip` → `AGENTIP_7b12...`
  * `data.srcip` → `SRCIP_...`
  * `data.dstip` → `DSTIP_...`
  * `data.user` → `USER_...`

* **Regex-based scrubbing** for free-text fields:

  * IP addresses
  * Email addresses
  * Hostnames
  * (You can add phone numbers, hashes, ticket IDs, etc.)

The mappings are deterministic: the same original value always becomes the same token (with the same prefix), which keeps it anonymous but still useful for correlation.

#### 3. Hard Field Allow-List

Even after anonymization, the middleware does **not** send the entire alert to ChatGPT.

Only fields listed under `anonymization.allowed_fields` in `config/config.yaml` are included in the JSON that’s embedded into the LLM prompt. Everything else is dropped.

This means:

* If new fields appear in Wazuh logs later, they won’t magically start leaking into the model.
* You explicitly decide what the model is allowed to see.

---

### Repository Layout (High Level)

In the GitHub repo you’ll find:

```text
Huds-Elastic-SIEM-GPT-Middleware/
├── docker-compose.yml
├── .env.example
├── config/
│   ├── config.yaml              # OpenAI model, logging, allow-list, prompt, etc.
│   ├── sensitive_fields.yaml    # List of fields to tokenize
│   └── regex_patterns.yaml      # Regexes for free-text anonymization
└── app/
    ├── Dockerfile               # Flask + Gunicorn container
    ├── requirements.txt
    └── app.py                   # Middleware application
```

You don’t need to copy-paste code from this article. Use the GitHub repo as the single source of truth and just customize the YAML files for your environment.

---

### Deploying the Middleware (Quick Version)

Full instructions are in the README, but the basic steps are:

1. **Clone the repo:**

```bash
git clone https://github.com/huddaannaa/Huds-Elastic-SIEM-GPT-Middleware.git
cd Huds-Elastic-SIEM-GPT-Middleware
```

2. **Create a `.env` file from the example:**

```bash
cp .env.example .env
vi .env
```

Fill in:

```env
OPENAI_API_KEY=sk-your-openai-key
MIDDLEWARE_API_KEY=super-secret-token
APP_PORT=8000
```

3. **Review the configuration in `config/config.yaml`**

* Update `allowed_fields` to match the Wazuh fields you want the model to see.
* Tweak the prompt text if you like.

4. **Start the container:**

```bash
docker compose up -d --build
```

5. **Check it’s alive:**

```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

Now you have a running AI gateway waiting to receive alerts.

---

### Wiring Wazuh to the Middleware (Manager Integration)

The simplest way to connect Wazuh is through a manager integration script.

#### 1. Create the integration script on the Wazuh manager

On the Wazuh manager host:

```bash
sudo vi /var/ossec/integrations/gpt_middleware.py
```

Example script (very similar to the one in the README):

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

> Note: replace `siem-gpt-middleware` and `super-secret-token` with your actual hostname and key.

Make it executable:

```bash
sudo chmod +x /var/ossec/integrations/gpt_middleware.py
```

#### 2. Register the integration in `ossec.conf`

Add a block like this:

```xml
<integration>
  <name>gpt_middleware</name>
  <hook_url>not_used</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

* `level` controls which alerts are sent (e.g. level ≥ 10 only).
* `alert_format` is set to `json` so the script receives raw JSON.

Restart the Wazuh manager so the changes take effect.

Now, whenever a high-severity alert is generated, Wazuh will:

* Pipe the alert JSON into `gpt_middleware.py`
* The script will push it to the middleware
* The middleware will anonymize it and ask ChatGPT for triage help

---

### What You Get Back

A typical response from the middleware looks like:

```json
{
  "alert_id": "…if present…",
  "anonymized_alert": {
    "@timestamp": "2025-01-01T10:00:00Z",
    "rule": { "name": "Suspicious RDP", "id": "100200" },
    "agent": { "name": "AGENT_3a9f...", "ip": "AGENTIP_7b12..." },
    "data": {
      "srcip": "SRCIP_2f1a...",
      "dstip": "DSTIP_4c9e...",
      "user": "USER_0f3d..."
    },
    "message": "User USER_0f3d... logged in via RDP from SRCIP_2f1a... to DSTIP_4c9e..."
  },
  "analysis": "• Short summary...\n• Severity: High...\n• Suggested steps: ..."
}
```

You can:

* Log this response
* Forward it to another system
* Or extend the middleware (the GitHub repo is structured so you can easily add an Elasticsearch/OpenSearch output)

---

### Why This Matters for Wazuh Users

As a Wazuh user (and ambassador), this pattern gives a few important benefits:

* **Safer experimentation with AI**
  You don’t have to choose between “no AI at all” and “raw alerts to a third-party API”.

* **Config-driven privacy**
  You can adjust:

  * Which fields are anonymized
  * Which fields are allowed out
  * How the LLM is prompted
    simply by editing YAML files.

* **Vendor-neutral**
  The same middleware also works with:

  * Elastic Security rules
  * Logstash pipelines
  * Other SIEMs that can send JSON over HTTP

But the Wazuh manager integration is one of the most straightforward starting points.

---

### Limitations and Things to Keep in Mind

This middleware:

* **Reduces risk**, but doesn’t replace a full DLP or legal review.
* Relies on you keeping `sensitive_fields.yaml` and `regex_patterns.yaml` up to date with:

  * new log sources
  * new data formats
  * new compliance requirements

You should still:

* Review your Wazuh data model
* Decide what “must never leave” under any circumstances
* Possibly add “hard-block” logic for things like cloud keys, JWTs, etc.
