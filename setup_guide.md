# Integration Guide — Policy Gateway + Audit Trail

## Overview

This guide shows how to integrate the compliance configurations with your AI agent system. We use the `agent-policy-gateway-mcp` and `agent-audit-trail-mcp` servers as reference, but the configs work with any Python-based agent framework.

---

## Step 1: Install Required Packages

```bash
pip install agent-policy-gateway-mcp  # Policy enforcement
# Or if building custom:
pip install mcp httpx python-dotenv
```

## Step 2: Load PII Patterns

```python
import json
import re

# PII-Patterns laden
with open("configs/pii_patterns.json") as f:
    pii_config = json.load(f)

# Patterns kompilieren fuer Performance
compiled_patterns = []
for pattern_def in pii_config["patterns"]:
    compiled_patterns.append({
        "id": pattern_def["id"],
        "name": pattern_def["name"],
        "severity": pattern_def["severity"],
        "regex": re.compile(pattern_def["pattern"]),
        "context": pattern_def.get("context_required"),
        "special_category": pattern_def.get("special_category", False),
    })


def scan_for_pii(text: str) -> list[dict]:
    """Text auf PII scannen. Gibt Liste gefundener Muster zurueck."""
    findings = []
    text_lower = text.lower()

    for pattern in compiled_patterns:
        # Kontext-Check: Manche Patterns brauchen bestimmte Schluesselwoerter
        if pattern["context"]:
            if not re.search(pattern["context"], text_lower):
                continue

        matches = pattern["regex"].findall(text)
        if matches:
            findings.append({
                "pattern_id": pattern["id"],
                "pattern_name": pattern["name"],
                "severity": pattern["severity"],
                "match_count": len(matches),
                "special_category": pattern["special_category"],
            })

    return findings
```

## Step 3: Apply GDPR Policies

```python
# GDPR-Policies laden
with open("configs/gdpr_policies.json") as f:
    gdpr_config = json.load(f)


def check_data_processing(purpose: str, has_consent: bool) -> dict:
    """Pruefen ob Datenverarbeitung erlaubt ist."""
    rules = gdpr_config["data_processing_rules"]

    # Zweckbindung pruefen
    allowed = rules["purpose_limitation"]["allowed_purposes"]
    blocked = rules["purpose_limitation"]["blocked_purposes"]

    if purpose in blocked:
        return {
            "allowed": False,
            "reason": f"Zweck '{purpose}' ist blockiert (GDPR Art. 5 Abs. 1 lit. b)"
        }

    if purpose not in allowed and not has_consent:
        return {
            "allowed": False,
            "reason": f"Zweck '{purpose}' nicht in erlaubter Liste und keine Einwilligung"
        }

    return {"allowed": True, "reason": "Verarbeitung erlaubt"}


def get_retention_days(data_type: str) -> int:
    """Aufbewahrungsfrist fuer einen Datentyp ermitteln."""
    policies = gdpr_config["data_processing_rules"]["storage_limitation"]["retention_policies"]

    if data_type in policies:
        return policies[data_type]["retention_days"]

    return gdpr_config["data_processing_rules"]["storage_limitation"]["default_retention_days"]
```

## Step 4: AI Act Risk Classification

```python
# AI Act Policies laden
with open("configs/ai_act_policies.json") as f:
    ai_act_config = json.load(f)


def classify_risk(use_case: str) -> dict:
    """Anwendungsfall nach EU AI Act klassifizieren."""
    categories = ai_act_config["risk_classification"]["categories"]

    # Von hoechstem zu niedrigstem Risiko pruefen
    for level_name in ["unacceptable", "high_risk", "limited_risk", "minimal_risk"]:
        category = categories[level_name]
        for example in category["examples"]:
            if example.lower() in use_case.lower():
                return {
                    "risk_level": level_name,
                    "risk_score": category["level"],
                    "action": category["action"],
                    "requirements": category["requirements"],
                }

    # Standard: Limited Risk (da Chatbots dort eingeordnet sind)
    return {
        "risk_level": "limited_risk",
        "risk_score": 2,
        "action": "transparency_obligations",
        "requirements": categories["limited_risk"]["requirements"],
    }
```

## Step 5: Configure Audit Logging

```python
import json
import time
import hashlib
from pathlib import Path

# Audit-Config laden
with open("configs/audit_config.json") as f:
    audit_config = json.load(f)


class AuditLogger:
    """Audit-Logger mit Hash-Kette fuer Integritaet."""

    def __init__(self, log_dir: str = "./logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.log_file = self.log_dir / "audit.jsonl"
        self._last_hash = "genesis"

    def log_event(self, category: str, data: dict) -> None:
        """Ereignis protokollieren mit Hash-Kette."""
        event_config = audit_config["events"]["categories"].get(category, {})
        if not event_config.get("enabled", False):
            return

        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "category": category,
            "data": data,
            "previous_hash": self._last_hash,
        }

        # Hash berechnen fuer Integritaet
        entry_str = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()
        self._last_hash = entry["hash"]

        # In Datei schreiben
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_tool_invocation(self, tool_name: str, params: dict, result_summary: str) -> None:
        """Tool-Aufruf protokollieren."""
        self.log_event("tool_invocation", {
            "tool": tool_name,
            "parameters": params if audit_config["events"]["categories"]["tool_invocation"]["log_parameters"] else {},
            "result_summary": result_summary[:500],
        })

    def log_pii_detection(self, pattern_id: str, severity: str, redacted: str) -> None:
        """PII-Erkennung protokollieren."""
        self.log_event("pii_detection", {
            "pattern_id": pattern_id,
            "severity": severity,
            "redacted_text": redacted,
        })

    def log_policy_violation(self, policy_id: str, action: str, details: str) -> None:
        """Richtlinienverstoß protokollieren."""
        self.log_event("policy_violation", {
            "policy_id": policy_id,
            "action_taken": action,
            "details": details,
        })


# Globale Logger-Instanz
audit = AuditLogger()
```

## Step 6: Putting It All Together

```python
async def process_agent_request(tool_name: str, params: dict, text_input: str) -> str:
    """Kompletter Compliance-Flow fuer einen Agent-Request."""

    # 1. PII scannen
    pii_findings = scan_for_pii(text_input)
    for finding in pii_findings:
        audit.log_pii_detection(
            finding["pattern_id"],
            finding["severity"],
            f"[{finding['pattern_name']} REDACTED]"
        )
        # Kritische PII blockieren
        if finding["severity"] == "critical":
            audit.log_policy_violation(
                "pii_critical_block",
                "blocked",
                f"Kritische PII erkannt: {finding['pattern_name']}"
            )
            return f"Anfrage blockiert: {finding['pattern_name']} erkannt."

    # 2. Datenverarbeitung pruefen
    check = check_data_processing("user_request_fulfillment", has_consent=True)
    if not check["allowed"]:
        return f"Nicht erlaubt: {check['reason']}"

    # 3. Tool ausfuehren
    result = await execute_tool(tool_name, params)  # Deine Tool-Logik

    # 4. Audit loggen
    audit.log_tool_invocation(tool_name, params, result[:200])

    return result
```

---

## Production Checklist

Before deploying to production, verify:

1. All config files loaded without errors
2. PII patterns tested with sample data
3. Audit log file writable and rotating correctly
4. Retention policies configured for your jurisdiction
5. Alert channels configured and tested
6. Compliance officer has access to audit logs
7. Data Processing Agreement (DPA) with third parties in place
