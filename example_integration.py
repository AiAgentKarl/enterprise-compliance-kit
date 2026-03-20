"""
Compliance Kit — Vollstaendiges Integrationsbeispiel
====================================================

Zeigt wie alle Configs zusammenspielen:
1. PII-Erkennung auf eingehende Texte
2. GDPR-Policy-Pruefung
3. AI Act Risiko-Klassifizierung
4. Audit-Logging mit Hash-Kette

Ausfuehrung:
    python example_integration.py
"""

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any


# ============================================================
# 1. Konfigurationen laden
# ============================================================

CONFIG_DIR = Path(__file__).parent / "configs"


def load_config(filename: str) -> dict[str, Any]:
    """JSON-Konfiguration laden."""
    with open(CONFIG_DIR / filename, encoding="utf-8") as f:
        return json.load(f)


pii_config = load_config("pii_patterns.json")
gdpr_config = load_config("gdpr_policies.json")
ai_act_config = load_config("ai_act_policies.json")
audit_config = load_config("audit_config.json")


# ============================================================
# 2. PII-Scanner
# ============================================================

class PIIScanner:
    """Scannt Text auf personenbezogene Daten."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.patterns = []
        self.severity_actions = config["severity_actions"]

        for p in config["patterns"]:
            self.patterns.append({
                "id": p["id"],
                "name": p["name"],
                "severity": p["severity"],
                "category": p["category"],
                "regex": re.compile(p["pattern"]),
                "context": p.get("context_required"),
                "special": p.get("special_category", False),
            })

    def scan(self, text: str) -> list[dict[str, Any]]:
        """Text scannen und Treffer zurueckgeben."""
        findings = []
        text_lower = text.lower()

        for pattern in self.patterns:
            # Kontext pruefen (manche Patterns brauchen Schluesselwoerter)
            if pattern["context"]:
                if not re.search(pattern["context"], text_lower):
                    continue

            matches = pattern["regex"].findall(text)
            if matches:
                action = self.severity_actions[pattern["severity"]]
                findings.append({
                    "pattern_id": pattern["id"],
                    "name": pattern["name"],
                    "category": pattern["category"],
                    "severity": pattern["severity"],
                    "match_count": len(matches),
                    "special_category": pattern["special"],
                    "action": action["action"],
                    "should_redact": action["redact"],
                })

        return findings


# ============================================================
# 3. GDPR Policy Checker
# ============================================================

class GDPRChecker:
    """Prueft GDPR-Konformitaet."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.rules = config["data_processing_rules"]
        self.rights = config["data_subject_rights"]

    def check_purpose(self, purpose: str) -> dict[str, Any]:
        """Pruefen ob der Verarbeitungszweck erlaubt ist."""
        allowed = self.rules["purpose_limitation"]["allowed_purposes"]
        blocked = self.rules["purpose_limitation"]["blocked_purposes"]

        if purpose in blocked:
            return {"allowed": False, "reason": f"Zweck '{purpose}' blockiert"}
        if purpose in allowed:
            return {"allowed": True, "reason": "Zweck erlaubt"}
        return {"allowed": False, "reason": f"Zweck '{purpose}' nicht in erlaubter Liste"}

    def get_retention(self, data_type: str) -> dict[str, Any]:
        """Aufbewahrungsfrist ermitteln."""
        policies = self.rules["storage_limitation"]["retention_policies"]
        if data_type in policies:
            return policies[data_type]
        return {
            "retention_days": self.rules["storage_limitation"]["default_retention_days"],
            "description": "Standard-Aufbewahrungsfrist"
        }


# ============================================================
# 4. AI Act Classifier
# ============================================================

class AIActClassifier:
    """Klassifiziert AI-Anwendungen nach EU AI Act."""

    def __init__(self, config: dict[str, Any]) -> None:
        self.categories = config["risk_classification"]["categories"]
        self.timeline = config["compliance_timeline"]

    def classify(self, description: str) -> dict[str, Any]:
        """Anwendung klassifizieren."""
        desc_lower = description.lower()

        for level in ["unacceptable", "high_risk", "limited_risk", "minimal_risk"]:
            cat = self.categories[level]
            for example in cat["examples"]:
                if example.lower() in desc_lower:
                    return {
                        "level": level,
                        "score": cat["level"],
                        "action": cat["action"],
                        "requirements": cat["requirements"],
                    }

        return {
            "level": "limited_risk",
            "score": 2,
            "action": "transparency_obligations",
            "requirements": self.categories["limited_risk"]["requirements"],
        }


# ============================================================
# 5. Audit Logger
# ============================================================

class AuditLogger:
    """Audit-Logger mit Hash-Kette fuer Integritaet."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self._last_hash = "genesis"

    def log(self, category: str, data: dict[str, Any]) -> dict[str, Any]:
        """Ereignis protokollieren."""
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "category": category,
            "data": data,
            "previous_hash": self._last_hash,
        }

        entry_str = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(entry_str.encode()).hexdigest()
        self._last_hash = entry["hash"]

        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Hash-Kette auf Integritaet pruefen."""
        prev_hash = "genesis"
        for entry in self.entries:
            if entry["previous_hash"] != prev_hash:
                return False
            # Hash ohne das hash-Feld berechnen
            check_entry = {k: v for k, v in entry.items() if k != "hash"}
            check_str = json.dumps(check_entry, sort_keys=True)
            expected = hashlib.sha256(check_str.encode()).hexdigest()
            if entry["hash"] != expected:
                return False
            prev_hash = entry["hash"]
        return True


# ============================================================
# 6. Demo
# ============================================================

def run_demo() -> None:
    """Demonstriert alle Compliance-Komponenten."""

    print("=" * 60)
    print("Enterprise Compliance Kit — Demo")
    print("=" * 60)

    # Komponenten initialisieren
    scanner = PIIScanner(pii_config)
    gdpr = GDPRChecker(gdpr_config)
    classifier = AIActClassifier(ai_act_config)
    audit = AuditLogger()

    # --- Test 1: PII-Erkennung ---
    print("\n--- Test 1: PII-Erkennung ---")
    test_texts = [
        "Kontaktieren Sie mich unter max.mustermann@firma.de oder +49 170 1234567",
        "Meine IBAN ist DE89 3704 0044 0532 0130 00",
        "Geburtsdatum: 15.03.1990, Steuer-ID: 12345678901",
        "Der Patient hat Blutgruppe A+ und Diagnose J06.9",
        "Keine personenbezogenen Daten in diesem Text.",
    ]

    for text in test_texts:
        findings = scanner.scan(text)
        print(f"\nText: '{text[:60]}...'")
        if findings:
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['name']} "
                      f"({f['match_count']}x) -> {f['action']}")
                audit.log("pii_detection", {
                    "pattern": f["pattern_id"],
                    "severity": f["severity"],
                })
        else:
            print("  Keine PII gefunden.")

    # --- Test 2: GDPR-Pruefung ---
    print("\n--- Test 2: GDPR-Pruefung ---")
    purposes = [
        "user_request_fulfillment",
        "profiling_without_consent",
        "security_monitoring",
        "marketing_without_consent",
    ]

    for purpose in purposes:
        result = gdpr.check_purpose(purpose)
        status = "ERLAUBT" if result["allowed"] else "BLOCKIERT"
        print(f"  {purpose}: {status} — {result['reason']}")
        audit.log("policy_check", {"purpose": purpose, "allowed": result["allowed"]})

    # --- Test 3: AI Act Klassifizierung ---
    print("\n--- Test 3: AI Act Klassifizierung ---")
    use_cases = [
        "Chatbot fuer Kundenservice",
        "Bewertungssystem fuer Bildung und Berufsausbildung",
        "Social Scoring durch Behoerden",
        "AI-gestuetzte Videospiele",
    ]

    for uc in use_cases:
        result = classifier.classify(uc)
        print(f"\n  '{uc}'")
        print(f"  Risiko: {result['level']} (Score: {result['score']}/4)")
        print(f"  Aktion: {result['action']}")
        audit.log("risk_classification", {"use_case": uc, "level": result["level"]})

    # --- Test 4: Audit-Integritaet ---
    print("\n--- Test 4: Audit-Log Integritaet ---")
    print(f"  Eintraege: {len(audit.entries)}")
    print(f"  Hash-Kette intakt: {audit.verify_chain()}")

    print("\n" + "=" * 60)
    print("Demo abgeschlossen.")
    print(f"Patterns geladen: {len(pii_config['patterns'])}")
    print(f"Audit-Eintraege: {len(audit.entries)}")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()
