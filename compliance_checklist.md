# AI Agent Compliance Checklist — 50 Points

## A. Data Protection (GDPR) — 15 Points

### A.1 Legal Basis
- [ ] **A1.1** Lawful basis for data processing documented (Art. 6 GDPR)
- [ ] **A1.2** Special category data processing justified (Art. 9 GDPR)
- [ ] **A1.3** Consent mechanism implemented and tested
- [ ] **A1.4** Consent withdrawal mechanism available
- [ ] **A1.5** Privacy notice provided to data subjects

### A.2 Data Handling
- [ ] **A2.1** Data minimization enforced — only necessary data collected
- [ ] **A2.2** Purpose limitation enforced — data used only for stated purpose
- [ ] **A2.3** Storage limitation — retention periods defined and automated
- [ ] **A2.4** Data accuracy — mechanisms to correct inaccurate data
- [ ] **A2.5** Encryption at rest implemented (AES-256 or equivalent)

### A.3 Data Subject Rights
- [ ] **A3.1** Right to access — users can request their data
- [ ] **A3.2** Right to erasure — data deletion on request
- [ ] **A3.3** Right to portability — data export in machine-readable format
- [ ] **A3.4** Right to object — processing stops on objection
- [ ] **A3.5** Right to restriction — processing can be limited

---

## B. EU AI Act — 12 Points

### B.1 Risk Classification
- [ ] **B1.1** AI system risk level classified (unacceptable/high/limited/minimal)
- [ ] **B1.2** Classification documented with rationale
- [ ] **B1.3** Requirements for risk level identified and listed

### B.2 Transparency
- [ ] **B2.1** Users informed they are interacting with AI
- [ ] **B2.2** AI-generated content labeled as such
- [ ] **B2.3** Capabilities and limitations documented

### B.3 Human Oversight
- [ ] **B3.1** Human-in-the-loop for high-risk decisions
- [ ] **B3.2** Kill switch implemented and tested
- [ ] **B3.3** Escalation path defined (agent > reviewer > officer)

### B.4 Technical Requirements
- [ ] **B4.1** Risk management system documented
- [ ] **B4.2** Technical documentation complete
- [ ] **B4.3** Logging/monitoring system active

---

## C. PII Protection — 8 Points

### C.1 Detection
- [ ] **C1.1** PII detection patterns loaded and tested
- [ ] **C1.2** All relevant PII categories covered for your jurisdiction
- [ ] **C1.3** Context-aware detection enabled (reduces false positives)
- [ ] **C1.4** Special category data detection active (health, religion, etc.)

### C.2 Response
- [ ] **C2.1** Critical PII automatically blocked
- [ ] **C2.2** High-severity PII redacted before processing
- [ ] **C2.3** PII detections logged (without the actual PII)
- [ ] **C2.4** Alert triggers configured for critical detections

---

## D. Audit Trail — 8 Points

### D.1 Logging
- [ ] **D1.1** All tool invocations logged
- [ ] **D1.2** Policy violations logged with details
- [ ] **D1.3** Data access events logged
- [ ] **D1.4** Authentication events logged

### D.2 Integrity
- [ ] **D2.1** Log integrity protected (hash chain or similar)
- [ ] **D2.2** Logs encrypted at rest
- [ ] **D2.3** Access to logs restricted to authorized roles
- [ ] **D2.4** Log retention periods configured and automated

---

## E. Organizational Measures — 7 Points

### E.1 Governance
- [ ] **E1.1** Data Protection Officer (DPO) appointed (if required)
- [ ] **E1.2** Data Processing Impact Assessment (DPIA) completed
- [ ] **E1.3** Data Processing Agreements (DPA) with all third parties

### E.2 Incident Response
- [ ] **E2.1** Breach notification procedure documented (72h to authority)
- [ ] **E2.2** Incident response team identified
- [ ] **E2.3** Breach notification templates prepared

### E.3 Training
- [ ] **E3.1** Staff trained on AI compliance requirements

---

## Scoring

| Score | Rating | Action |
|-------|--------|--------|
| 45-50 | Excellent | Ready for production |
| 35-44 | Good | Minor gaps, address before launch |
| 25-34 | Fair | Significant gaps, remediation needed |
| 15-24 | Poor | Major compliance risks |
| 0-14  | Critical | Do not deploy — fundamental gaps |

## Notes

- This checklist covers EU requirements (GDPR + AI Act)
- Additional requirements may apply for specific sectors (finance, health, etc.)
- Review and update quarterly or when regulations change
- This is a technical checklist, not legal advice
