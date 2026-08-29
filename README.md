# SentinelGuard

## AI Runtime Security & Governance Gateway

SentinelGuard is an AI security and governance gateway designed to reduce the risk of sensitive information exposure in AI systems.

It sits between users/applications and AI models to detect sensitive information, assess risk, enforce security policies, protect AI inputs and outputs, and maintain an auditable record of security events.

---

## Problem Statement

### AI Safety & Governance Layer

Organizations need mechanisms to prevent sensitive data exposure in AI systems.

The challenge is to identify personally identifiable information and other sensitive data, protect it before it reaches an AI model, and provide organizations with visibility into AI security decisions.

---

## Our Solution

SentinelGuard provides a runtime security layer for AI interactions.

Every request passes through a security pipeline:

**Detect → Classify → Assess Risk → Enforce Policy → Protect → Audit**

Depending on the detected information and configured policy, a request can be:

- **ALLOW** — Safe request continues to the AI model.
- **MASK** — Sensitive information is replaced before processing.
- **BLOCK** — High-risk or prohibited requests are prevented.

SentinelGuard also supports output inspection to identify possible sensitive-information leakage in AI-generated responses.

---

## Key Capabilities

- PII and sensitive-data detection
- Email, phone, Aadhaar and PAN detection
- Credit-card detection
- API-key, secret and password detection
- JWT detection
- Automatic sensitive-data masking
- Risk scoring from 0–100
- Risk classification
- Configurable security policies
- ALLOW / MASK / BLOCK enforcement
- AI input security
- AI output inspection
- Prompt-threat detection
- Real-time security events
- Audit logging
- Model usage analytics
- Security dashboard
- Multi-provider AI support

---

## Architecture

```text
User / Application
        |
        v
SentinelGuard Gateway
        |
        v
Sensitive Data Detection
        |
        v
Risk Assessment
        |
        v
Policy Engine
        |
   +----+----+ 
   |    |    |
 ALLOW MASK BLOCK
   |    |
   +----+
        |
        v
      AI Model
        |
        v
Output Security Scan
        |
        v
   Safe Response
        |
        v
   Audit Logging