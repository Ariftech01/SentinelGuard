import re

RISK_ORDER = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3}
ACTION_PRIORITY = {'ALLOW': 0, 'MASK': 1, 'BLOCK': 2}

DETECTORS = [
    ('jwt_token', 'JWT token', '[JWT_MASKED]', 45,
     re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b')),
    ('api_key', 'API key', '[API_KEY_MASKED]', 50,
     re.compile(r'\b(?:sk|pk|rk|api)[-_](?:[A-Za-z0-9]+[-_])*[A-Za-z0-9]{12,}\b|\bAKIA[0-9A-Z]{16}\b')),
    ('secret_key', 'Secret key', '[SECRET_MASKED]', 50,
     re.compile(r'(?i)\b(?:secret|access[_-]?key|private[_-]?key|auth[_-]?token)\s*(?:is|[:=])\s*\S+')),
    ('password', 'Password', '[PASSWORD_MASKED]', 45,
     re.compile(r'(?i)\b(?:password|passwd|pwd)\s*(?:is|[:=])\s*\S+')),
    ('email', 'Email address', '[EMAIL_MASKED]', 15,
     re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')),
    ('credit_card', 'Credit card', '[CREDIT_CARD_MASKED]', 40,
     re.compile(r'(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)')),
    ('aadhaar', 'Aadhaar number', '[AADHAAR_MASKED]', 35,
     re.compile(r'(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}(?!\d)')),
    ('pan', 'PAN number', '[PAN_MASKED]', 30,
     re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')),
    ('phone', 'Phone number', '[PHONE_MASKED]', 15,
     re.compile(r'(?<!\d)(?:\+\d{1,3}[\s-]?)?(?:\(\d{3}\)[\s-]?)?\d{3}[\s-]?\d{3}[\s-]?\d{4}(?!\d)')),
]

TYPE_LABELS = {key: label for key, label, _, _, _ in DETECTORS}


def detect_and_mask(text: str):
    """Returns (masked_text, detections). Detections include raw sample for ephemeral display only."""
    masked = text
    detections = []
    for key, label, placeholder, weight, pattern in DETECTORS:
        matches = pattern.findall(masked)
        if not matches:
            continue
        first = pattern.search(masked).group(0)
        masked = pattern.sub(placeholder, masked)
        detections.append({
            'type': key, 'label': label, 'count': len(matches),
            'weight': weight, 'original': first, 'masked': placeholder,
        })
    return masked, detections


def risk_score(detections):
    score = 0
    for d in detections:
        score += d['weight'] + max(0, d['count'] - 1) * 5
    return min(100, score)


def risk_level(score: int) -> str:
    if score >= 80:
        return 'Critical'
    if score >= 50:
        return 'High'
    if score >= 25:
        return 'Medium'
    return 'Low'


def evaluate_policies(detected_types, level, policies, block_critical=True):
    """Returns (action, policy_name). Policies: [{name, when: [types]|['any'], risk, then, enabled}]"""
    if not detected_types:
        return 'ALLOW', 'Default allow'
    if block_critical and level == 'Critical':
        return 'BLOCK', 'Critical risk guard'
    best = None
    for p in policies:
        if not p.get('enabled'):
            continue
        when = p.get('when') or ['any']
        type_match = 'any' in when or any(t in when for t in detected_types)
        risk_match = RISK_ORDER.get(level, 0) >= RISK_ORDER.get(p.get('risk', 'Low'), 0)
        if type_match and risk_match:
            if best is None or ACTION_PRIORITY[p['then']] > ACTION_PRIORITY[best['then']]:
                best = p
    if best:
        return best['then'], best['name']
    return 'MASK', 'Default sensitive data masking'


DEFAULT_POLICIES = [
    {'name': 'PII standard protection', 'when': ['email', 'phone'], 'risk': 'Low', 'then': 'MASK', 'enabled': True},
    {'name': 'PCI data block', 'when': ['credit_card'], 'risk': 'Medium', 'then': 'BLOCK', 'enabled': True},
    {'name': 'Secrets critical block', 'when': ['api_key', 'secret_key', 'jwt_token', 'password'], 'risk': 'Medium', 'then': 'BLOCK', 'enabled': True},
    {'name': 'Identity document masking', 'when': ['aadhaar', 'pan'], 'risk': 'Low', 'then': 'MASK', 'enabled': True},
]
