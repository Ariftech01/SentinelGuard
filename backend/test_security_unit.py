"""Local unit checks for security.py (no external deps)."""
from security import detect_and_mask, risk_score, risk_level, evaluate_policies, DEFAULT_POLICIES

failures = []

def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(name)
        print(f"  FAIL  {name}  {detail}")

# 1. Each detector fires on a representative sample
samples = {
    'email': 'reach me at jane.doe@acme-corp.com please',
    'phone': 'call 555-123-4567 tomorrow',
    'credit_card': 'my card 4111 1111 1111 1111 expires soon',
    'aadhaar': 'aadhaar 2345 6789 0123 here',
    'pan': 'PAN is ABCDE1234F ok',
    'password': 'password: hunter2',
    'api_key': 'use sk-abcdefghijklmnop1234',
    'jwt_token': 'token eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c',
    'secret_key': 'secret_key = abcdef123456',
}
for key, text in samples.items():
    masked, dets = detect_and_mask(text)
    found = any(d['type'] == key for d in dets)
    leaked = found and dets[[d['type'] for d in dets].index(key)]['original'] in masked
    check(f"detects {key}", found, f"got {[d['type'] for d in dets]}")
    check(f"masks {key} (no raw leak)", found and not leaked, f"masked={masked!r}")

# 2. Risk scoring monotonicity and bounds
_, d_none = detect_and_mask("hello how are you")
_, d_email = detect_and_mask(samples['email'])
_, d_card = detect_and_mask(samples['credit_card'])
_, d_jwt = detect_and_mask(samples['jwt_token'])
check("clean text -> score 0", risk_score(d_none) == 0)
check("card risk > email risk", risk_score(d_card) > risk_score(d_email))
check("score capped at 100", risk_score(d_none + d_email + d_card + d_jwt) <= 100)
check("risk_level boundaries", risk_level(0) == 'Low' and risk_level(24) == 'Low'
      and risk_level(25) == 'Medium' and risk_level(49) == 'Medium'
      and risk_level(50) == 'High' and risk_level(79) == 'High'
      and risk_level(80) == 'Critical' and risk_level(100) == 'Critical')

# 3. Policy engine
check("no detections -> ALLOW", evaluate_policies([], 'Low', DEFAULT_POLICIES)[0] == 'ALLOW')
check("critical -> BLOCK guard", evaluate_policies(['email'], 'Critical', DEFAULT_POLICIES)[0] == 'BLOCK')
check("credit_card -> PCI BLOCK", evaluate_policies(['credit_card'], 'Medium', DEFAULT_POLICIES)[0] == 'BLOCK')
check("email -> PII MASK", evaluate_policies(['email'], 'Low', DEFAULT_POLICIES)[0] == 'MASK')
check("api_key -> secrets BLOCK", evaluate_policies(['api_key'], 'High', DEFAULT_POLICIES)[0] == 'BLOCK')
check("aadhaar -> identity MASK", evaluate_policies(['aadhaar'], 'Medium', DEFAULT_POLICIES)[0] == 'MASK')
disabled = [dict(p, enabled=False) for p in DEFAULT_POLICIES]
check("all disabled -> default MASK", evaluate_policies(['email'], 'Low', disabled)[0] == 'MASK')
check("block_critical=False honors policy", evaluate_policies(['email'], 'Critical', DEFAULT_POLICIES, block_critical=False)[0] == 'MASK')

print()
if failures:
    print(f"{len(failures)} FAILURES: {failures}")
    raise SystemExit(1)
print("ALL SECURITY UNIT CHECKS PASSED")
