import base64, json
from pathlib import Path
from attest import load_policy, generate_keypair
from x402_hook import evaluate_payment_required_header

KEY_DIR = Path(__file__).parent / "keys"
KEY_DIR.mkdir(exist_ok=True)
PRIVATE_KEY = KEY_DIR / "issuer_private.key"
PUBLIC_KEY = KEY_DIR / "issuer_public.key"

if not PRIVATE_KEY.exists():
    generate_keypair(PRIVATE_KEY, PUBLIC_KEY)

policy = load_policy(Path(__file__).parent / "policy.yaml")

def build_header(amount_atomic, pay_to):
    payload = {
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": {"url": "https://api.example.com/premium-data", "description": "Access to premium market data", "mimeType": "application/json"},
        "accepts": [{
            "scheme": "exact", "network": "eip155:84532",
            "amount": amount_atomic,
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": pay_to, "maxTimeoutSeconds": 60,
            "extra": {"name": "usdc", "version": "2"},
        }],
        "extensions": {},
    }
    return base64.b64encode(json.dumps(payload).encode()).decode()

print("--- Scenario 1: small payment (0.01 USDC), within policy ---")
header = build_header("10000", "0xRECIPIENT_SMALL")
for r in evaluate_payment_required_header(header, "agent-42", policy, PRIVATE_KEY):
    print(f"  offer: {r.decision.intent.amount} {r.decision.intent.currency} to {r.decision.intent.recipient}")
    print(f"  verdict: {r.decision.verdict} ({r.decision.reason})")

print("\n--- Scenario 2: large payment (100 USDC), exceeds max_amount in policy.yaml ---")
header = build_header("100000000", "0xRECIPIENT_LARGE")
for r in evaluate_payment_required_header(header, "agent-42", policy, PRIVATE_KEY):
    print(f"  offer: {r.decision.intent.amount} {r.decision.intent.currency} to {r.decision.intent.recipient}")
    print(f"  verdict: {r.decision.verdict} ({r.decision.reason})")
    print(f"  -> a real x402 client would STOP HERE and never construct a PAYMENT-SIGNATURE")

print("\n--- Scenario 3: unrecognized asset — refuses to guess rather than misjudge ---")
payload = {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:8453", "amount": "5000000000000000000", "asset": "0xSomeUnknownTokenContract", "payTo": "0xRECIPIENT_UNKNOWN_TOKEN", "extra": {"name": "SomeRandomToken"}}]}
header = base64.b64encode(json.dumps(payload).encode()).decode()
for r in evaluate_payment_required_header(header, "agent-42", policy, PRIVATE_KEY):
    print(f"  verdict: {r.decision.verdict} ({r.decision.reason})")