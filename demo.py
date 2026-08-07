import json
from pathlib import Path
from attest import PaymentIntent, evaluate_payment, load_policy, generate_keypair, sign_decision, verify_attestation

KEY_DIR = Path(__file__).parent / "keys"
KEY_DIR.mkdir(exist_ok=True)
PRIVATE_KEY = KEY_DIR / "issuer_private.key"
PUBLIC_KEY = KEY_DIR / "issuer_public.key"

if not PRIVATE_KEY.exists():
    generate_keypair(PRIVATE_KEY, PUBLIC_KEY)
    print(f"[setup] generated new Ed25519 keypair in {KEY_DIR}/\n")

policy = load_policy(Path(__file__).parent / "policy.yaml")

def run_case(label, intent):
    print(f"--- {label} ---")
    decision = evaluate_payment(intent, policy)
    print(f"  verdict: {decision.verdict}  ({decision.reason})")
    attestation = sign_decision(decision, PRIVATE_KEY)
    ok = verify_attestation(attestation, PUBLIC_KEY)
    print(f"  attestation signature valid: {ok}")
    return attestation

run_case("Case 1: payment within limits", PaymentIntent(agent_id="agent-42", recipient="0xRECIPIENT1", amount=10.0))
attestation = run_case("Case 2: payment exceeds max_amount", PaymentIntent(agent_id="agent-42", recipient="0xRECIPIENT2", amount=999.0))
print("\n  Signed attestation:")
print(" ", json.dumps(attestation, indent=2))

print("\n--- Case 3: tampered attestation ---")
tampered = json.loads(json.dumps(attestation))
tampered["decision"]["verdict"] = "ALLOW"
ok = verify_attestation(tampered, PUBLIC_KEY)
print(f"  attestation signature valid after tampering: {ok}  (must be False)")

run_case("Case 4: blocked recipient", PaymentIntent(agent_id="agent-42", recipient="0xBAD0000000000000000000000000000000BAD0", amount=1.0))

print("\n--- Case 5: rate limit ---")
for i in range(policy["max_payments_per_window"] + 2):
    d = evaluate_payment(PaymentIntent(agent_id="agent-42", recipient="0xRECIPIENT3", amount=1.0), policy)
    print(f"  payment #{i+1}: {d.verdict} ({d.reason})")