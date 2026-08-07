from __future__ import annotations
import json, time, hashlib
from dataclasses import dataclass, field
from pathlib import Path
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

def load_policy(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["payment_limits"]

_payment_history: dict[str, list[float]] = {}

def _record_and_count(recipient, window_seconds):
    now = time.time()
    history = _payment_history.setdefault(recipient, [])
    history[:] = [t for t in history if now - t < window_seconds]
    history.append(now)
    return len(history)

@dataclass
class PaymentIntent:
    agent_id: str
    recipient: str
    amount: float
    currency: str = "USD"

@dataclass
class Decision:
    verdict: str
    reason: str
    intent: PaymentIntent
    timestamp: float = field(default_factory=time.time)

    def to_signable_bytes(self) -> bytes:
        payload = {
            "verdict": self.verdict, "reason": self.reason,
            "agent_id": self.intent.agent_id, "recipient": self.intent.recipient,
            "amount": self.intent.amount, "currency": self.intent.currency,
            "timestamp": self.timestamp,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

def evaluate_payment(intent, policy):
    if intent.recipient in policy.get("blocked_recipients", []):
        return Decision("BLOCK", f"recipient {intent.recipient} is on the block list", intent)
    allowed = policy.get("allowed_recipients") or []
    if allowed and intent.recipient not in allowed:
        return Decision("BLOCK", f"recipient {intent.recipient} not in allowlist", intent)
    if intent.amount > policy["max_amount"]:
        return Decision("BLOCK", f"amount {intent.amount} exceeds max_amount {policy['max_amount']}", intent)
    count = _record_and_count(intent.recipient, policy["window_seconds"])
    if count > policy["max_payments_per_window"]:
        return Decision("BLOCK", f"rate limit exceeded: {count} payments to {intent.recipient} in last {policy['window_seconds']}s (max {policy['max_payments_per_window']})", intent)
    return Decision("ALLOW", "within policy", intent)

def generate_keypair(private_key_path, public_key_path):
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    Path(private_key_path).write_bytes(private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    Path(public_key_path).write_bytes(public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))

def sign_decision(decision, private_key_path):
    key_bytes = Path(private_key_path).read_bytes()
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    message = decision.to_signable_bytes()
    signature = private_key.sign(message)
    return {
        "decision": json.loads(message.decode()),
        "signature": signature.hex(),
        "message_sha256": hashlib.sha256(message).hexdigest(),
    }

def verify_attestation(attestation, public_key_path):
    key_bytes = Path(public_key_path).read_bytes()
    public_key = Ed25519PublicKey.from_public_bytes(key_bytes)
    message = json.dumps(attestation["decision"], sort_keys=True, separators=(",", ":")).encode()
    signature = bytes.fromhex(attestation["signature"])
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False