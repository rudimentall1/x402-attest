from __future__ import annotations
import base64, json
from dataclasses import dataclass
from attest import PaymentIntent, evaluate_payment, sign_decision, Decision

_KNOWN_DECIMALS = {"usdc": 6}

class UnknownAssetError(Exception):
    pass

def parse_payment_required(header_value: str) -> dict:
    decoded = base64.b64decode(header_value)
    return json.loads(decoded)

def _decimals_for(requirement: dict) -> int:
    extra = requirement.get("extra") or {}
    name = (extra.get("name") or "").strip().lower()
    if name in _KNOWN_DECIMALS:
        return _KNOWN_DECIMALS[name]
    raise UnknownAssetError(f"no known decimals for asset {requirement.get('asset')} (extra.name={extra.get('name')!r}) — refusing to guess")

def intent_from_requirement(requirement: dict, agent_id: str) -> PaymentIntent:
    atomic_amount = int(requirement["amount"])
    decimals = _decimals_for(requirement)
    human_amount = atomic_amount / (10 ** decimals)
    return PaymentIntent(
        agent_id=agent_id,
        recipient=requirement["payTo"],
        amount=human_amount,
        currency=(requirement.get("extra") or {}).get("name", "UNKNOWN"),
    )

@dataclass
class EvaluatedRequirement:
    requirement: dict
    decision: Decision
    attestation: dict

def evaluate_payment_required_header(header_value: str, agent_id: str, policy: dict, private_key_path: str):
    payload = parse_payment_required(header_value)
    results = []
    for requirement in payload.get("accepts", []):
        try:
            intent = intent_from_requirement(requirement, agent_id)
        except UnknownAssetError as e:
            decision = Decision("BLOCK", f"cannot evaluate: {e}", PaymentIntent(agent_id=agent_id, recipient=requirement.get("payTo", "?"), amount=0.0))
        else:
            decision = evaluate_payment(intent, policy)
        attestation = sign_decision(decision, private_key_path)
        results.append(EvaluatedRequirement(requirement, decision, attestation))
    return results