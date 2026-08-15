"""Live demo: build (never sign) an EIP-3009 TransferWithAuthorization
message for a hypothetical x402 USDC-on-Base payment."""
import json
from eip3009 import build_transfer_authorization, resolve_domain

print("--- Scenario 1: known asset (USDC on Base) - message built ---")
domain = resolve_domain("USDC", "base")
msg = build_transfer_authorization(
    domain=domain,
    from_address="0x1111111111111111111111111111111111111111",
    to_address="0x2222222222222222222222222222222222222222",
    value_atomic_units=1_000_000,  # 1.00 USDC (6 decimals)
)
print(json.dumps(msg, indent=2))
print()
print("-> hand this dict to the payer's own wallet (eth_signTypedData_v4")
print("   / eth_account.sign_typed_data). This module never sees a private key.")
print()

print("--- Scenario 2: unrecognized asset - refuses to guess the domain ---")
unknown = resolve_domain("DAI", "base")
print(f"resolve_domain('DAI', 'base') -> {unknown}")
print("-> caller must supply a verified EIP3009Domain explicitly; nothing is fabricated.")
