"""Builds an UNSIGNED EIP-712 typed-data structure for EIP-3009
TransferWithAuthorization - the message a payer's own wallet would sign
to authorize an x402 payment, gas-free, without a prior on-chain approve.

This module does not sign anything and never touches a private key. It
builds the same kind of structured dict eth_account.sign_typed_data() or
a browser wallet's eth_signTypedData_v4 expects as input - the actual
signature is produced by whoever holds the payer's key, entirely outside
this codebase. That split mirrors agentic-wallet-guardian-v3's
tx_builder.py: build the artifact, never sign it.

Field structure and both typehash comments verified directly against the
canonical EIP-3009 spec (https://eips.ethereum.org/EIPS/eip-3009) and the
reference implementation
(https://github.com/CoinbaseStablecoin/eip-3009/blob/master/contracts/lib/EIP3009.sol),
not reproduced from memory:

    keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")

The domain (name/version/verifyingContract) is token- and
network-specific and is NOT derivable from the token address alone -
guessing it wrong produces a validly-formed but silently unverifiable
signature. Only pre-verified token+network combinations are supported;
anything else raises rather than guessing, the same rule x402_hook.py
already applies to unrecognized asset decimals.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Optional

EIP712_DOMAIN_TYPE = [
    {"name": "name", "type": "string"},
    {"name": "version", "type": "string"},
    {"name": "chainId", "type": "uint256"},
    {"name": "verifyingContract", "type": "address"},
]

TRANSFER_WITH_AUTHORIZATION_TYPE = [
    {"name": "from", "type": "address"},
    {"name": "to", "type": "address"},
    {"name": "value", "type": "uint256"},
    {"name": "validAfter", "type": "uint256"},
    {"name": "validBefore", "type": "uint256"},
    {"name": "nonce", "type": "bytes32"},
]

DEFAULT_VALID_FOR_SECONDS = 600  # a timing window, not a value-affecting
# parameter (unlike amount/recipient) - a conservative default here is
# the same category of choice as swap's deadline_seconds_from_now in
# agentic-wallet-guardian-v3, not the same category as guessing decimals.


@dataclass(frozen=True)
class EIP3009Domain:
    name: str
    version: str
    chain_id: int
    verifying_contract: str


# Cross-checked against multiple independent sources before being
# hardcoded (BaseScan + Circle's own announcement for Base; the Ethereum
# mainnet USDC address matches the one independently verified earlier in
# agentic-wallet-guardian-v3's own test suite). "version": "2" is USDC's
# own EIP-712 domain version since its v2 contract upgrade, not assumed.
KNOWN_USDC_DOMAINS = {
    ("USDC", "base"): EIP3009Domain(
        name="USD Coin", version="2", chain_id=8453,
        verifying_contract="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    ),
    ("USDC", "ethereum"): EIP3009Domain(
        name="USD Coin", version="2", chain_id=1,
        verifying_contract="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    ),
}


def resolve_domain(asset_symbol: str, network: str) -> Optional[EIP3009Domain]:
    """Returns the verified EIP-712 domain for a known asset+network pair,
    or None if this combination hasn't been specifically verified. Never
    fabricates a plausible-looking domain for an unrecognized pair."""
    return KNOWN_USDC_DOMAINS.get((asset_symbol.upper(), network.lower()))


def build_transfer_authorization(
    domain: EIP3009Domain,
    from_address: str,
    to_address: str,
    value_atomic_units: int,
    valid_for_seconds: int = DEFAULT_VALID_FOR_SECONDS,
    valid_after: int = 0,
    nonce: Optional[bytes] = None,
) -> dict:
    """Returns an unsigned EIP-712 typed-data dict for
    TransferWithAuthorization, ready to hand to a wallet's
    eth_signTypedData_v4 (or eth_account.sign_typed_data). This function
    signs nothing - it has no access to, and never asks for, a private
    key.

    `nonce`: EIP-3009's nonce is any client-chosen 32 bytes (not a
    sequential counter - contracts track a used/unused mapping keyed by
    this value, so any sufficiently random value works and colliding
    with a past nonce for the same `from` simply fails the transfer,
    it doesn't misfire against the wrong prior authorization). If not
    supplied, one is generated with `secrets.token_bytes` - this is
    ordinary cryptographic randomness, not a signing operation.
    """
    if value_atomic_units <= 0:
        raise ValueError("value_atomic_units must be positive - refusing to build a zero/negative-value authorization")

    resolved_nonce = nonce if nonce is not None else secrets.token_bytes(32)
    valid_before = int(time.time()) + valid_for_seconds

    return {
        "types": {
            "EIP712Domain": EIP712_DOMAIN_TYPE,
            "TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION_TYPE,
        },
        "domain": {
            "name": domain.name,
            "version": domain.version,
            "chainId": domain.chain_id,
            "verifyingContract": domain.verifying_contract,
        },
        "primaryType": "TransferWithAuthorization",
        "message": {
            "from": from_address,
            "to": to_address,
            "value": value_atomic_units,
            "validAfter": valid_after,
            "validBefore": valid_before,
            "nonce": "0x" + resolved_nonce.hex(),
        },
    }
