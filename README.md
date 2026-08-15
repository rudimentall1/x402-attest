# x402-attest

Proof of concept, not a product.

📄 [Read the white paper](docs/whitepaper.pdf)

Cryptographically signed attestations for agent-to-agent payment
policy decisions. A payment intent is evaluated against a YAML policy
(amount cap, blocklist, rate limit) and the ALLOW/BLOCK decision is
signed with Ed25519. A third party can verify the signature using only
the public key — no access to the issuer's server, database, or logs
required. Tampering with a decision after the fact is detectable.

## Run it

pip install cryptography pyyaml
python demo.py
python demo_x402.py
python demo_eip3009.py

## Files

- `policy.yaml` — example payment policy
- `attest.py` — evaluate a payment against policy, sign the decision, verify a signature independently
- `demo.py` — 5 scenarios: allow, block-on-amount, tamper-detection, blocked recipient, rate limit
- `x402_hook.py` — parses a real base64-encoded x402 v2 `PAYMENT-REQUIRED`
  header (`accepts[]`, atomic amount, `payTo`, `extra.name` for decimals),
  evaluates each offer against policy, and signs the decision. Refuses to
  guess decimals for an asset it doesn't recognize rather than misjudging
  the amount.
- `demo_x402.py` — 3 scenarios against real `PAYMENT-REQUIRED` header
  bytes: within policy, exceeds `max_amount`, unrecognized asset (refused
  rather than guessed)
- `eip3009.py` — builds (never signs) the unsigned EIP-712 typed-data
  structure for EIP-3009 `TransferWithAuthorization`, the message a
  payer's own wallet would sign to complete a gasless x402 USDC payment.
  Domain (name/version/verifyingContract) is only filled in for
  specifically verified token+network pairs (currently USDC on Base and
  Ethereum mainnet, cross-checked against Circle's own announcement and
  BaseScan/Etherscan) - an unrecognized pair returns `None` rather than
  a guessed domain, which would produce a validly-shaped but silently
  unverifiable signature. Structurally validated against a real EIP-712
  encoder (`eth_account`) during development, including a full
  sign/recover round-trip with a throwaway test key - not shipped as a
  dependency of this module, which touches no signing library and no
  key at all.
- `demo_eip3009.py` — builds a real TransferWithAuthorization message
  for USDC on Base; shows the unrecognized-asset refusal

## What's missing before this is more than a demo

- Rate-limit state is in-memory only (dies on restart)
- `PAYMENT-REQUIRED` parsing is real (see `x402_hook.py`). The unsigned
  `PAYMENT-SIGNATURE` message is now built for verified token+network
  pairs (see `eip3009.py`) - actually producing the signature requires
  the payer's own wallet/private key, which is deliberately outside
  this project's scope, the same boundary this author holds in
  agentic-wallet-guardian-v3's transaction builder.
- No key rotation / key management story
- No currency conversion

---

## Related projects

Same author, same principle applied elsewhere:

- [agentic-wallet-guardian-v3](https://github.com/rudimentall1/agentic-wallet-guardian-v3) - a security decision layer for AI agents transacting on-chain. MIT, 131 tests.
- [agent-guardrail](https://github.com/rudimentall1/agent-guardrail) - a generic policy firewall for AI agent tool calls (not blockchain-specific). Published on PyPI, MIT, 59 tests.
- [open-agent-attestation](https://github.com/rudimentall1/open-agent-attestation) - vendor-neutral open spec (JWT+EdDSA) generalizing the signing approach used here into a format any tool can emit/verify. Draft v0.1.
