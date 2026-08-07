\# x402-attest



Proof of concept, not a product.



Cryptographically signed attestations for agent-to-agent payment

policy decisions. A payment intent is evaluated against a YAML policy

(amount cap, blocklist, rate limit) and the ALLOW/BLOCK decision is

signed with Ed25519. A third party can verify the signature using only

the public key — no access to the issuer's server, database, or logs

required. Tampering with a decision after the fact is detectable.



\## Run it



pip install cryptography pyyaml

python demo.py



\## Files



\- `policy.yaml` — example payment policy

\- `attest.py` — evaluate a payment against policy, sign the decision, verify a signature independently

\- `demo.py` — 5 scenarios: allow, block-on-amount, tamper-detection, blocked recipient, rate limit



\## What's missing before this is more than a demo



\- Rate-limit state is in-memory only (dies on restart)

\- No real x402 (or any other payment rail) integration yet — this evaluates payment \*intents\* constructed in Python, not real on-the-wire requests

\- No key rotation / key management story

\- No currency conversion

