# Axom unified provably-fair verifier

This repository is the public, independently auditable implementation of
Axom Casino's unified provably-fair protocol. Verification runs locally: the
JavaScript implementation uses the browser's Web Crypto API and never sends
the revealed server seed to a verification backend.

Telegram-native Dice Rush, Seven Up, and Triple Dice consume outcomes supplied
by Telegram and are intentionally outside the Axom-generated protocol.

## Published components

- [`provably_fair/specification.md`](provably_fair/specification.md) — normative
  byte encoding, HMAC construction, unbiased number generation, versioning,
  game mappings, and payout rules.
- [`provably_fair_webapp/verifier.js`](provably_fair_webapp/verifier.js) —
  dependency-free browser verifier.
- [`provably_fair_webapp/index.html`](provably_fair_webapp/index.html) — manual
  verification interface. Axom's compact `/v/<proof-id>` pages embed the
  immutable public record in the initial document, so Cloudflare or WebView API
  challenges cannot interrupt local verification. Mines and Tower proofs also
  include visual seed-derived board replays.
- [`provably_fair/`](provably_fair/) — Python reference implementation.
- [`tests/`](tests/) — fixed protocol vectors, deterministic mapping tests, and
  JavaScript/Python parity checks.

## Protocol summary

```text
server_seed_hash = SHA256(server_seed)

block[cursor] = HMAC-SHA256(
  key = UTF8(server_seed),
  message = UTF8(
    "pf-v1\ngame=<game>\nclient_seed=<seed>\nnonce=<nonce>\ncursor=<cursor>"
  )
)
```

Consecutive 32-byte blocks form the random byte stream. Bounded integers use
rejection sampling; floating-point values use 52 random bits. Game mappings
consume that stream sequentially and are locked by explicit algorithm version.
Current proof IDs bind the game name to 128 bits of independent random entropy,
for example `pf_mines_<32 hex characters>`; gameplay nonces are never reused as
public proof identifiers.

## Run the tests

Python 3.10+ is sufficient for the reference tests. Node.js is optional and is
used for browser/Python parity checks.

```bash
python3 -m unittest tests.test_provably_fair tests.test_browser_verifier
```

## Use the manual verifier

Serve the repository from its root and open the verifier page:

```bash
python3 -m http.server 8000
```

Then visit `http://localhost:8000/provably_fair_webapp/`. Paste a complete
verification record or enter its fields manually. The final result separately
reports commitment, random stream, mapped outcome, and payout checks.

## Versioning policy

Published algorithm versions are immutable. Any mapping or protocol change is
released under a new version, while historical versions remain available so
old bets can always be replayed.
