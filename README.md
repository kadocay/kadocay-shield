# Kadocay Shield — Wallet Security Scanner Agent

**Agent Games (zkVerify) — Wildcard track entry.**

A public agent that screens a wallet for drain / scam risk **before** the owner signs
anything. Built after a real drain: in October 2026 a compromised wallet app moved
2,787 USDG out of a fresh wallet in one signed `transfer()`. The checks here are the
same ones that catch that pattern — run on-chain, live, for any BSC wallet.

## The problem

Most wallet drains do not look like an attack until after the signature. The two
things that matter before signing are:

1. **Has the wallet itself been turned into a smart contract?** An EIP-7702
   delegation (`0xef0100...` code on an EOA) hands execution to a contract.
   If the owner did not delegate it, the wallet is compromised.
2. **Can the wallet even act?** A wallet with almost no BNB cannot pay gas to
   rescue funds — a real blocker when a drain is in progress.

Kadocay Shield answers both in one call, plus an activity baseline, using only
public BSC RPC — no keys, no signing, no fund movement. Read-only by design.

## Who it helps

- **Agent-wallet owners** (Binance Agentic Wallet, `.ai` Agent IDs) who mint,
  list, and claim every day and need a pre-flight check before any signature.
- **Anyone who was drained once** and wants a cheap "is this wallet still safe?"
  check before trusting it again.

## How it works

`POST /scan` with `{ "address": "0x...", "chainId": 56 }`. The agent calls BSC
JSON-RPC (with fallback across three public endpoints) and returns a risk report:

```json
{
  "agent": "kadocay-shield",
  "version": "1.0.0",
  "chainId": 56,
  "address": "0xB9c1...C5ba",
  "riskLevel": "LOW",
  "highFindings": 0,
  "summary": "Low risk: no drain indicator, but the wallet is low on gas. Top up BNB before acting.",
  "findings": [
    { "check": "eip7702_delegation", "pass": true, "severity": "info",
      "detail": "No EIP-7702 delegation code on this wallet." },
    { "check": "native_balance", "pass": true, "severity": "low",
      "detail": "BNB balance 0.000668 BNB — below gas comfort; top up before any rescue." },
    { "check": "tx_count", "pass": true, "severity": "info",
      "detail": "Transaction count 952." }
  ]
}
```

Checks in v1 (all live, on-chain, BSC):

| Check | What it does |
|---|---|
| `eip7702_delegation` | `eth_getCode` — flags `0xef0100` delegation code (**high** if present). |
| `native_balance` | `eth_getBalance` — flags < 0.001 BNB as gas risk (**low**). |
| `tx_count` | `eth_getTransactionCount` — activity baseline (**info**). |

`riskLevel` is `HIGH` if any finding is high, `LOW` if only a low-severity
finding, otherwise `CLEAR`.

## Endpoints

| Route | Method | Description |
|---|---|---|
| `/` | GET | Agent info + usage. |
| `/health` | GET | `{ ok: true }`. |
| `/scan` | POST | `{ address, chainId? }` → risk report JSON. Only chainId 56 in v1. |

## Run it

Node.js 18+ required. No dependencies — stdlib only.

```bash
node server.js            # listens on 127.0.0.1:8080 (set PORT to change)
```

Test:

```bash
curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{"address":"0xB9c1287155F3Fc14736f074DA9f796092Ee7C5ba","chainId":56}'
```

## What it can and cannot do

- **Can:** tell you if a BSC wallet carries EIP-7702 delegation code, whether it
  holds enough BNB to act, and its activity baseline — before you sign.
- **Cannot:** see off-chain compromises (a leaked seed, a malicious app), read
  approvals history, or undo a transaction. It is a pre-flight check, not a
  recovery tool. If `riskLevel` is `HIGH`, do not sign — move funds from a
  clean wallet instead.

## Submission

- Track: Agent Games — Wildcard.
- Handle: `kadocay`.
- zkVerify: not used in v1 (optional for this track). A checkable claim for a
  future version would be "this scan result was computed from RPC responses at
  block N" via zkTLS; v1 reports the raw on-chain values instead.
