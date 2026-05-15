# Kalvex Smart Contract Audit Action

AI-powered Solidity vulnerability scanner for GitHub Actions. Audits every smart contract on every PR — catches reentrancy, selfdestruct, oracle manipulation, and 66 more vulnerabilities before they reach mainnet.

## What it does

- Scans all `.sol` files in your repo on every PR
- Posts a detailed finding report as a PR comment
- Fails the build if CRITICAL vulnerabilities are found
- Maps every finding to real DeFi exploits (Euler $197M, The DAO $60M, Ronin $625M)
- Gives a clear verdict: ✅ SAFE TO DEPLOY / ⚠️ HIGH RISK / 🚨 DO NOT DEPLOY

## Quick Start

```yaml
# .github/workflows/kalvex-audit.yml
name: Kalvex Smart Contract Audit

on:
  pull_request:
    paths:
      - '**.sol'

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Kalvex Audit
        uses: msandeep38/kalvex-action@v1
        with:
          api-key: ${{ secrets.KALVEX_API_KEY }}
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Setup

1. Get a free API key at [kalvex.io/get-api-key](https://kalvex.io/get-api-key)
2. Add it to your repo: **Settings → Secrets → Actions → New secret**
   - Name: `KALVEX_API_KEY`
   - Value: `kv_fre_your_key_here`
3. Add the workflow file above to `.github/workflows/`
4. Open a PR that touches any `.sol` file — Kalvex runs automatically

## Inputs

| Input | Description | Default |
|---|---|---|
| `api-key` | Your Kalvex API key (required) | — |
| `contracts-path` | Path to audit (file or directory) | `contracts/` |
| `fail-on` | Fail build on findings at this severity or above | `CRITICAL` |
| `comment-on-pr` | Post results as PR comment | `true` |
| `base-url` | API base URL (for self-hosted) | `https://kalvex.io` |

## Outputs

| Output | Description |
|---|---|
| `verdict` | `DO_NOT_DEPLOY` / `HIGH_RISK` / `REVIEW_REQUIRED` / `SAFE_TO_DEPLOY` |
| `findings-count` | Total findings |
| `critical-count` | Critical findings count |
| `high-count` | High findings count |

## Advanced Usage

```yaml
- name: Kalvex Audit
  id: audit
  uses: msandeep38/kalvex-action@v1
  with:
    api-key: ${{ secrets.KALVEX_API_KEY }}
    contracts-path: 'src/contracts/'
    fail-on: 'HIGH'           # fail on HIGH and above
    comment-on-pr: 'true'
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

- name: Print verdict
  run: echo "Verdict: ${{ steps.audit.outputs.verdict }}"
```

## Example PR Comment

```
## 🛡️ Kalvex Smart Contract Audit

### 🚨 `contracts/Vault.sol`
**Verdict:** DO NOT DEPLOY
**3 critical vulnerabilities found. Matches known exploit patterns.**

🔴 CRITICAL — 3 findings

#### Reentrancy: State Updated After External Call
- CVSS: 9.8
- CWE: CWE-841
- ⚡ Real exploit: This pattern drained $60M from The DAO (2016) and
  $130M from Cream Finance (2021). An attacker can drain 100% of contract ETH.
...

---
Total findings: 8 | 🔴 Critical: 3 | 🟠 High: 2

> 🔑 Unlock PoC exploit generation — upgrade to Kalvex Pro ($49/mo)
```

## Pricing

| Tier | Audits/Day | Price |
|---|---|---|
| Free | 10 | $0 |
| Pro | 100 | $49/mo |
| Enterprise | Unlimited | Custom |

Get your key at [kalvex.io/get-api-key](https://kalvex.io/get-api-key)

## Detectors

69 Solidity vulnerability detectors covering:

**CRITICAL:** Reentrancy, Unprotected selfdestruct, tx.origin auth, Arbitrary delegatecall, Storage collision, Read-only reentrancy

**HIGH:** Signature replay, Unchecked calls, Weak randomness, Missing slippage, Chainlink staleness, Return bomb, Arbitrary ETH send, Encode-packed collision

**MEDIUM:** Centralization risk, Front-running, Enum conversion, Cyclomatic complexity, ERC20/ERC721 interface violations

**LOW/INFO:** Floating pragma, Dead code, Cache array length, Boolean equality, Too many digits

---

Built by [Kalvex](https://kalvex.io) — AI-powered Web2 + Web3 Security
 