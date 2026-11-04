# ReplayCourt MCP server: the recorded testnet run

An MCP client ([`demo/client-demo.ts`](demo/client-demo.ts), the official MCP TypeScript SDK client
over stdio) drives the server exactly as an AI agent's host would: it sees tool names, schemas and
results only. It has no key, no policy file and no chain access of its own. It is a script, not a
language model. In this run it played the agent and earned a real testnet bounty on the showcase contract, from its vault, and was refused everything outside
its policy. Full output: [`../demo/logs/mcp-client-demo.txt`](../demo/logs/mcp-client-demo.txt).

| | |
|---|---|
| contract | `contract.replaycourt.testnet`, `version()` = `2.0.0` ([`../demo/SHOWCASE.md`](../demo/SHOWCASE.md)) |
| hunter account | `agent.replaycourt.testnet` |
| program | 0, "Ethereum DeFi replay bounty" (bond 0.05 NEAR for a new hunter) |
| server | `src/server.ts` in vault mode (`REPLAYCOURT_MCP_MODE=vault`), signing with the function-call key `ed25519:37ugn3ZBbkH7oU6wp1JKYDi6Y7dS9fBjGWDvZNsnAmPD`: receiver = the contract, methods `submit_report_from_vault`, `finalize`, `withdraw_pending`, allowance 0.5 NEAR |
| on-chain vault policy | max bond 0.1 NEAR per report, max 0.3 NEAR per 24 h, programs `[0]` |
| local policy | [`demo/policy.vault-showcase.json`](demo/policy.vault-showcase.json): programs `[0]`, max bond 0.1, max 0.3 per report, 0.3 per 24 h, 1 lifetime, keep 0.2 NEAR, 4 reports/h |

## Setup (agent CLI, the agent account's full-access key)

```bash
cd agent
export REPLAYCOURT_CONFIG=../.secrets/showcase-v2.json
node src/cli.ts vault-deposit --amount 0.5 --as agent
node src/cli.ts vault-set-policy --max-bond 0.1 --max-per-day 0.3 --programs 0 --as agent
node src/cli.ts setup-hunter-key --as agent        # function-call key, allowance 0.5 NEAR
```

| step | transaction | result |
|---|---|---|
| `vault-deposit 0.5` | [`8XjFmKba…`](https://testnet.nearblocks.io/txns/8XjFmKbaszoXdDMExdRYy5NaTCazc7Xzr9iagqtEagTs) | vault balance 0.49596 NEAR (0.00404 went to the vault's storage) |
| `vault-set-policy 0.1 / 0.3 / [0]` | [`FRwKEG1E…`](https://testnet.nearblocks.io/txns/FRwKEG1EyPFX97xrAw8WUT24kGfeXvjn3MNsgFTYeocw) | 1 yoctoNEAR attached, which only a full-access key can do |
| `setup-hunter-key` | [`6eyXmmy3…`](https://testnet.nearblocks.io/txns/6eyXmmy3ho7nJiQFaBv3YnJME4Fjz7uP4uvMPNaA3E5W) | key stored in `.secrets/showcase-v2/`, where the server finds it |

## Run

```bash
cd mcp
node demo/client-demo.ts --config ../.secrets/showcase-v2.json --hunter agent \
  --policy demo/policy.vault-showcase.json --report 02_seneca_chamber.md --exact \
  --title "Seneca Chamber.performOperations() executes arbitrary calls - theft of approved tokens" --verify-seal
```

At startup the server read the key's permission on-chain and refused nothing: it is a function-call
key with exactly the three methods.

| # | the agent calls | outcome | transaction |
|---|---|---|---|
| 1, 2 | list tools, `list_programs` | nine tools. Program 0 has `allowed_by_policy` and `allowed_by_vault`, program 1 has neither. Program names arrive wrapped as `<untrusted-…>` | - |
| 3 | `required_bond(0)` | 0.05 NEAR; policy and vault both allow it; 0.3 NEAR left in the window | - |
| 4 | `submit_report(0, 02_seneca_chamber.md)` | **submitted, #6**, with `submit_report_from_vault`: `attached` 0, charged on-chain bond 0.05 + storage 0.08461 = 0.13461 NEAR from the vault, `funded_by_vault: true` | [`98c5qCNu…`](https://testnet.nearblocks.io/txns/98c5qCNuzrKM7F3d2o4TXdNSTsYW7wmj6W3aiK1n5XFy) |
| 5 | `submit_report(1, …)`: **a program outside the allow-list** | **refused**, `refused_by: "vault_policy"`, rule `program_not_allowed`, `retry_after: null`, `signed: false`; `also_refused_by` the local policy (`program_not_allowed`) | none, no gas |
| 6 | `submit_report(0, a long report)`: **over the cap** (7,562 bytes, with 0.16216 NEAR left in the window) | **refused**, `refused_by: "vault_policy"`, rule `daily_spend_cap`: bond 0.05 + storage estimate 0.1628 on top of 0.13461 spent exceeds 0.3 NEAR; `retry_after` 2026-11-03T20:50:46.662Z, when the window resets; `also_refused_by` the local policy (`daily_deposit_cap`) | none, no gas |
| 7 | `submit_report(report_path = the function-call key file)`: a prompt-injected exfiltration | **refused**, `refused_by: "path_allow_list"`, rule `path_not_allowed` | none |
| 8 | **`budget_status`** | vault mode; key permission `FunctionCall` and its allowance; vault balance 0.36135 NEAR, `spent_in_window` 0.13461, 0.16539 left, reset time; the local caps and what is left of them; ledger integrity ok | - |
| 9 | `get_submission(6)` | `pending`, `funded_by_vault: true` | - |
| 10 | out-of-band, as the verifier (`--verify-seal`) | the sealed blob opens with the verifier key, the v2 commitment matches for the agent, the plaintext equals the submitted file. The same blob claimed by `hunter2` is rejected (commitment mismatch) | - |

## What happened to the report

The verifier worker judged #6 and the owner disputed it. The agent's bounty then arrived without
the agent doing anything more:

| step | transaction | result |
|---|---|---|
| `post_verdict` (worker, function-call key) | [`CZkNUyqE…`](https://testnet.nearblocks.io/txns/CZkNUyqELPKx3zjfcPmPc6M2hTQU3MJ3envRxgSfupEf) | valid, critical, fork block 19,325,936 |
| `dispute` (owner, 0.1 NEAR dispute bond), then no `resolve` | [`H8x5uNL1…`](https://testnet.nearblocks.io/txns/H8x5uNL1wKdLKCS3ScfPZXMr9VUL2SLb5JfEEv4dYmVx) | disputed; `resolve_until` 180 s later |
| `finalize` (signed by `hunter3`: anyone may call it) after `resolve_until` | [`6d82aM5X…`](https://testnet.nearblocks.io/txns/6d82aM5XoVGh5gnNkiVxEKcHNTDTYTUBcDNzW5pC8uzA) | paid: the agent account gets +0.5 NEAR (payout 0.4 + dispute bond 0.1), and the 0.05 bond returns to the vault (0.36135 -> 0.41135) |

So the agent spent 0.08461 NEAR of storage, plus gas from its key's allowance, and earned 0.5 NEAR.
The agent could also have called `finalize` itself: its key allows it.

## The same key outside MCP

MCP's refusals are a convenience. The contract is the enforcement. Attack f in
[`../demo/ATTACKS.md`](../demo/ATTACKS.md) signs directly with this function-call key, without the
server: `vault_withdraw`, `vault_set_policy`, a transfer, new keys, deleting the account, another
contract, and two submissions the policy forbids. All 11 attempts failed, and the vault did not
change. `client-demo.ts --raw-key` runs a shorter version of the same attempts.

Not part of this run: the demo's `--withdraw` step (`withdraw_pending` after the pending timeout).
The showcase's pending timeout is 24 h and #6 was settled long before. The same path ran on the
showcase through the CLI, for #11.
