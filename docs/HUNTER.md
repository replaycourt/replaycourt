# I found a bug: from report to payout

ReplayCourt runs on NEAR testnet, with test tokens only. You submit from a command line. The
[explorer](https://replaycourt.github.io/replaycourt/web/) only shows the results.

**What you need:** Node 24 and npm, Python 3.8+, [Foundry](https://getfoundry.sh), a clone of this
repository with `npm ci` run in `agent/`, and a NEAR testnet account:

```sh
near account create-account sponsor-by-faucet-service you.testnet \
  autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
export REPLAYCOURT_CONTRACT_ID=<contract account of the bounty>
```

## 1. Write the report

A report is one Markdown file with a Foundry test inside. Copy
[`report-template.md`](report-template.md), or read a real one:
[`01_templedao_stax.md`](../engine/reports/01_templedao_stax.md). The header names the chain, the
block to fork from and the test to run. Replace the zero addresses with real ones. Fill in
`target`, the contract your attack goes through.

The verifier does not read your text to decide. It runs the test and reads the trace:

- value must leave a third party and reach the attacker;
- it must leave through a contract in the program's scope;
- `vm.prank` as the victim and a profit made with `vm.deal` or `deal` do not count.

## 2. Check it yourself first

This runs the same check as the verifier, on your machine. It costs nothing and posts nothing.
Take the scope from the program's page in the explorer.

```sh
python3 -I engine/replay.py check report.md --no-register --dest check --scope 1:0xTHE_CONTRACT_IN_SCOPE
```

Read `check/summary.md`. Submit only if the verdict is `valid`. The template as it stands compiles and
is judged `invalid`, because it moves no money yet.

## 3. Submit

```sh
cd agent
node src/cli.ts submit --program 0 --report ../report.md --as you.testnet
```

The command reads the bond it needs, encrypts the report for the verifier and locks your **bond** and
a **storage fee** in the contract. It prints your submission id. On the showcase program the bond is about 0.05 NEAR and
the storage fee about 0.08 NEAR. The storage fee is not refunded. Nobody but the verifier can read
the report until it is settled; the contract stores only your commitment and the encrypted file.

## 4. Follow it

Open `#/submission/<id>` in the explorer, or run `node src/cli.ts status --program 0`. How long the
verdict takes depends on the verifier: only a program with a running verifier gets verdicts.

| Verdict | What happens to your money | Your next step |
|---|---|---|
| `valid` | waits for the challenge window, in which the owner can object | step 5 |
| `invalid` | you lose the bond (to the pool, minus the verifier's fee) | none; a wrong verdict has no appeal yet |
| `duplicate` | bond back, minus the verifier's fee | none |
| `needs_human` | the owner decides before a deadline; if not, bond back | wait |
| no verdict | after the pending timeout you can take the bond back | `node src/cli.ts withdraw-pending <id> --as you.testnet` |

## 5. Get paid

After the challenge window anyone can trigger the payment:

```sh
node src/cli.ts finalize <id> --as you.testnet
```

You receive the payout for the severity plus your bond. If the owner objected and then did not decide
in time, the same command also pays you the owner's dispute bond. If the owner overrules the verifier,
you get no payout, but you get your bond and the dispute bond.

## Try the whole flow

No verifier is running for the showcase contract right now. To see every step work, deploy your own
copy with [`demo/README.md`](../demo/README.md), path C, which also starts a verifier.
