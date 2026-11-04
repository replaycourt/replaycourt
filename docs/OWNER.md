# I run a bounty: setting up and operating a program

ReplayCourt runs on NEAR testnet, with test tokens only. You operate it from a command line. The
[explorer](https://replaycourt.github.io/replaycourt/web/) shows your program with
`?contract=<contract account>`. There are no notifications, multisig or owner screens yet.

**What you need:** Node 24 and npm, Python 3.8+, [Foundry](https://getfoundry.sh), a clone of this
repository with `npm ci` run in `agent/`, one NEAR testnet account for you and one for the verifier,
and an archive RPC for the chain your contracts run on.

## 1. Decide who runs the verifier

Reports are encrypted to the verifier's key, so whoever runs it reads the bugs first.

- **You run it:** you read the reports at once, but you judge your own program, and slashed bonds go to
  your pool. Hunters have to trust that.
- **Someone else runs it:** hunters trust a third party, but you only read a report through that party.
  The protocol has no channel for this yet.

ReplayCourt does not solve this choice. See "Limits" in the [README](../README.md).

## 2. Create the program

```sh
cd agent
export REPLAYCOURT_CONTRACT_ID=<contract account>
export REPLAYCOURT_OWNER_ID=you.testnet
export REPLAYCOURT_VERIFIER_ID=verifier.you.testnet
node src/cli.ts keygen                 # the verifier's encryption key
node src/cli.ts setup-verifier-key     # a key that can only post verdicts
node src/cli.ts create-program --name "My bounty" \
  --pool 10 --bond 0.1 --dispute-bond 0.2 --payouts 2,1,0.5,0.1 \
  --challenge 86400 --resolve-timeout 259200 \
  --scope 1:0xYOUR_CONTRACT,1:0xYOUR_OTHER_CONTRACT
```

- **Pool:** the rewards, held by the contract. Each open report reserves the highest payout plus the
  verifier's fee, so a pool of 10 with a top payout of 2 can take about 5 open reports. You can withdraw
  what is not reserved.
- **Payouts:** critical, high, medium, low.
- **Scope:** always set it. The verifier rejects reports whose value does not leave through these
  contracts. A program without a scope accepts an exploit of any contract.

## 3. Run the verifier

```sh
REPLAYCOURT_WORKER_PROGRAMS=<program id> node src/cli.ts worker --min-fork-block <today's block>
```

The worker replays every pending report on a fork and posts the verdict. `--min-fork-block` rejects reports that fork from before your program started: an
old public exploit of your contract is not a new finding. The PoC is hostile code on this machine. It
runs without network limits or a kernel sandbox, so use a separate machine or container.

## 4. Handle what comes in

| Situation | What you do | Cost |
|---|---|---|
| `valid` | nothing: after the challenge window it pays out | payout and verifier's fee from the pool |
| `valid`, but you disagree | `node src/cli.ts dispute <id> --reason "..."` inside the window | locks your dispute bond |
| disputed | `node src/cli.ts resolve <id> --outcome valid --severity high --note "..."` or `--outcome invalid` before the deadline | overruling or a lower severity gives the hunter your dispute bond; missing the deadline pays the hunter plus the bond |
| `needs_human` | `node src/cli.ts unseal --submission <id>` to read it, then `resolve` before the deadline | if you do nothing, the hunter gets the bond back |

The verifier decides `needs_human` for what a replay cannot settle, such as a local run, faked state or
a privileged role. Read those reports.

## 5. Publish and close

```sh
node src/cli.ts publish                               # evidence of settled reports, so anyone can check it
node src/cli.ts withdraw-pool --program <id> --all    # the unreserved part of the pool
```
