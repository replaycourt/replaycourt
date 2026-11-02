# ReplayCourt explorer (web/)

A static, read-only explorer for the ReplayCourt contract on NEAR testnet. It has no build step, no
dependencies and loads nothing from a CDN: plain HTML, CSS and ES modules. The page reads the
contract with JSON-RPC `query` / `call_function` view calls through `fetch`, and sends no
transactions. In the browser it hashes each verdict's evidence file with `crypto.subtle`, compares it
with the `evidence_sha256` stored on-chain and, for protocol v2, checks that the evidence names the
submission it is shown for.

**Both contract versions.** The page asks the contract for `version()` once and applies the matching
rules. `1.0.x` is protocol v1 (the first deployments of the hackathon), `2.0.0` is protocol v2
(`../SPEC.md`, the showcase `contract.replaycourt.testnet`). An unknown answer gets the strict v2 rules, as `verify-onchain` does. The header shows
the version next to the network. Views that only v2 has (`get_hunter_in_program`, `required_bond`,
`get_vault`) are never called on a v1 contract.

| View | Route | Shows |
|---|---|---|
| Overview | `#/` | what ReplayCourt does; every program with pool, reserved, payouts, bond, verifier fee, challenge window, owner, verifier and stats. v2 adds the dispute bond, resolve timeout and `stats.overruled` |
| Program | `#/program/0` | the same facts, then all submissions: id, title, hunter (with a "vault" tag for vault-funded reports), status badge (incl. v2 `expired`), outcome, severity, payout, submitted block |
| Submission | `#/submission/3` | every verdict field (reason, fingerprint, fork chain and block, `duplicate_of` as a link); the settlement (bond, storage cost, payout, and in v2 "funded by" vault or deposit, dispute bond and where it went); the deadlines (challenge window, v2 resolve deadline, pending timeout) with a live countdown or "passed" and what happens then; the commitment with its v1 or v2 definition; the **evidence check** (below); the engine's `summary.md` and links to the raw files |
| Hunters | `#/hunters` | `get_hunter` (global, display only) of every hunter that has submitted. v2 adds per hunter a table of `get_hunter_in_program` per program with the bond the hunter must post there now (`required_bond`), and a vault card if `get_vault` returns one: balance, policy (max bond per report, max spend per 24 h, allowed programs) and the amount spent in the current window with its reset time |

Accounts link to `testnet.nearblocks.io`. The page follows the system theme; the header button
switches between light and dark (stored in `localStorage`). `?theme=dark` or `?theme=light` in the
URL forces a theme, e.g. `http://127.0.0.1:8000/web/?theme=dark#/hunters`.

Screenshots of the showcase, in [`../docs/screenshots/`](../docs/screenshots/):

| file | shows |
|---|---|
| `overview.png` | `#/`: the programs with pool, stats and accounts |
| `program.png` | `#/program/0`: the program and its submissions |
| `submission.png` | `#/submission/1`: the TempleDAO report with the evidence check |
| `submission-disputed.png` | `#/submission/6`: the AI hunter's report, disputed, then paid with the dispute bond after `resolve_until` |
| `hunters.png` | `#/hunters`: reputation, bond per program, the agent's vault card |
| `attack-sandbox-escape.png` | `#/submission/8`: attack b, the refusals in the engine's summary |
| `attack-copied-seal.png` | `#/submission/10`: attack e, a copied seal judged invalid |

## Run it

The evidence files live in `runs/` at the repository root, so serve the **repository root**, not
`web/`:

```bash
# from the repository root (any static server works; Python 3 is enough)
python3 -m http.server 8000 --bind 127.0.0.1
```

Then open <http://127.0.0.1:8000/web/>, or another deployment with `?contract=`, e.g.
`http://127.0.0.1:8000/web/?contract=<account>#/program/0`. `http://127.0.0.1` (or `localhost`) is needed, not `file://`: browsers do not load ES
modules from `file://`, and `crypto.subtle` only exists in secure contexts (https or localhost). Stop
the server with Ctrl+C.

Tests (Node >= 20, no install). 18 tests: escaping, Markdown, URLs and formatting
(`lib.test.mjs`), and the v2 rules (`v2.test.mjs`): version detection, the envelope binding check,
the `runs/` path restriction, the private state, raw-file links of both layouts, the v1 and v2
commitment, deadlines and the vault window:

```bash
# from the repository root
node --test web/test/*.test.mjs
```

Screenshots with headless Chrome (macOS path; on Linux use `google-chrome`). The
`--virtual-time-budget` flag lets the RPC calls finish before the picture is taken:

```bash
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --hide-scrollbars \
  --virtual-time-budget=15000 --window-size=1400,1640 \
  --screenshot=submission.png "http://127.0.0.1:8000/web/#/submission/1"
```

## Configuration: `config.js`

| Key | Default | Meaning |
|---|---|---|
| `network` | `testnet` | label, and the `network` an evidence envelope must name |
| `contractId` | `contract.replaycourt.testnet` | the ReplayCourt contract (the showcase, `../demo/SHOWCASE.md`). `?contract=<account>` in the page URL overrides it without editing the file, e.g. your own deployment from `demo/full-testnet.sh`; values that are not valid account ids are ignored |
| `rpc` | `https://test.rpc.fastnear.com`, `https://near-testnet.drpc.org` | JSON-RPC endpoints, tried in order. On a network error, HTTP error or timeout the next one is used (both send CORS headers; `rpc.testnet.near.org` is slow and not used) |
| `rpcTimeoutMs` | `8000` | per request |
| `evidenceBase` | `../` | base for the on-chain `evidence_uri`, which is a path below `runs/` relative to the repository root (`runs/testnet/<contract>/<id>/evidence.json` in v2, `.../verdict.json` in v1). `../` is the repository root when the page is `/web/` |
| `explorer` | `https://testnet.nearblocks.io` | account links |

**Every host in `rpc` or `evidenceBase` must also be in `connect-src` of the CSP** in
`index.html`. Otherwise the browser blocks the request, and the page shows a warning banner naming
the missing host. Two ways to host it:

- **GitHub Pages from the repository root**: the page is `/web/` and `runs/` is published next to it.
  Keep `evidenceBase: "../"`; nothing else changes.
- **Page elsewhere, evidence from GitHub**: set
  `evidenceBase: "https://raw.githubusercontent.com/<owner>/<repo>/<branch>/"` and add
  `https://raw.githubusercontent.com` to `connect-src` (raw.githubusercontent.com answers with
  `Access-Control-Allow-Origin: *`).

## The evidence check

The same rules as `cd agent && npm run cli -- verify-onchain` (`../agent/src/verify.ts`), run in the
browser for the submission on screen:

1. **Location.** `evidence_uri` must be a relative path below `runs/` (SPEC v2 "Evidence"). Every
   segment may only use letters, digits, `.`, `_` and `-` and must not start with a dot, so `..`,
   `%2e%2e`, `?`, `#`, backslashes and absolute URLs of any scheme are refused, and the resolved URL
   must still lie below `<evidenceBase>runs/`. A refused location is ✗ and is not loaded.
2. **Hash.** The page fetches the file and hashes the **raw bytes** with
   `crypto.subtle.digest("SHA-256", …)`. A difference from the on-chain `evidence_sha256` is ✗.
3. **Binding (v2).** `evidence.json` is a `replaycourt.evidence/v1` envelope. Its `network`,
   `contract_id`, `program_id`, `submission_id`, `hunter_id` and `commitment` must equal the network
   and contract the page reads and the on-chain submission, with strict types (`"0"` is not `0`). The
   page shows each field from the file next to the expected value with ✓ or ✗. Evidence copied from
   another submission therefore fails here even though its own hash is right.
4. **v1 evidence.** A `verdict.json` without an envelope passes by hash only, and only from a v1
   contract ("v1 evidence: hash only"). From a v2 contract it is ✗ (not bound). An envelope is
   checked for its binding on either version.
5. **Private until settlement.** The worker keeps the evidence of unsettled submissions private and
   publishes it once the submission is final (`paid`, `invalid`, `duplicate`, `rejected`, `expired`,
   `withdrawn`). If the file answers 404 while the submission is not final, the page shows
   "Evidence private until settlement" with the on-chain hash. **This is not a failure.** A final
   submission that `publish` holds back for a related one that is not final yet
   (`runs/<network>/<contract>/disclosure.json`) is shown as held back, also not a failure. A final
   submission without its file is ✗.

When the engine ran, the page then renders `summary.md` from the same folder and links the raw files.
In the v2 layout these are `evidence.json`, `summary.md`, `report.md`, the PoC (`engine.poc.copy`)
and the engine's `verdict.json`; in the v1 layout `verdict.json`, `summary.md`, `report.md` and the
PoC. For a worker verdict (the engine did not run, e.g. "sealed report does not match commitment")
it shows the worker's reason instead. If `report.md` is published, the page also recomputes the
commitment from it: v2 `sha256("replaycourt/commit/v2" ‖ 0x00 ‖ hunter ‖ 0x00 ‖ report)`, bound to
the hunter account, v1 `sha256(report)`. It shows whether it reproduces the on-chain commitment.

## Security

Every string from the chain is untrusted. Anyone can submit a report, create a program or fund a
vault, so titles, program names, reasons, dispute reasons, resolution notes, account ids and
evidence files are attacker-controlled.

- All markup is built with the `html` tagged template in `lib.js`, which HTML-escapes every
  interpolated value. Only `renderMarkdown` / `renderInline` return markup of their own. They escape
  the text first and then add a fixed set of tags (`h3`-`h6`, `p`, `strong`, `code`, `pre`, `ul`,
  `li`, `table`, `hr`); links and raw HTML in Markdown stay text. `web/test/lib.test.mjs` feeds both
  hostile input.
- Status, outcome and severity become CSS classes only through allow-lists. Ids, program ids in a
  vault policy and evidence binding ids are forced through `Number()` or compared strictly. Account
  links use `encodeURIComponent`. Only `http(s)` URLs become links, and evidence is only fetched
  from below `runs/` (see above). A PoC file name from the evidence becomes a link only if it is a
  plain file name.
- CSP (meta tag in `index.html`): `default-src 'self'; script-src 'self'; style-src 'self';
  img-src 'self'; font-src 'self'; connect-src 'self' https://test.rpc.fastnear.com
  https://near-testnet.drpc.org; object-src 'none'; base-uri 'none'; form-action 'none'`. There are
  no inline scripts, inline styles or event-handler attributes. Requests go out without credentials
  and without a referrer.

## Files

```
web/
  index.html     page shell, CSP
  config.js      network, contract, RPC list, evidence base
  app.js         router (hash routes), views, evidence check, deadlines, theme
  near.js        JSON-RPC client with endpoint fallback and a 15 s view cache
  lib.js         escaping (html``), formatting, sha256, evidence URLs, v1/v2 evidence and commitment
                 rules, minimal Markdown
  style.css      light and dark theme
  favicon.svg
  test/lib.test.mjs   escaping, Markdown, URLs, formatting
  test/v2.test.mjs    protocol v2 rules
```

AI disclosure: written with Claude Code (AI-generated code, reviewed and tested as described above).
