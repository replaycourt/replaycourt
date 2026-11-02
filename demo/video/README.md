# ReplayCourt demo video

`replaycourt-demo.mp4` is the demo video for the NEAR hackathon entry. Specs: 1920x1080, 30 fps, H.264 High with AAC stereo audio, 119.4 s. Burned-in captions are included. `replaycourt-demo.srt` has the same captions as a subtitle file.

The video is generated from [`storyboard.json`](storyboard.json). It is not screen-recorded. Every number, account, hash and transaction id shown comes from a file in this repository, and everything from scene 3 on shows the showcase deployment `contract.replaycourt.testnet`:

- `demo/SHOWCASE.md`: submissions #0 to #11, all tx hashes, the dispute of #6
- `demo/logs/`: `showcase-submissions.txt`, `showcase-worker.txt`, `showcase-settlement.txt`, `mcp-client-demo.txt`
- `demo/ATTACKS.md` and `demo/attacks/logs/`: `d-stolen-key.txt` (attack d), `f-stolen-agent-key.txt` (attack f), attack a
- `runs/testnet/contract.replaycourt.testnet/<id>/`: `summary.md`, `worker.json`, `evidence.json`
- `mcp/DEMO.md`: the AI hunter, its vault and its policy
- `docs/screenshots/submission.png` and `submission-disputed.png`: the explorer pages of #1 and #6

The terminal panels show the commands from `demo/SHOWCASE.md` and selected lines those commands printed, copied from the logs above. The panels are re-typeset, not screen recordings.

## Scenes

| # | Scene | Time | What is shown |
|---|---|---|---|
| 1 | The problem | 0:00-0:18 | AI-report flood: Ethereum Foundation "allow up to a week", Cosmos +900 %, Decred paused. A real Cosmos EVM bug was marked "unable to reproduce" and later exploited for about $5.7M |
| 2 | The idea | 0:18-0:30 | A bug report that proves itself: hunter → commit on NEAR → replay on a fork → valid / invalid / duplicate |
| 3 | One report, start to finish | 0:30-0:58 | #1 (TempleDAO, hunter1): `submit` (tx `B9zDQa3f…`, bond 0.05321 NEAR, commitment bound to the hunter), worker replay at Ethereum block 15,725,066 (attacker +321,154.87 xFraxTempleLP, victim −100 %, 11.3 s), verdict valid/critical with the function-call key (tx `GkFdHxRB…`), `finalize` by hunter3 (tx `HkGucff6…`), payout 0.4 NEAR, and the explorer showing "Evidence matches on-chain and is bound to this submission" |
| 4 | Spam pays for itself | 0:58-1:12 | #4 fake profit via `vm.prank`: invalid, 0.05585 NEAR slashed (tx `EMXodkQ5…`). #2 reworded copy: same fingerprint, committed in NEAR block 275,950,743 after #1 (275,950,735): duplicate of #1 (tx `F9jjLYmF…`). #0 broken first try: invalid, 0.05321 NEAR slashed (tx `E9BXf71d…`), and it does not block #1 |
| 5 | Built for hostile input | 1:12-1:20 | Attack d, stolen verifier key: `AccessKeyRequiresFullAccessActionError`, `AccessKeyMethodNameMismatchActionError`, `AccessKeyDepositWithFunctionCallActionError`. Attack a, prompt injection in report #7: invalid, "No measurable value movement" (tx `BJ9w66rb…`) |
| 6 | The AI hunter | 1:20-1:35 | Vault plus function-call key: #6 (Seneca) submitted through MCP from the vault (tx `98c5qCNu…`), valid, bounty 0.4 NEAR. MCP refusal `vault_policy` / `daily_spend_cap`. Attack f, stolen agent key: `vault_withdraw` and `vault_set_policy` refused with the exact protocol errors, vault unchanged |
| 7 | An owner who stalls pays | 1:35-1:45 | The owner disputes #6 (tx `H8x5uNL1…`) and does not resolve. `finalize` is refused before the deadline, then paid after it (tx `6d82aM5X…`): the agent gets +0.5 NEAR, payout 0.4 plus dispute bond 0.1 |
| 8 | Why NEAR | 1:45-1:59 | Escrow without a custodian, function-call access keys, on-chain spending policy, on-chain commit order. Repo link and a question |

The exact times are printed by `voice.py` (see below). They follow from the length of the spoken cues.

Sources for the problem facts (scene 1):

- Ethereum Foundation, <https://ethereum.org/en/bug-bounty/>: "Due to the increase in AI submissions, please allow up to a week for us to respond to your submission."
- Cointelegraph, 22 Apr 2026, <https://cointelegraph.com/news/ai-crypto-bug-bounty-submissions-surge> (Cosmos): "a 900% increase in submission volume from last year, on the order of 20-50 per day".
- Decred, 17 May 2026, <https://bounty.decred.org/2026/05/bounty-program-hiatus/>: "a severe drain on resources that is not sustainable".
- Cosmos EVM. A valid report from 25 Apr 2026 was triaged as non-critical ("unable to reproduce … on 18-decimal networks"). The bug was exploited on six chains for about $5.7M in August 2026:
  - The Block, 29 Aug 2026: <https://theblock.co/news/defi/2026-08-29-cosmos-labs-says-it-wrongly-cleared-the-bug-behind-a-5-7-million-six-chain-hack-413061>
  - The Hacker News: <https://thehackernews.com/2026/08/cosmos-evm-flaw-exploited-after-cosmos.html>

## Regenerate

Requirements:

- macOS, with `afconvert` and `swiftc` (Xcode command line tools, AVFoundation)
- Google Chrome
- Node >= 22
- Python 3.8+
- The voice: [Piper](https://github.com/OHF-Voice/piper1-gpl) (`piper-tts`, offline neural TTS) and the voice `en_US-lessac-high` from [rhasspy/piper-voices](https://huggingface.co/rhasspy/piper-voices/tree/main/en/en_US/lessac/high) (model sha256 `4cabf7c3a638017137f34a1516522032d4fe3f38228a843cc9b764ddcbcd9e09`):

  ```sh
  python3 -m venv <venv> && <venv>/bin/pip install piper-tts
  export REPLAYCOURT_PIPER_PYTHON=<venv>/bin/python
  export REPLAYCOURT_PIPER_VOICES=<dir with en_US-lessac-high.onnx and .onnx.json>
  ```

  To build without Piper, set `"engine": "say"` and a macOS voice name in `storyboard.json`.

No ffmpeg and no npm packages are needed.

From the repository root:

```bash
demo/video/tools/build.sh
```

This writes `demo/video/replaycourt-demo.mp4` and `demo/video/replaycourt-demo.srt`. Scratch files go to `$WORK` (default `$TMPDIR/replaycourt-video`): voice clips, a few hundred MB of PNG frames, and the compiled Swift tools. A full build takes about 5 minutes. The voice clips are cached in `$WORK/voice/`.

Useful variants:

```bash
# put the scratch files somewhere else, and wrap every step in a memory/time cap
WORK=/path/to/scratch WRAP="python3 /path/to/memcap.py --limit 4G --timeout 30m --" demo/video/tools/build.sh

# after the build, export frames of the finished MP4 at these seconds as PNG (into $WORK/check/)
STILLS=1,45,58,70,100 demo/video/tools/build.sh
```

The individual steps, as `build.sh` runs them:

```bash
V=demo/video; WORK=${TMPDIR:-/tmp}/replaycourt-video; mkdir -p $WORK/bin
python3 -I $V/tools/voice.py --storyboard $V/storyboard.json --work $WORK --srt $V/replaycourt-demo.srt
node $V/tools/render.mjs --work $WORK                      # frames + $WORK/frames/manifest.txt
swiftc -O -swift-version 5 $V/tools/encode.swift -o $WORK/bin/encode
swiftc -O -swift-version 5 $V/tools/probe.swift -o $WORK/bin/probe
$WORK/bin/encode --manifest $WORK/frames/manifest.txt --audio $WORK/voice.wav --out $V/replaycourt-demo.mp4 \
  --fps 30 --width 1920 --height 1080 --vbitrate 6000000 --abitrate 160000
$WORK/bin/probe $V/replaycourt-demo.mp4 --stills 2,45,58 --out $WORK/check
```

Quick look at single frames without a full render (after `voice.py` has written the timeline):

```bash
node demo/video/tools/render.mjs --work $WORK --stills 2,40,58   # -> $WORK/stills/t<sec>.png
```

## How it works

| File | Role |
|---|---|
| `storyboard.json` | the only content source: narration (`say`) and captions per cue, all on-screen texts, tx hashes, screenshot paths and crops, cue-relative timings, voice and encoder settings |
| `tools/voice.py` | speaks each cue with Piper (voice `en_US-lessac-high`), measures the clips and lays them out (lead-in, gaps, minimum scene lengths). Writes `timeline.json`, the voice track `voice.wav` (48 kHz stereo) and the `.srt` |
| `scenes/index.html`, `player.js`, `style.css` | the frame player. `setup()` builds the scenes from the storyboard. `seek(t)` sets the page to time `t`: fades, typing, highlights and captions are pure functions of `t` |
| `tools/render.mjs` | drives headless Chrome over the DevTools pipe. It calls `seek(i/30)` for every frame and takes a screenshot only when the page state changed. Identical frames are stored once |
| `tools/encode.swift` | AVAssetWriter: PNG frames → H.264 (BT.709, 6 Mbit/s, keyframe every 2 s), WAV → AAC 160 kbit/s, `moov` atom at the front |
| `tools/probe.swift` | AVFoundation check of the result (duration, size, codecs, tracks) and still-frame export |

## Changing the material

All content is in `storyboard.json`. Edit it and run `build.sh` again. `build.sh` stops if a placeholder in angle brackets is left in it.

- **Texts and narration**: each scene has `cues`. `caption` is shown and written to the `.srt`. `say` (optional) is what the voice speaks, for example numbers spelled out or a respelling for the voice ("Dee-cred", "duplikit"). The scene length follows the speech. Keep the total at or under 120 s (`voice.py` prints it); tighten the narration rather than speeding the voice.
- **Tx hashes, accounts, numbers**: the `submit`, `replay`, `verdict` and `paid` blocks of scene `moment`, `cards` and `strip` of `spam`, `cols` of `security` and `agent`, `steps` of `dispute`.
- **Contract name**: `meta.contract` and `meta.dataNote` (header line), plus the strings in the blocks above.
- **Screenshots**: `src` (path from the repository root), `crop` (pixels of the source image), `pan` (a list of `{at, y}` scrolls) and `highlights` (boxes in source-image pixels, each with the cue time `at` at which it appears).
- **Timing**: `at` values are cue references (`"c2"` = start of cue 2, `"c2@0.5"` = halfway through it, `"c2+0.4"` = 0.4 s after its start). Scene-level `minDuration`, `tail` and per-cue `gapAfter` add reading time.
- **Repository link**: `meta.repo` and `near.cta.repo`.

## Provenance

AI disclosure: the storyboard, the scenes and the tools in this folder were written by an AI coding agent (Claude). The voice is the synthetic Piper voice `en_US-lessac-high`.
