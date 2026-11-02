#!/usr/bin/env bash
# Build demo/video/replaycourt-demo.mp4 and replaycourt-demo.srt from storyboard.json.
#
#   demo/video/tools/build.sh                 # full build
#   STILLS=2,40,70 demo/video/tools/build.sh  # also export these seconds as PNGs for a check
#
# Environment:
#   WORK   scratch directory for voice clips, frames and binaries (default: $TMPDIR/replaycourt-video).
#          Frames take a few hundred MB; nothing in WORK is needed after the build.
#   WRAP   optional command prefix for every step, e.g. a memory/time cap wrapper:
#          WRAP="python3 /path/to/memcap.py --limit 4G --timeout 30m --"
#   CHROME path of the Chrome binary (default: the macOS app bundle)
#
# Needs macOS (afconvert, swiftc with AVFoundation), Node >= 22, Python 3.8+ and the voice (see README.md). No ffmpeg.
set -euo pipefail

VIDEO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-${TMPDIR:-/tmp}/replaycourt-video}"
WORK="${WORK%/}"
WRAP="${WRAP:-}"
mkdir -p "$WORK/bin"

meta() { python3 -I -c "import json,sys; print(json.load(open(sys.argv[1]))['meta'][sys.argv[2]])" "$VIDEO/storyboard.json" "$1"; }

if grep -nE "<(tx|key|sha256|commitment|block|repo)>" "$VIDEO/storyboard.json"; then echo "storyboard.json still holds placeholders" >&2; exit 1; fi

echo "== 1/5 voiceover, timeline, subtitles"
$WRAP python3 -I "$VIDEO/tools/voice.py" --storyboard "$VIDEO/storyboard.json" --work "$WORK" --srt "$VIDEO/replaycourt-demo.srt"

echo "== 2/5 frames (headless Chrome)"
$WRAP node "$VIDEO/tools/render.mjs" --work "$WORK" ${CHROME:+--chrome "$CHROME"}

echo "== 3/5 compile encoder and probe"
$WRAP swiftc -O -swift-version 5 "$VIDEO/tools/encode.swift" -o "$WORK/bin/encode" 2>/dev/null
$WRAP swiftc -O -swift-version 5 "$VIDEO/tools/probe.swift" -o "$WORK/bin/probe" 2>/dev/null

echo "== 4/5 encode H.264 + AAC"
$WRAP "$WORK/bin/encode" --manifest "$WORK/frames/manifest.txt" --audio "$WORK/voice.wav" \
  --out "$VIDEO/replaycourt-demo.mp4" --fps "$(meta fps)" --width "$(meta width)" --height "$(meta height)" \
  --vbitrate "$(meta videoBitrate)" --abitrate "$(meta audioBitrate)"

echo "== 5/5 check"
$WRAP "$WORK/bin/probe" "$VIDEO/replaycourt-demo.mp4" ${STILLS:+--stills "$STILLS" --out "$WORK/check"}
