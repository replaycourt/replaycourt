#!/usr/bin/env python3
"""Voiceover, timeline and subtitles for the ReplayCourt demo video.

Reads storyboard.json, speaks every cue (Piper neural TTS, or macOS `say` with "engine": "say"),
measures each clip, lays the cues out on a timeline (scene lead-in, gaps between cues, scene tail, minimum scene lengths) and writes:

  <work>/timeline.json   scene and cue times, read by render.mjs and the player page
  <work>/voice.wav       48 kHz stereo 16-bit PCM, exactly as long as the video
  <srt>                  subtitles (one cue per caption)

Python 3.8+ standard library only; needs `afconvert` (macOS) and the voice engine. For Piper, set
REPLAYCOURT_PIPER_PYTHON (a Python with `piper-tts` installed) and REPLAYCOURT_PIPER_VOICES (the
directory holding <voice>.onnx and <voice>.onnx.json).
Usage: python3 -I voice.py --storyboard storyboard.json --work <dir> --srt replaycourt-demo.srt
"""
import argparse
import array
import hashlib
import json
import math
import os
import subprocess
import sys
import wave

RATE = 48000
PIPER_OPTIONS = {
    "lengthScale": "--length-scale",
    "noiseScale": "--noise-scale",
    "noiseW": "--noise-w-scale",
    "sentenceSilence": "--sentence-silence",
}


def clip_path(work, voice, text):
    settings = json.dumps({k: voice.get(k) for k in ("engine", "name", "rate", *PIPER_OPTIONS)}, sort_keys=True)
    key = hashlib.sha256(f"{settings}|{text}".encode("utf-8")).hexdigest()[:16]
    return os.path.join(work, "voice", key)


def synthesize(voice, text, out):
    """Write `text` as speech to the audio file `out`; afconvert reads whatever format results."""
    if voice.get("engine", "say") == "say":
        cmd = ["say", "-v", voice["name"], "-o", out]
        if voice.get("rate"):
            cmd += ["-r", str(voice["rate"])]
        subprocess.run(cmd + [text], check=True)
        return
    python = os.environ.get("REPLAYCOURT_PIPER_PYTHON")
    voices = os.environ.get("REPLAYCOURT_PIPER_VOICES")
    if not python or not voices:
        sys.exit("voice engine piper needs REPLAYCOURT_PIPER_PYTHON and REPLAYCOURT_PIPER_VOICES (see README.md)")
    cmd = [python, "-I", "-m", "piper", "--model", os.path.join(voices, voice["name"] + ".onnx"), "--output-file", out]
    for key, flag in PIPER_OPTIONS.items():
        if voice.get(key) is not None:
            cmd += [flag, str(voice[key])]
    subprocess.run(cmd, input=text.encode("utf-8"), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def speak(work, voice, text):
    """Return mono 48 kHz int16 samples of `text` (cached by voice settings and text)."""
    base = clip_path(work, voice, text)
    wav = base + ".wav"
    if not os.path.exists(wav):
        os.makedirs(os.path.dirname(base), exist_ok=True)
        raw = base + (".aiff" if voice.get("engine", "say") == "say" else ".raw.wav")
        synthesize(voice, text, raw)
        subprocess.run(["afconvert", "-f", "WAVE", "-d", f"LEI16@{RATE}", "-c", "1", raw, wav + ".tmp"], check=True)
        os.replace(wav + ".tmp", wav)
        os.remove(raw)
    with wave.open(wav, "rb") as w:
        assert w.getnchannels() == 1 and w.getsampwidth() == 2 and w.getframerate() == RATE, wav
        data = array.array("h")
        data.frombytes(w.readframes(w.getnframes()))
    if sys.byteorder == "big":
        data.byteswap()
    return trim(data)


def trim(samples, threshold=60):
    """Cut leading/trailing near-silence of a clip, keeping 40 ms of margin."""
    n = len(samples)
    lo, hi = 0, n
    while lo < n and abs(samples[lo]) < threshold:
        lo += 1
    while hi > lo and abs(samples[hi - 1]) < threshold:
        hi -= 1
    margin = int(0.04 * RATE)
    return samples[max(0, lo - margin):min(n, hi + margin)]


def fmt_srt(t):
    ms = int(round(t * 1000))
    h, ms = divmod(ms, 3600000)
    m, ms = divmod(ms, 60000)
    s, ms = divmod(ms, 1000)
    return f"{h:02d}:{m:02d}:{s:02d},{ms:03d}"


def wrap2(text, width=58):
    """Break a caption into at most two balanced lines."""
    if len(text) <= width:
        return [text]
    words = text.split(" ")
    best, best_cost = [text], None
    for i in range(1, len(words)):
        a, b = " ".join(words[:i]), " ".join(words[i:])
        cost = max(len(a), len(b))
        if best_cost is None or cost < best_cost:
            best, best_cost = [a, b], cost
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--storyboard", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--srt", required=True)
    args = ap.parse_args()

    with open(args.storyboard, encoding="utf-8") as f:
        sb = json.load(f)
    v = sb["voice"]
    fps = sb["meta"]["fps"]
    os.makedirs(args.work, exist_ok=True)

    t = 0.0
    scenes, placed = [], []
    for scene in sb["scenes"]:
        start = t
        cursor = start + scene.get("leadIn", v["sceneLeadIn"])
        cues = []
        for cue in scene["cues"]:
            text = cue.get("say", cue["caption"])
            samples = speak(args.work, v, text)
            dur = len(samples) / RATE
            cues.append({"start": round(cursor, 3), "end": round(cursor + dur, 3), "caption": cue["caption"]})
            placed.append((cursor, samples))
            cursor += dur + cue.get("gapAfter", v["cueGap"])
        end = max(cursor - v["cueGap"] + scene.get("tail", v["sceneTail"]), start + scene.get("minDuration", 0))
        scenes.append({"id": scene["id"], "start": round(start, 3), "end": round(end, 3), "cues": cues})
        t = end
    t += v.get("endHold", 0)
    scenes[-1]["end"] = round(t, 3)
    frames = int(math.ceil(t * fps))
    duration = frames / fps

    # caption display windows: from cue start until shortly after it ends (never past the next cue)
    all_cues = [c for s in scenes for c in s["cues"]]
    for i, c in enumerate(all_cues):
        nxt = all_cues[i + 1]["start"] if i + 1 < len(all_cues) else duration
        c["showUntil"] = round(min(c["end"] + v.get("captionHold", 0.7), nxt - 0.05), 3)

    # audio: silence with every clip at its place, stereo
    total = int(round(duration * RATE))
    mono = array.array("h", bytes(2 * total))
    for at, samples in placed:
        off = int(round(at * RATE))
        n = min(len(samples), total - off)
        mono[off:off + n] = samples[:n]
    stereo = array.array("h", bytes(4 * total))
    stereo[0::2] = mono
    stereo[1::2] = mono
    if sys.byteorder == "big":
        stereo.byteswap()
    wav_path = os.path.join(args.work, "voice.wav")
    with wave.open(wav_path, "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(stereo.tobytes())

    timeline = {"fps": fps, "frames": frames, "duration": duration, "scenes": scenes}
    with open(os.path.join(args.work, "timeline.json"), "w", encoding="utf-8") as f:
        json.dump(timeline, f, indent=1, ensure_ascii=False)

    with open(args.srt, "w", encoding="utf-8") as f:
        for i, c in enumerate(all_cues, 1):
            f.write(f"{i}\n{fmt_srt(c['start'])} --> {fmt_srt(c['showUntil'])}\n")
            f.write("\n".join(wrap2(c["caption"])) + "\n\n")

    print(f"duration {duration:.2f} s, {frames} frames at {fps} fps, {len(all_cues)} cues")
    for s in scenes:
        print(f"  {s['id']:<9} {s['start']:6.2f} - {s['end']:6.2f}  ({s['end'] - s['start']:5.2f} s)")


if __name__ == "__main__":
    main()
