// Inspect the finished MP4 with AVFoundation and export still frames for a visual check.
//
//   swiftc -O -swift-version 5 probe.swift -o probe
//   ./probe replaycourt-demo.mp4 [--stills 2,40,70,100 --out <dir>]
//
// Prints duration, file size, and per track: media type, codec, size, frame rate, data rate,
// audio format. Exits 1 if there is no H.264 video or no AAC audio track.
import AVFoundation
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

func fourCC(_ v: FourCharCode) -> String {
    let bytes = [24, 16, 8, 0].map { UInt8((v >> $0) & 0xff) }
    return String(bytes: bytes, encoding: .ascii) ?? String(v)
}

var argv = Array(CommandLine.arguments.dropFirst())
guard let path = argv.first else {
    FileHandle.standardError.write("usage: probe <file.mp4> [--stills 2,40 --out <dir>]\n".data(using: .utf8)!)
    exit(64)
}
argv.removeFirst()
var opts: [String: String] = [:]
while argv.count >= 2 { let k = argv.removeFirst(); opts[String(k.dropFirst(2))] = argv.removeFirst() }

let url = URL(fileURLWithPath: path)
let asset = AVURLAsset(url: url)
let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
print(String(format: "file      %@", url.lastPathComponent))
print(String(format: "size      %.2f MB (%d bytes)", Double(size) / 1_000_000, size))
print(String(format: "duration  %.3f s", CMTimeGetSeconds(asset.duration)))
var hasH264 = false
var hasAAC = false
for track in asset.tracks {
    let fd = track.formatDescriptions.first as! CMFormatDescription
    let codec = fourCC(CMFormatDescriptionGetMediaSubType(fd))
    if track.mediaType == .video {
        if codec == "avc1" { hasH264 = true }
        let ext = CMFormatDescriptionGetExtensions(fd) as? [String: Any] ?? [:]
        let prim = ext[kCMFormatDescriptionExtension_ColorPrimaries as String] ?? "-"
        print(String(format: "video     %@ %.0fx%.0f, %.3f fps, %.2f Mbit/s, %d frames, %.3f s, color %@",
                     codec, track.naturalSize.width, track.naturalSize.height, track.nominalFrameRate,
                     track.estimatedDataRate / 1_000_000,
                     Int((CMTimeGetSeconds(track.timeRange.duration) * Double(track.nominalFrameRate)).rounded()),
                     CMTimeGetSeconds(track.timeRange.duration), String(describing: prim)))
    } else if track.mediaType == .audio {
        if codec == "aac " { hasAAC = true }
        let asbd = CMAudioFormatDescriptionGetStreamBasicDescription(fd)!.pointee
        print(String(format: "audio     %@ %.0f Hz, %d ch, %.0f kbit/s, %.3f s",
                     codec, asbd.mSampleRate, asbd.mChannelsPerFrame, track.estimatedDataRate / 1000,
                     CMTimeGetSeconds(track.timeRange.duration)))
    } else {
        print("other     \(track.mediaType.rawValue) \(codec)")
    }
}

if let stills = opts["stills"] {
    let outDir = opts["out"] ?? "."
    try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
    let gen = AVAssetImageGenerator(asset: asset)
    gen.requestedTimeToleranceBefore = .zero
    gen.requestedTimeToleranceAfter = .zero
    for s in stills.split(separator: ",") {
        let secs = Double(s)!
        do {
            let img = try gen.copyCGImage(at: CMTime(seconds: secs, preferredTimescale: 600), actualTime: nil)
            let out = URL(fileURLWithPath: outDir).appendingPathComponent("still-\(s).png")
            let dest = CGImageDestinationCreateWithURL(out as CFURL, UTType.png.identifier as CFString, 1, nil)!
            CGImageDestinationAddImage(dest, img, nil)
            CGImageDestinationFinalize(dest)
            print("still     \(out.path)")
        } catch {
            print("still     \(s): \(error)")
        }
    }
}
if !hasH264 || !hasAAC {
    print("FAIL: expected an H.264 video track and an AAC audio track")
    exit(1)
}
print("ok        H.264 video + AAC audio")
