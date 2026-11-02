// Encode PNG frames + a WAV voice track into an H.264/AAC MP4 with AVFoundation (no ffmpeg).
//
//   swiftc -O -swift-version 5 encode.swift -o encode
//   ./encode --manifest frames/manifest.txt --audio voice.wav --out video.mp4 \
//            [--fps 30] [--width 1920] [--height 1080] [--vbitrate 6000000] [--abitrate 160000]
//
// manifest.txt holds one PNG path per video frame (repeated paths are decoded once).
import AVFoundation
import CoreGraphics
import CoreVideo
import Foundation
import ImageIO

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

var opts: [String: String] = [:]
var argv = Array(CommandLine.arguments.dropFirst())
while !argv.isEmpty {
    let k = argv.removeFirst()
    guard k.hasPrefix("--"), !argv.isEmpty else { fail("bad argument \(k)") }
    opts[String(k.dropFirst(2))] = argv.removeFirst()
}
guard let manifestPath = opts["manifest"], let audioPath = opts["audio"], let outPath = opts["out"] else {
    fail("usage: encode --manifest <txt> --audio <wav> --out <mp4> [--fps 30] [--width 1920] [--height 1080] [--vbitrate 6000000] [--abitrate 160000]")
}
let fps = Int32(opts["fps"] ?? "30")!
let width = Int(opts["width"] ?? "1920")!
let height = Int(opts["height"] ?? "1080")!
let vBitrate = Int(opts["vbitrate"] ?? "6000000")!
let aBitrate = Int(opts["abitrate"] ?? "160000")!

guard let manifestText = try? String(contentsOfFile: manifestPath, encoding: .utf8) else { fail("cannot read \(manifestPath)") }
let frames = manifestText.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
guard !frames.isEmpty else { fail("manifest is empty") }

let outURL = URL(fileURLWithPath: outPath)
try? FileManager.default.removeItem(at: outURL)
let writer: AVAssetWriter
do { writer = try AVAssetWriter(outputURL: outURL, fileType: .mp4) } catch { fail("AVAssetWriter: \(error)") }
writer.shouldOptimizeForNetworkUse = true

// ---- video input ----
let videoSettings: [String: Any] = [
    AVVideoCodecKey: AVVideoCodecType.h264,
    AVVideoWidthKey: width,
    AVVideoHeightKey: height,
    AVVideoColorPropertiesKey: [
        AVVideoColorPrimariesKey: AVVideoColorPrimaries_ITU_R_709_2,
        AVVideoTransferFunctionKey: AVVideoTransferFunction_ITU_R_709_2,
        AVVideoYCbCrMatrixKey: AVVideoYCbCrMatrix_ITU_R_709_2,
    ],
    AVVideoCompressionPropertiesKey: [
        AVVideoAverageBitRateKey: vBitrate,
        AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel,
        AVVideoMaxKeyFrameIntervalKey: Int(fps) * 2,
        AVVideoExpectedSourceFrameRateKey: Int(fps),
        AVVideoAllowFrameReorderingKey: true,
    ],
]
let videoIn = AVAssetWriterInput(mediaType: .video, outputSettings: videoSettings)
videoIn.expectsMediaDataInRealTime = false
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: videoIn, sourcePixelBufferAttributes: [
    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
    kCVPixelBufferWidthKey as String: width,
    kCVPixelBufferHeightKey as String: height,
    kCVPixelBufferCGImageCompatibilityKey as String: true,
    kCVPixelBufferCGBitmapContextCompatibilityKey as String: true,
])
guard writer.canAdd(videoIn) else { fail("cannot add video input") }
writer.add(videoIn)

// ---- audio input (PCM from the WAV, re-encoded to AAC) ----
let audioAsset = AVURLAsset(url: URL(fileURLWithPath: audioPath))
guard let audioTrack = audioAsset.tracks(withMediaType: .audio).first else { fail("no audio track in \(audioPath)") }
let reader: AVAssetReader
do { reader = try AVAssetReader(asset: audioAsset) } catch { fail("AVAssetReader: \(error)") }
let readerOut = AVAssetReaderTrackOutput(track: audioTrack, outputSettings: [
    AVFormatIDKey: kAudioFormatLinearPCM,
    AVLinearPCMBitDepthKey: 16,
    AVLinearPCMIsFloatKey: false,
    AVLinearPCMIsBigEndianKey: false,
    AVLinearPCMIsNonInterleaved: false,
])
reader.add(readerOut)
var channels = 2
var sampleRate = 48000.0
if let fd = audioTrack.formatDescriptions.first, let asbd = CMAudioFormatDescriptionGetStreamBasicDescription(fd as! CMAudioFormatDescription)?.pointee {
    channels = Int(asbd.mChannelsPerFrame)
    sampleRate = asbd.mSampleRate
}
let audioIn = AVAssetWriterInput(mediaType: .audio, outputSettings: [
    AVFormatIDKey: kAudioFormatMPEG4AAC,
    AVSampleRateKey: sampleRate,
    AVNumberOfChannelsKey: channels,
    AVEncoderBitRateKey: aBitrate,
])
audioIn.expectsMediaDataInRealTime = false
guard writer.canAdd(audioIn) else { fail("cannot add audio input") }
writer.add(audioIn)

guard writer.startWriting() else { fail("startWriting: \(String(describing: writer.error))") }
guard reader.startReading() else { fail("startReading: \(String(describing: reader.error))") }
writer.startSession(atSourceTime: .zero)

// ---- frame decoding ----
let colorSpace = CGColorSpace(name: CGColorSpace.sRGB)!
func loadImage(_ path: String) -> CGImage {
    guard let src = CGImageSourceCreateWithURL(URL(fileURLWithPath: path) as CFURL, nil),
          let img = CGImageSourceCreateImageAtIndex(src, 0, nil) else { fail("cannot decode \(path)") }
    return img
}
func makeBuffer(_ image: CGImage) -> CVPixelBuffer {
    var pb: CVPixelBuffer?
    if let pool = adaptor.pixelBufferPool {
        CVPixelBufferPoolCreatePixelBuffer(nil, pool, &pb)
    }
    if pb == nil {
        CVPixelBufferCreate(nil, width, height, kCVPixelFormatType_32BGRA, [
            kCVPixelBufferCGImageCompatibilityKey: true, kCVPixelBufferCGBitmapContextCompatibilityKey: true,
        ] as CFDictionary, &pb)
    }
    guard let buffer = pb else { fail("cannot create pixel buffer") }
    CVPixelBufferLockBaseAddress(buffer, [])
    let ctx = CGContext(data: CVPixelBufferGetBaseAddress(buffer), width: width, height: height, bitsPerComponent: 8,
                        bytesPerRow: CVPixelBufferGetBytesPerRow(buffer), space: colorSpace,
                        bitmapInfo: CGImageAlphaInfo.premultipliedFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue)!
    ctx.interpolationQuality = .high
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
    CVPixelBufferUnlockBaseAddress(buffer, [])
    CVBufferSetAttachment(buffer, kCVImageBufferColorPrimariesKey, kCVImageBufferColorPrimaries_ITU_R_709_2, .shouldPropagate)
    CVBufferSetAttachment(buffer, kCVImageBufferTransferFunctionKey, kCVImageBufferTransferFunction_ITU_R_709_2, .shouldPropagate)
    CVBufferSetAttachment(buffer, kCVImageBufferYCbCrMatrixKey, kCVImageBufferYCbCrMatrix_ITU_R_709_2, .shouldPropagate)
    return buffer
}

let group = DispatchGroup()
let videoQueue = DispatchQueue(label: "video")
let audioQueue = DispatchQueue(label: "audio")
var frameIndex = 0
var lastPath = ""
var lastBuffer: CVPixelBuffer? = nil
var decoded = 0
var audioSamples = 0

group.enter()
videoIn.requestMediaDataWhenReady(on: videoQueue) {
    while videoIn.isReadyForMoreMediaData && frameIndex < frames.count {
        let path = frames[frameIndex]
        if path != lastPath || lastBuffer == nil {
            autoreleasepool {
                lastBuffer = makeBuffer(loadImage(path))
            }
            lastPath = path
            decoded += 1
        }
        let time = CMTime(value: CMTimeValue(frameIndex), timescale: fps)
        if !adaptor.append(lastBuffer!, withPresentationTime: time) {
            fail("append frame \(frameIndex): \(String(describing: writer.error))")
        }
        frameIndex += 1
        if frameIndex % 600 == 0 { print("video \(frameIndex)/\(frames.count)") }
    }
    if frameIndex >= frames.count {
        videoIn.markAsFinished()
        group.leave()
    }
}

group.enter()
audioIn.requestMediaDataWhenReady(on: audioQueue) {
    while audioIn.isReadyForMoreMediaData {
        if let sb = readerOut.copyNextSampleBuffer() {
            audioSamples += CMSampleBufferGetNumSamples(sb)
            if !audioIn.append(sb) { fail("append audio: \(String(describing: writer.error))") }
        } else {
            audioIn.markAsFinished()
            group.leave()
            break
        }
    }
}

group.wait()
let done = DispatchSemaphore(value: 0)
writer.finishWriting { done.signal() }
done.wait()
if writer.status != .completed { fail("finishWriting: \(String(describing: writer.error))") }
// shouldOptimizeForNetworkUse can leave its unoptimized temp copy (<name>.sb-*) next to the output
let outDir = outURL.deletingLastPathComponent()
for name in (try? FileManager.default.contentsOfDirectory(atPath: outDir.path)) ?? [] where name.hasPrefix(outURL.lastPathComponent + ".sb-") {
    try? FileManager.default.removeItem(at: outDir.appendingPathComponent(name))
}
let size = (try? FileManager.default.attributesOfItem(atPath: outPath)[.size] as? Int) ?? 0
print(String(format: "wrote %@: %d frames (%d decoded), %.2f s video, %.2f s audio (%d ch, %.0f Hz), %.1f MB",
             outPath, frames.count, decoded, Double(frames.count) / Double(fps), Double(audioSamples) / sampleRate,
             channels, sampleRate, Double(size) / 1_000_000))
