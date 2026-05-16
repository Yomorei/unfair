import Darwin
import Foundation
import MachO

public final class BinaryDecryptor {
    private let logger: UnfairLogger
    private typealias MremapEncrypted = @convention(c) (UnsafeMutableRawPointer?, Int, UInt32, UInt32, UInt32) -> Int32
    private let addFileSignaturesReturn = Int32(97)

    private struct FileSignatures {
        var fileStart: off_t
        var blobStart: UnsafeMutableRawPointer?
        var blobSize: Int
    }

    private struct TemporarySinf {
        var destination: URL
    }

    private enum DecryptionStatus {
        case decrypted
        case skipped
    }

    private let cpuTypeArm64 = UInt32(bitPattern: CPU_TYPE_ARM64)
    private let cpuSubtypeArm64All = UInt32(CPU_SUBTYPE_ARM64_ALL)

    public init(logger: UnfairLogger = UnfairLogger()) {
        self.logger = logger
    }

    public func decryptBinary(at url: URL, rootSinf: URL, displayPath: String? = nil) throws {
        let temporarySinf = try installTemporarySinf(for: url, rootSinf: rootSinf)
        defer { removeTemporarySinf(temporarySinf) }
        let status = try decryptBinaryInPlace(at: url)
        log(status: status, label: displayPath ?? url.path)
    }

    public func decryptBinary(installedAt installedURL: URL, outputURL: URL, rootSinf: URL, displayPath: String? = nil) throws {
        let temporarySinf = try installTemporarySinf(for: installedURL, rootSinf: rootSinf)
        defer { removeTemporarySinf(temporarySinf) }
        let status = try decryptBinary(installedAt: installedURL, outputURL: outputURL)
        log(status: status, label: displayPath ?? outputURL.path)
    }

    private func log(status: DecryptionStatus, label: String) {
        switch status {
        case .decrypted:
            logger.log("decrypted: \(label)")
        case .skipped:
            logger.log("skipped: \(label)")
        }
    }

    private func installTemporarySinf(for url: URL, rootSinf: URL) throws -> TemporarySinf? {
        let scInfo = URL(fileURLWithPath: "SC_Info", isDirectory: true)
        try FileSystem.createDirectory(scInfo)

        let destination = scInfo.appendingPathComponent(url.lastPathComponent + ".sinf")
        if FileSystem.sameFile(rootSinf, destination) {
            return nil
        }

        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }

        logger.verbose("sinf copy: root sinf -> ./SC_Info/\(url.lastPathComponent).sinf")
        try FileManager.default.copyItem(at: rootSinf, to: destination)
        return TemporarySinf(destination: destination)
    }

    private func removeTemporarySinf(_ temporarySinf: TemporarySinf?) {
        guard let temporarySinf = temporarySinf else {
            return
        }
        try? FileManager.default.removeItem(at: temporarySinf.destination)
    }

    private func decryptBinaryInPlace(at url: URL) throws -> DecryptionStatus {
        logger.verbose("target: \(url.path)")
        logger.verbose("opening \(url.path) (read-write)")

        let fd = open(url.path, O_RDWR)
        guard fd >= 0 else {
            throw UnfairError.io("open failed: \(String(cString: strerror(errno)))")
        }
        defer { close(fd) }

        let mapped = try mapWritableBinary(fd: fd)
        defer { munmap(mapped.base, mapped.size) }

        let output = try inspectMappedBinary(mapped.base, fileSize: mapped.size)
        guard let enc = output.encryptionInfo else {
            return .skipped
        }
        if enc.cryptid == 0 {
            logger.verbose("cryptid is 0; skipping")
            return .skipped
        }

        try UnfairProcessPermissions.prepareForAppBundleDecryption(logger: logger)
        try unprotectRegion(fd: fd, fileOffset: output.slice.offset, sliceBase: output.sliceBase, sliceSize: output.slice.size, info: enc)
        try markDecrypted(sliceBase: output.sliceBase, commandOffset: enc.commandOffset)

        guard msync(mapped.base, mapped.size, MS_SYNC) == 0 else {
            throw UnfairError.io("sync failed: \(String(cString: strerror(errno)))")
        }
        logger.verbose("done - binary decrypted in-place")
        return .decrypted
    }

    private func decryptBinary(installedAt installedURL: URL, outputURL: URL) throws -> DecryptionStatus {
        logger.verbose("installed target: \(installedURL.path)")
        logger.verbose("output target: \(outputURL.path)")
        logger.verbose("opening installed binary (read-only)")

        let installedFD = open(installedURL.path, O_RDONLY)
        guard installedFD >= 0 else {
            throw UnfairError.io("open installed failed: \(String(cString: strerror(errno)))")
        }
        defer { close(installedFD) }

        logger.verbose("opening output binary (read-write)")
        let outputFD = open(outputURL.path, O_RDWR)
        guard outputFD >= 0 else {
            throw UnfairError.io("open output failed: \(String(cString: strerror(errno)))")
        }
        defer { close(outputFD) }

        let installedSize = try fileSize(fd: installedFD, label: "installed")
        let mappedOutput = try mapWritableBinary(fd: outputFD)
        defer { munmap(mappedOutput.base, mappedOutput.size) }
        guard mappedOutput.size == installedSize else {
            throw UnfairError.invalidMachO("installed and output binary sizes differ")
        }

        let output = try inspectMappedBinary(mappedOutput.base, fileSize: mappedOutput.size)
        guard let enc = output.encryptionInfo else {
            return .skipped
        }
        if enc.cryptid == 0 {
            logger.verbose("cryptid is 0; skipping")
            return .skipped
        }

        try UnfairProcessPermissions.prepareForAppBundleDecryption(logger: logger)
        try unprotectRegion(
            fd: installedFD,
            fileOffset: output.slice.offset,
            destinationSliceBase: output.sliceBase,
            sliceSize: output.slice.size,
            info: enc
        )
        try markDecrypted(sliceBase: output.sliceBase, commandOffset: enc.commandOffset)

        guard msync(mappedOutput.base, mappedOutput.size, MS_SYNC) == 0 else {
            throw UnfairError.io("sync output failed: \(String(cString: strerror(errno)))")
        }
        logger.verbose("done - binary decrypted to output")
        return .decrypted
    }

    private func fileSize(fd: Int32, label: String) throws -> Int {
        var statInfo = stat()
        guard fstat(fd, &statInfo) == 0 else {
            throw UnfairError.io("fstat \(label) failed: \(String(cString: strerror(errno)))")
        }
        let size = Int(statInfo.st_size)
        logger.verbose("\(label) file size: \(size) bytes")
        guard size > 0 else {
            throw UnfairError.invalidMachO("invalid \(label) file size")
        }
        return size
    }

    private func mapWritableBinary(fd: Int32) throws -> (base: UnsafeMutableRawPointer, size: Int) {
        let size = try fileSize(fd: fd, label: "mapped")
        guard let mapped = mmap(nil, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0),
              mapped != MAP_FAILED else {
            throw UnfairError.io("mmap failed: \(String(cString: strerror(errno)))")
        }
        return (mapped, size)
    }

    private func inspectMappedBinary(_ mapped: UnsafeMutableRawPointer, fileSize: Int) throws -> (slice: MachOSlice, sliceBase: UnsafeMutableRawPointer, encryptionInfo: EncryptionInfo?) {
        let rawBase = UnsafeRawPointer(mapped)
        let slice = try MachOInspector.selectArm64Slice(base: rawBase, size: fileSize, logger: logger)
        let sliceBase = mapped.advanced(by: slice.offset)
        let sliceRawBase = UnsafeRawPointer(sliceBase)

        let header = sliceRawBase.load(as: mach_header_64.self)
        logger.verbose("mach-o header: magic=0x\(String(header.magic, radix: 16))  ncmds=\(header.ncmds)  sizeofcmds=0x\(String(header.sizeofcmds, radix: 16))")

        guard let enc = try MachOInspector.findEncryptionInfo(base: sliceRawBase, size: slice.size) else {
            logger.verbose("warning: lc_encryption_info_64 not found")
            return (slice, sliceBase, nil)
        }
        logger.verbose("encryption info command: cmd_offset=0x\(String(enc.commandOffset, radix: 16))")

        guard MachOInspector.hasRange(size: slice.size, offset: Int(enc.cryptoff), length: Int(enc.cryptsize)) else {
            throw UnfairError.invalidMachO("invalid encrypted region")
        }
        return (slice, sliceBase, enc)
    }

    private func markDecrypted(sliceBase: UnsafeMutableRawPointer, commandOffset: Int) throws {
        let infoPointer = sliceBase.advanced(by: commandOffset).assumingMemoryBound(to: encryption_info_command_64.self)
        if infoPointer.pointee.cryptid != 0 {
            infoPointer.pointee.cryptid = 0
            logger.verbose("cryptid set to 0")
        }
    }

    private func unprotectRegion(fd: Int32, fileOffset: Int, sliceBase: UnsafeMutableRawPointer, sliceSize: Int, info: EncryptionInfo) throws {
        try unprotectRegion(fd: fd, fileOffset: fileOffset, destinationSliceBase: sliceBase, sliceSize: sliceSize, info: info)
    }

    private func unprotectRegion(fd: Int32, fileOffset: Int, destinationSliceBase: UnsafeMutableRawPointer, sliceSize: Int, info: EncryptionInfo) throws {
        if info.cryptsize == 0 {
            logger.verbose("encrypted region is empty")
            return
        }

        let encryptedOffset = fileOffset + Int(info.cryptoff)
        logger.verbose("decrypting: cryptid=\(info.cryptid)  cryptoff=0x\(String(info.cryptoff, radix: 16))  cryptsize=0x\(String(info.cryptsize, radix: 16))  fileoff=0x\(String(encryptedOffset, radix: 16))")

        try registerCodeSignature(fd: fd, fileOffset: fileOffset, sliceBase: UnsafeRawPointer(destinationSliceBase), sliceSize: sliceSize)

        let encryptedSize = Int(info.cryptsize)
        guard let encrypted = mmap(nil, encryptedSize, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, off_t(encryptedOffset)),
              encrypted != MAP_FAILED else {
            throw UnfairError.io("mmap encrypted region failed: \(String(cString: strerror(errno)))")
        }
        defer { munmap(encrypted, encryptedSize) }

        guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "mremap_encrypted") else {
            throw UnfairError.mremapUnavailable
        }
        let mremap = unsafeBitCast(symbol, to: MremapEncrypted.self)

        logger.verbose("calling mremap_encrypted (cpu=arm64, sub=all)")
        let result = mremap(encrypted, encryptedSize, info.cryptid, cpuTypeArm64, cpuSubtypeArm64All)
        guard result == 0 else {
            throw UnfairError.decryptFailed("mremap_encrypted failed: \(String(cString: strerror(errno)))")
        }

        logger.verbose("copying 0x\(String(info.cryptsize, radix: 16)) decrypted bytes back to base")
        memcpy(destinationSliceBase.advanced(by: Int(info.cryptoff)), encrypted, encryptedSize)
        logger.verbose("decrypt done")
    }

    private func registerCodeSignature(fd: Int32, fileOffset: Int, sliceBase: UnsafeRawPointer, sliceSize: Int) throws {
        guard let codeSignature = try MachOInspector.findCodeSignatureInfo(base: sliceBase, size: sliceSize) else {
            throw UnfairError.invalidMachO("code signature command missing")
        }

        var signatures = FileSignatures(
            fileStart: off_t(fileOffset),
            blobStart: UnsafeMutableRawPointer(bitPattern: Int(codeSignature.dataoff)),
            blobSize: Int(codeSignature.datasize)
        )

        logger.verbose("registering code signature: file_start=0x\(String(fileOffset, radix: 16))  blob=0x\(String(codeSignature.dataoff, radix: 16))  size=0x\(String(codeSignature.datasize, radix: 16))")
        let result = withUnsafeMutablePointer(to: &signatures) { pointer in
            fcntl(fd, addFileSignaturesReturn, pointer)
        }
        guard result == 0 else {
            throw UnfairError.io("F_ADDFILESIGS_RETURN failed: \(String(cString: strerror(errno)))")
        }
    }
}
