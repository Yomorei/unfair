// to be clear, this ONLY gives unfair the ability to select ARM64 or ARM32.

import Darwin
import Foundation
import MachO

struct MachORecord {
    var url: URL
    var displayPath: String
    var name: String
    var hasEncryptionInfo: Bool
    var cryptid: UInt32

    var isEncrypted: Bool {
        hasEncryptionInfo && cryptid == 1
    }
}

struct MachOSlice {
    var offset: Int
    var size: Int
}

struct EncryptionInfo {
    var commandOffset: Int
    var cryptoff: UInt32
    var cryptsize: UInt32
    var cryptid: UInt32
    var cpuType: UInt32
    var cpuSubtype: UInt32
}

struct MachOInspection {
    var hasEncryptionInfo: Bool
    var cryptid: UInt32
}

enum MachOInspector {
    private static let fatCigam = UInt32(FAT_CIGAM)
    private static let mhMagic = UInt32(MH_MAGIC)
    private static let mhMagic64 = UInt32(MH_MAGIC_64)
    private static let lcEncryptionInfo = UInt32(LC_ENCRYPTION_INFO)
    private static let lcEncryptionInfo64 = UInt32(LC_ENCRYPTION_INFO_64)
    private static let cpuTypeArm = UInt32(bitPattern: CPU_TYPE_ARM)
    private static let cpuTypeArm64 = UInt32(bitPattern: CPU_TYPE_ARM64)
    private static let cpuSubtypeMask = UInt32(CPU_SUBTYPE_MASK)
    private static let cpuSubtypeArm64All = UInt32(CPU_SUBTYPE_ARM64_ALL)

    static func scanBinaries(appURL: URL, label: String) throws -> [MachORecord] {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        guard let enumerator = FileManager.default.enumerator(
            at: appURL,
            includingPropertiesForKeys: keys,
            options: []
        ) else {
            throw UnfairError.io("opendir failed: \(appURL.path)")
        }

        var records: [MachORecord] = []
        for case let url as URL in enumerator {
            if let record = try autoreleasepool(invoking: { () throws -> MachORecord? in
                let values = try url.resourceValues(forKeys: Set(keys))
                guard values.isSymbolicLink != true,
                      values.isRegularFile == true else {
                    return nil
                }

                guard let inspection = try inspect(url: url) else {
                    return nil
                }

                let display = displayPath(for: url, appURL: appURL, label: label)
                return MachORecord(
                    url: url,
                    displayPath: display,
                    name: url.lastPathComponent,
                    hasEncryptionInfo: inspection.hasEncryptionInfo,
                    cryptid: inspection.cryptid
                )
            }) {
                records.append(record)
            }
        }

        return records
    }

    static func inspect(url: URL) throws -> MachOInspection? {
        let fd = open(url.path, O_RDONLY | O_CLOEXEC)
        guard fd >= 0 else {
            throw UnfairError.io(
                "open failed: \(url.path): \(String(cString: strerror(errno)))"
            )
        }
        defer { close(fd) }

        var magic: UInt32 = 0
        let magicRead = pread(fd, &magic, MemoryLayout<UInt32>.size, 0)
        guard magicRead == MemoryLayout<UInt32>.size,
              magic == fatCigam || magic == mhMagic || magic == mhMagic64 else {
            return nil
        }

        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress,
                  rawBuffer.count >= MemoryLayout<UInt32>.size else {
                return nil
            }

            guard let slice = try? selectSupportedSlice(
                base: base,
                size: rawBuffer.count,
                logger: nil
            ) else {
                return nil
            }

            guard let enc = try? findEncryptionInfo(
                base: base.advanced(by: slice.offset),
                size: slice.size
            ) else {
                return nil
            }

            return MachOInspection(
                hasEncryptionInfo: true,
                cryptid: enc.cryptid
            )
        }
    }

    static func selectSupportedSlice(
        base: UnsafeRawPointer,
        size: Int,
        logger: UnfairLogger?
    ) throws -> MachOSlice {
        guard hasRange(
            size: size,
            offset: 0,
            length: MemoryLayout<UInt32>.size
        ) else {
            throw UnfairError.invalidMachO("invalid Mach-O")
        }

        let magic = base.load(as: UInt32.self)

        if magic == mhMagic || magic == mhMagic64 {
            return MachOSlice(offset: 0, size: size)
        }

        guard magic == fatCigam,
              hasRange(
                  size: size,
                  offset: 0,
                  length: MemoryLayout<fat_header>.size
              ) else {
            throw UnfairError.invalidMachO("invalid Mach-O")
        }

        let header = base.load(as: fat_header.self)
        let archCount = Int(UInt32(bigEndian: header.nfat_arch))
        let tableSize = archCount * MemoryLayout<fat_arch>.size

        guard archCount > 0,
              tableSize / MemoryLayout<fat_arch>.size == archCount,
              hasRange(
                  size: size,
                  offset: MemoryLayout<fat_header>.size,
                  length: tableSize
              ) else {
            throw UnfairError.invalidMachO("invalid FAT arch table")
        }

        logger?.verbose("detected fat binary with \(archCount) arches")

        let arches = base.advanced(by: MemoryLayout<fat_header>.size)
        var armSlice: MachOSlice?

        for index in 0..<archCount {
            let arch = arches
                .advanced(by: index * MemoryLayout<fat_arch>.size)
                .load(as: fat_arch.self)

            let cpuType = UInt32(
                bigEndian: UInt32(bitPattern: arch.cputype)
            )
            let cpuSubtype = UInt32(
                bigEndian: UInt32(bitPattern: arch.cpusubtype)
            )
            let offset = Int(UInt32(bigEndian: arch.offset))
            let archSize = Int(UInt32(bigEndian: arch.size))

            logger?.verbose(
                "  arch[\(index)]: cputype=\(cpuType) cpusubtype=\(cpuSubtype) offset=\(offset) size=\(archSize)"
            )

            guard archSize > 0,
                  hasRange(
                      size: size,
                      offset: offset,
                      length: archSize
                  ) else {
                throw UnfairError.invalidMachO("invalid ARM slice")
            }

            if cpuType == cpuTypeArm64,
               isSupportedArm64Subtype(cpuSubtype) {
                logger?.verbose(
                    "  selected arm64 slice at offset 0x\(String(offset, radix: 16))"
                )
                return MachOSlice(offset: offset, size: archSize)
            }

            if cpuType == cpuTypeArm, armSlice == nil {
                armSlice = MachOSlice(offset: offset, size: archSize)
            }
        }

        if let armSlice {
            logger?.verbose(
                "  selected arm slice at offset 0x\(String(armSlice.offset, radix: 16))"
            )
            return armSlice
        }

        throw UnfairError.invalidMachO(
            "fat binary has no supported ARM slice"
        )
    }

    static func findEncryptionInfo(
        base: UnsafeRawPointer,
        size: Int
    ) throws -> EncryptionInfo? {
        guard hasRange(
            size: size,
            offset: 0,
            length: MemoryLayout<UInt32>.size
        ) else {
            throw UnfairError.invalidMachO("invalid Mach-O header")
        }

        let magic = base.load(as: UInt32.self)

        let headerSize: Int
        let commandCount: UInt32
        let commandBytes: UInt32
        let cpuType: UInt32
        let cpuSubtype: UInt32

        if magic == mhMagic64 {
            guard hasRange(
                size: size,
                offset: 0,
                length: MemoryLayout<mach_header_64>.size
            ) else {
                throw UnfairError.invalidMachO(
                    "invalid 64-bit Mach-O header"
                )
            }

            let header = base.load(as: mach_header_64.self)

            cpuType = UInt32(bitPattern: header.cputype)
            cpuSubtype = UInt32(bitPattern: header.cpusubtype)

            guard cpuType == cpuTypeArm64,
                  isSupportedArm64Subtype(cpuSubtype) else {
                throw UnfairError.invalidMachO(
                    "invalid 64-bit Mach-O header"
                )
            }

            headerSize = MemoryLayout<mach_header_64>.size
            commandCount = header.ncmds
            commandBytes = header.sizeofcmds
        } else if magic == mhMagic {
            guard hasRange(
                size: size,
                offset: 0,
                length: MemoryLayout<mach_header>.size
            ) else {
                throw UnfairError.invalidMachO(
                    "invalid 32-bit Mach-O header"
                )
            }

            let header = base.load(as: mach_header.self)

            cpuType = UInt32(bitPattern: header.cputype)
            cpuSubtype = UInt32(bitPattern: header.cpusubtype)

            guard cpuType == cpuTypeArm else {
                throw UnfairError.invalidMachO(
                    "invalid 32-bit Mach-O header"
                )
            }

            headerSize = MemoryLayout<mach_header>.size
            commandCount = header.ncmds
            commandBytes = header.sizeofcmds
        } else {
            throw UnfairError.invalidMachO("invalid Mach-O header")
        }

        guard hasRange(
            size: size,
            offset: headerSize,
            length: Int(commandBytes)
        ) else {
            throw UnfairError.invalidMachO(
                "invalid load command range"
            )
        }

        var commandOffset = headerSize

        for _ in 0..<commandCount {
            guard hasRange(
                size: size,
                offset: commandOffset,
                length: MemoryLayout<load_command>.size
            ) else {
                throw UnfairError.invalidMachO(
                    "invalid load command"
                )
            }

            let command = base
                .advanced(by: commandOffset)
                .load(as: load_command.self)

            guard command.cmdsize >= UInt32(
                MemoryLayout<load_command>.size
            ),
            hasRange(
                size: size,
                offset: commandOffset,
                length: Int(command.cmdsize)
            ) else {
                throw UnfairError.invalidMachO(
                    "invalid load command size"
                )
            }

            if command.cmd == lcEncryptionInfo ||
                command.cmd == lcEncryptionInfo64 {
                let minimumSize = command.cmd == lcEncryptionInfo64
                    ? MemoryLayout<encryption_info_command_64>.size
                    : MemoryLayout<encryption_info_command>.size

                guard command.cmdsize >= UInt32(minimumSize) else {
                    throw UnfairError.invalidMachO(
                        "invalid encryption command"
                    )
                }

                let info = base
                    .advanced(by: commandOffset)
                    .load(as: encryption_info_command.self)

                return EncryptionInfo(
                    commandOffset: commandOffset,
                    cryptoff: info.cryptoff,
                    cryptsize: info.cryptsize,
                    cryptid: info.cryptid,
                    cpuType: cpuType,
                    cpuSubtype: cpuSubtype
                )
            }

            commandOffset += Int(command.cmdsize)
        }

        return nil
    }

    static func hasRange(
        size: Int,
        offset: Int,
        length: Int
    ) -> Bool {
        offset >= 0 &&
            length >= 0 &&
            offset <= size &&
            length <= size - offset
    }

    private static func isSupportedArm64Subtype(
        _ subtype: UInt32
    ) -> Bool {
        let baseSubtype = subtype & ~cpuSubtypeMask
        return baseSubtype == cpuSubtypeArm64All ||
            baseSubtype == UInt32(CPU_SUBTYPE_ARM64E)
    }

    private static func displayPath(
        for url: URL,
        appURL: URL,
        label: String
    ) -> String {
        let roots = [
            appURL.standardizedFileURL.path,
            appURL.standardizedFileURL.resolvingSymlinksInPath().path,
        ]

        let paths = [
            url.standardizedFileURL.path,
            url.standardizedFileURL.resolvingSymlinksInPath().path,
        ]

        for root in roots {
            for path in paths
            where path == root || path.hasPrefix(root + "/") {
                return label + String(
                    path.dropFirst(root.count)
                )
            }
        }

        return url.path
    }
}
