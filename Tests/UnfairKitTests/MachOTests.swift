import Foundation
import MachO
@testable import UnfairKit
import XCTest

final class MachOTests: XCTestCase {
    func testArmV7EncryptionInfo() throws {
        var header = mach_header()
        header.magic = UInt32(MH_MAGIC)
        header.cputype = CPU_TYPE_ARM
        header.cpusubtype = CPU_SUBTYPE_ARM_V7
        header.filetype = UInt32(MH_EXECUTE)
        header.ncmds = 1
        header.sizeofcmds = UInt32(
            MemoryLayout<encryption_info_command>.size
        )

        var encryption = encryption_info_command()
        encryption.cmd = UInt32(LC_ENCRYPTION_INFO)
        encryption.cmdsize = UInt32(
            MemoryLayout<encryption_info_command>.size
        )
        encryption.cryptoff = 0x4000
        encryption.cryptsize = 0x15A8000
        encryption.cryptid = 1

        var data = Data()

        withUnsafeBytes(of: &header) {
            data.append(contentsOf: $0)
        }

        withUnsafeBytes(of: &encryption) {
            data.append(contentsOf: $0)
        }

        let info = try data.withUnsafeBytes { rawBuffer -> EncryptionInfo? in
            guard let base = rawBuffer.baseAddress else {
                return nil
            }

            let slice = try MachOInspector.selectSupportedSlice(
                base: base,
                size: rawBuffer.count,
                logger: nil
            )

            return try MachOInspector.findEncryptionInfo(
                base: base.advanced(by: slice.offset),
                size: slice.size
            )
        }

        let encryptionInfo = try XCTUnwrap(info)

        XCTAssertEqual(encryptionInfo.cryptoff, 0x4000)
        XCTAssertEqual(encryptionInfo.cryptsize, 0x15A8000)
        XCTAssertEqual(encryptionInfo.cryptid, 1)
        XCTAssertEqual(
            encryptionInfo.cpuType,
            UInt32(bitPattern: CPU_TYPE_ARM)
        )
        XCTAssertEqual(
            encryptionInfo.cpuSubtype,
            UInt32(bitPattern: CPU_SUBTYPE_ARM_V7)
        )
    }
}
