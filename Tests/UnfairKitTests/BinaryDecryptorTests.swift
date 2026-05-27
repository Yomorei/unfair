import Foundation
@testable import UnfairKit
import XCTest

final class BinaryDecryptorTests: XCTestCase {
    func testInstallTemporarySinfKeepsExistingBinarySinf() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let rootSinf = root.appendingPathComponent("Root.sinf")
        try Data("root".utf8).write(to: rootSinf)

        let framework = root.appendingPathComponent("FirebaseCore.framework", isDirectory: true)
        let scInfo = framework.appendingPathComponent("SC_Info", isDirectory: true)
        try FileManager.default.createDirectory(at: scInfo, withIntermediateDirectories: true)

        let binary = framework.appendingPathComponent("FirebaseCore")
        try Data().write(to: binary)

        let existingSinf = scInfo.appendingPathComponent("FirebaseCore.sinf")
        try Data("framework".utf8).write(to: existingSinf)

        let previousDirectory = FileManager.default.currentDirectoryPath
        defer { FileManager.default.changeCurrentDirectoryPath(previousDirectory) }
        FileManager.default.changeCurrentDirectoryPath(framework.path)

        let decryptor = BinaryDecryptor()
        let temporarySinf = try decryptor.installTemporarySinf(
            for: URL(fileURLWithPath: binary.lastPathComponent),
            rootSinf: rootSinf
        )

        XCTAssertNil(temporarySinf)
        XCTAssertEqual(try Data(contentsOf: existingSinf), Data("framework".utf8))
    }
}
