import Foundation
import XCTest

final class SourcePolicyTests: XCTestCase {
    func testIOSDecryptionDoesNotUseIPAInstallationCommands() throws {
        let root = try repositoryRoot()
        let sourcePaths = [
            "Sources/UnfairKit/PackageProcessor.swift",
            "Sources/UnfairKit/FileSystem.swift",
            "Sources/UnfairSupport/UnfairSupport.c",
            "Sources/UnfairSupport/include/UnfairSupport.h",
            "global.xml",
        ]
        let bannedTerms = [
            "appinst",
            "uicache",
            "mobileinstall",
            "uninstall",
            "installIPA",
            "installableIPA",
            "MinimumOSVersion",
            "unfair_run_executable",
        ]

        for sourcePath in sourcePaths {
            let source = try String(contentsOf: root.appendingPathComponent(sourcePath), encoding: .utf8)
            for term in bannedTerms {
                XCTAssertFalse(source.contains(term), "\(sourcePath) contains \(term)")
            }
        }
    }

    private func repositoryRoot() throws -> URL {
        var url = URL(fileURLWithPath: #filePath)
        while url.path != "/" {
            url.deleteLastPathComponent()
            if FileManager.default.fileExists(atPath: url.appendingPathComponent("Package.swift").path) {
                return url
            }
        }
        throw NSError(domain: "SourcePolicyTests", code: 1)
    }
}
