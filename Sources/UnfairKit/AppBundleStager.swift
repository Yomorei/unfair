import Darwin
import Foundation

#if os(iOS)
struct StagedAppBundle {
    var containerURL: URL
    var appURL: URL
}

struct StagedBinary {
    var bundle: StagedAppBundle
    var binaryURL: URL
    var rootSinf: URL
}

enum AppBundleStager {
    private static let applicationBundleRoot = URL(fileURLWithPath: "/var/containers/Bundle/Application", isDirectory: true)

    static func isInsideApplicationBundleRoot(_ url: URL) -> Bool {
        let paths = [
            url.standardizedFileURL.path,
            url.standardizedFileURL.resolvingSymlinksInPath().path,
        ]
        let root = applicationBundleRoot.standardizedFileURL.path
        return paths.contains { path in
            path == root || path.hasPrefix(root + "/")
        }
    }

    static func stageBinary(_ binaryURL: URL, rootSinf: URL, logger: UnfairLogger) throws -> StagedBinary {
        let appName = binaryURL.lastPathComponent + ".app"
        let bundle = try createBundle(appName: appName, logger: logger)
        let stagedBinary = bundle.appURL.appendingPathComponent(binaryURL.lastPathComponent)
        try copyFile(binaryURL, to: stagedBinary)
        try FileSystem.chmod(stagedBinary, mode: 0o755)

        let stagedSinf = try copyCredentials(
            from: rootSinf.deletingLastPathComponent(),
            explicitRootSinf: rootSinf,
            binaryName: binaryURL.lastPathComponent,
            to: bundle.appURL
        )

        return StagedBinary(bundle: bundle, binaryURL: stagedBinary, rootSinf: stagedSinf)
    }

    static func stageAppBundle(sourceApp: URL, encryptedRecords: [MachORecord], logger: UnfairLogger) throws -> StagedAppBundle {
        let bundle = try createBundle(appName: sourceApp.lastPathComponent, logger: logger)
        let scInfo = sourceApp.appendingPathComponent("SC_Info", isDirectory: true)
        try copyCredentials(from: scInfo, explicitRootSinf: nil, binaryName: nil, to: bundle.appURL)

        for record in encryptedRecords {
            let relativePath = try relativePath(of: record.url, in: sourceApp)
            let destination = bundle.appURL.appendingPathComponent(relativePath)
            try copyFile(record.url, to: destination)
            try FileSystem.chmod(destination, mode: 0o755)
        }

        return bundle
    }

    static func cleanup(_ bundle: StagedAppBundle) {
        FileSystem.removeTree(bundle.containerURL)
    }

    private static func createBundle(appName: String, logger: UnfairLogger) throws -> StagedAppBundle {
        let container = applicationBundleRoot.appendingPathComponent("UNFAIR-\(UUID().uuidString)", isDirectory: true)
        let app = container.appendingPathComponent(appName, isDirectory: true)
        try FileSystem.createDirectory(app)
        logger.log("staged app: \(app.path)")
        return StagedAppBundle(containerURL: container, appURL: app)
    }

    @discardableResult
    private static func copyCredentials(from sourceSCInfo: URL, explicitRootSinf: URL?, binaryName: String?, to appURL: URL) throws -> URL {
        let destinationSCInfo = appURL.appendingPathComponent("SC_Info", isDirectory: true)
        try FileSystem.createDirectory(destinationSCInfo)

        if let children = try? FileManager.default.contentsOfDirectory(
            at: sourceSCInfo,
            includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]
        ) {
            for child in children {
                let values = try child.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
                guard values.isRegularFile == true, values.isSymbolicLink != true else {
                    continue
                }
                guard shouldCopyCredential(child.lastPathComponent, binaryName: binaryName) else {
                    continue
                }
                try copyFile(child, to: destinationSCInfo.appendingPathComponent(child.lastPathComponent))
            }
        }

        if let explicitRootSinf {
            let stagedRootSinf = destinationSCInfo.appendingPathComponent((binaryName ?? explicitRootSinf.deletingPathExtension().lastPathComponent) + ".sinf")
            if FileManager.default.fileExists(atPath: stagedRootSinf.path) == false {
                try copyFile(explicitRootSinf, to: stagedRootSinf)
            }
            return stagedRootSinf
        }

        if let binaryName {
            return destinationSCInfo.appendingPathComponent(binaryName + ".sinf")
        }
        return destinationSCInfo
    }

    private static func shouldCopyCredential(_ name: String, binaryName: String?) -> Bool {
        guard let binaryName else {
            return true
        }
        return name == "Manifest.plist" || name.hasPrefix(binaryName + ".")
    }

    private static func copyFile(_ source: URL, to destination: URL) throws {
        try FileSystem.createDirectory(destination.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.copyItem(at: source, to: destination)
    }

    private static func relativePath(of child: URL, in root: URL) throws -> String {
        let rootPath = root.standardizedFileURL.path + "/"
        let childPath = child.standardizedFileURL.path
        guard childPath.hasPrefix(rootPath) else {
            throw UnfairError.io("path is outside app bundle: \(child.path)")
        }
        return String(childPath.dropFirst(rootPath.count))
    }
}
#endif
