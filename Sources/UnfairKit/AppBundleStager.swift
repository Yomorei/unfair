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
        try createDirectoryTree(app)
        logger.log("staged app: \(app.path)")
        return StagedAppBundle(containerURL: container, appURL: app)
    }

    @discardableResult
    private static func copyCredentials(from sourceSCInfo: URL, explicitRootSinf: URL?, binaryName: String?, to appURL: URL) throws -> URL {
        let destinationSCInfo = appURL.appendingPathComponent("SC_Info", isDirectory: true)
        try createDirectoryTree(destinationSCInfo)

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
        try createDirectoryTree(destination.deletingLastPathComponent())
        if unlink(destination.path) != 0 && errno != ENOENT {
            throw UnfairError.io("unlink failed: \(destination.path): \(String(cString: strerror(errno)))")
        }

        let sourceFD = open(source.path, O_RDONLY)
        guard sourceFD >= 0 else {
            throw UnfairError.io("open source failed: \(source.path): \(String(cString: strerror(errno)))")
        }
        defer { close(sourceFD) }

        var statInfo = stat()
        guard fstat(sourceFD, &statInfo) == 0 else {
            throw UnfairError.io("fstat source failed: \(source.path): \(String(cString: strerror(errno)))")
        }

        let mode = statInfo.st_mode & 0o777
        let destinationFD = open(destination.path, O_WRONLY | O_CREAT | O_EXCL, mode)
        guard destinationFD >= 0 else {
            throw UnfairError.io("open destination failed: \(destination.path): \(String(cString: strerror(errno)))")
        }
        defer { close(destinationFD) }

        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let readCount = buffer.withUnsafeMutableBytes { rawBuffer in
                read(sourceFD, rawBuffer.baseAddress, rawBuffer.count)
            }
            guard readCount >= 0 else {
                throw UnfairError.io("read failed: \(source.path): \(String(cString: strerror(errno)))")
            }
            if readCount == 0 {
                break
            }

            var written = 0
            while written < readCount {
                let writeCount = buffer.withUnsafeBytes { rawBuffer in
                    write(destinationFD, rawBuffer.baseAddress!.advanced(by: written), readCount - written)
                }
                guard writeCount > 0 else {
                    throw UnfairError.io("write failed: \(destination.path): \(String(cString: strerror(errno)))")
                }
                written += writeCount
            }
        }

        guard fchmod(destinationFD, mode) == 0 else {
            throw UnfairError.io("fchmod failed: \(destination.path): \(String(cString: strerror(errno)))")
        }
    }

    private static func createDirectoryTree(_ url: URL) throws {
        let path = url.standardizedFileURL.path
        if path == "/" || path.isEmpty {
            return
        }

        var statInfo = stat()
        if stat(path, &statInfo) == 0 {
            guard (statInfo.st_mode & S_IFMT) == S_IFDIR else {
                throw UnfairError.io("path exists and is not a directory: \(path)")
            }
            return
        }
        guard errno == ENOENT else {
            throw UnfairError.io("stat failed: \(path): \(String(cString: strerror(errno)))")
        }

        let parent = url.deletingLastPathComponent()
        if parent.path != url.path {
            try createDirectoryTree(parent)
        }

        if mkdir(path, 0o755) != 0 && errno != EEXIST {
            throw UnfairError.io("mkdir failed: \(path): \(String(cString: strerror(errno)))")
        }
        guard Darwin.chmod(path, 0o755) == 0 else {
            throw UnfairError.io("chmod failed: \(path): \(String(cString: strerror(errno)))")
        }
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
