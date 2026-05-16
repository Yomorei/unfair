import Darwin
import Foundation
import ZIPFoundation

public final class PackageProcessor {
    private let logger: UnfairLogger
    private let installedAppRoot = URL(fileURLWithPath: "/var/containers/Bundle/Application", isDirectory: true)

    public init(logger: UnfairLogger = UnfairLogger()) {
        self.logger = logger
    }

    public func process(input: URL, output: URL, workingDirectory providedWorkingDirectory: URL? = nil) throws {
        let workingDirectory = try prepareWorkingDirectory(providedWorkingDirectory, preserving: input)
        defer { FileSystem.removeTree(workingDirectory) }

        logger.verbose("temp dir: \(workingDirectory.path)")
        try extractIPA(input, to: workingDirectory)

        let payloadURL = try payloadDirectory(in: workingDirectory)
        logger.log("payload: payload")
        FileSystem.clearExtendedAttributesRecursively(at: workingDirectory)

        #if os(iOS)
        try processInstalledPackage(input: input, output: output, workingDirectory: workingDirectory, payloadURL: payloadURL)
        #else
        var decryptedRecords: [MachORecord] = []
        for app in try appBundles(in: payloadURL) {
            decryptedRecords.append(contentsOf: try processAppBundle(app))
        }

        let destination = destinationPath(input: input, output: output)
        let archiveOutput = workingDirectory.appendingPathComponent("output.ipa")
        try writeArchive(input: input, decryptedRecords: decryptedRecords, to: archiveOutput)
        try copyArchive(archiveOutput, to: destination)
        logger.log("output: \(destination.path)")
        #endif
    }

    private func writeArchive(input: URL, decryptedRecords: [MachORecord], to destination: URL) throws {
        let replacements = decryptedRecords.map { record in
            ArchiveReplacement(
                path: "Payload/" + record.displayPath,
                url: record.url
            )
        }
        let writer = PackageArchiveWriter(logger: logger)
        try writer.writeArchive(input: input, replacements: replacements, to: destination)
    }

    #if os(iOS)
    private struct AppBundleMetadata {
        var bundleID: String
        var executable: String
        var bundleName: String
        var minimumOSVersion: String?
        var infoPlist: URL
    }

    private func processInstalledPackage(input: URL, output: URL, workingDirectory: URL, payloadURL: URL) throws {
        let sourceApps = try appBundles(in: payloadURL)
        guard sourceApps.count == 1, let sourceApp = sourceApps.first else {
            throw UnfairError.io("iOS package mode expects one Payload/*.app bundle")
        }

        let metadata = try appBundleMetadata(sourceApp)
        try UnfairProcessPermissions.prepareForAppBundleDecryption(logger: logger)
        let installInput = try installableIPA(input: input, metadata: metadata, workingDirectory: workingDirectory)
        try installIPA(installInput, bundleID: metadata.bundleID)

        let installedApp = try findInstalledApp(metadata)
        defer { cleanupInstalledApp(installedApp, bundleID: metadata.bundleID) }

        var decryptedRecords: [MachORecord] = []
        decryptedRecords.append(contentsOf: try processAppBundle(installedApp))

        let destination = destinationPath(input: input, output: output)
        let archiveOutput = workingDirectory.appendingPathComponent("output.ipa")
        try writeArchive(input: input, decryptedRecords: decryptedRecords, to: archiveOutput)
        try copyArchive(archiveOutput, to: destination)
        logger.log("output: \(destination.path)")
    }

    private func appBundleMetadata(_ appURL: URL) throws -> AppBundleMetadata {
        let infoPlist = appURL.appendingPathComponent("Info.plist")
        guard let info = NSDictionary(contentsOf: infoPlist) as? [String: Any] else {
            throw UnfairError.io("failed to read Info.plist: \(infoPlist.path)")
        }
        guard let bundleID = info["CFBundleIdentifier"] as? String, bundleID.isEmpty == false else {
            throw UnfairError.io("CFBundleIdentifier missing: \(infoPlist.path)")
        }
        guard let executable = info["CFBundleExecutable"] as? String, executable.isEmpty == false else {
            throw UnfairError.io("CFBundleExecutable missing: \(infoPlist.path)")
        }
        return AppBundleMetadata(
            bundleID: bundleID,
            executable: executable,
            bundleName: appURL.lastPathComponent,
            minimumOSVersion: info["MinimumOSVersion"] as? String,
            infoPlist: infoPlist
        )
    }

    private func installableIPA(input: URL, metadata: AppBundleMetadata, workingDirectory: URL) throws -> URL {
        let installInput = workingDirectory.appendingPathComponent("install.ipa")
        try copyArchive(input, to: installInput)

        guard let minimumOSVersion = metadata.minimumOSVersion,
              minimumOSVersionExceedsCurrentDevice(minimumOSVersion) else {
            return installInput
        }

        let patchedMinimumOSVersion = currentDeviceMinimumOSVersion()
        logger.log("patching MinimumOSVersion for install: \(minimumOSVersion) -> \(patchedMinimumOSVersion)")

        guard let info = NSMutableDictionary(contentsOf: metadata.infoPlist) else {
            throw UnfairError.io("failed to patch Info.plist: \(metadata.infoPlist.path)")
        }
        info["MinimumOSVersion"] = patchedMinimumOSVersion
        guard info.write(to: metadata.infoPlist, atomically: true) else {
            throw UnfairError.io("failed to write patched Info.plist: \(metadata.infoPlist.path)")
        }

        let archive = try Archive(url: installInput, accessMode: .update, pathEncoding: nil)
        try replaceArchiveEntry(
            path: "Payload/\(metadata.bundleName)/Info.plist",
            with: metadata.infoPlist,
            in: archive
        )
        return installInput
    }

    private func replaceArchiveEntry(path: String, with source: URL, in archive: Archive) throws {
        guard let entry = archive[path] else {
            throw UnfairError.io("archive entry missing: \(path)")
        }
        let attributes = entry.fileAttributes
        let modificationDate = attributes[.modificationDate] as? Date ?? Date()
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? defaultFilePermissions
        let compressionMethod: CompressionMethod = entry.isCompressed ? .deflate : .none
        let fileSize = try FileSystem.fileSize(source)
        let handle = try FileHandle(forReadingFrom: source)
        defer { try? handle.close() }
        let provider: Provider = { position, size in
            try handle.seek(toOffset: UInt64(position))
            return handle.readData(ofLength: size)
        }

        try archive.remove(entry)
        try archive.addEntry(
            with: path,
            type: .file,
            uncompressedSize: fileSize,
            modificationDate: modificationDate,
            permissions: permissions,
            compressionMethod: compressionMethod,
            provider: provider
        )
    }

    private func minimumOSVersionExceedsCurrentDevice(_ value: String) -> Bool {
        let requested = OperatingSystemVersion(unfairVersionString: value)
        let current = ProcessInfo.processInfo.operatingSystemVersion
        return compareOperatingSystemVersions(requested, current) == .orderedDescending
    }

    private func currentDeviceMinimumOSVersion() -> String {
        let current = ProcessInfo.processInfo.operatingSystemVersion
        return "\(current.majorVersion).0"
    }

    private func compareOperatingSystemVersions(_ left: OperatingSystemVersion, _ right: OperatingSystemVersion) -> ComparisonResult {
        let leftParts = [left.majorVersion, left.minorVersion, left.patchVersion]
        let rightParts = [right.majorVersion, right.minorVersion, right.patchVersion]
        for index in 0..<leftParts.count {
            if leftParts[index] < rightParts[index] {
                return .orderedAscending
            }
            if leftParts[index] > rightParts[index] {
                return .orderedDescending
            }
        }
        return .orderedSame
    }

    private func installIPA(_ input: URL, bundleID: String) throws {
        let appinst = try existingExecutable([
            "/var/jb/usr/bin/appinst",
            "/usr/bin/appinst",
            "/bin/appinst",
        ])
        logger.log("installing: \(bundleID)")
        let result = try FileSystem.runExecutable(appinst, arguments: [input.path])
        guard result.status == 0 else {
            throw UnfairError.io("appinst failed (\(result.status)): \(result.output)")
        }
    }

    private func findInstalledApp(_ metadata: AppBundleMetadata) throws -> URL {
        let children = try FileManager.default.contentsOfDirectory(at: installedAppRoot, includingPropertiesForKeys: [.isDirectoryKey])
        var matches: [URL] = []
        for container in children {
            let app = container.appendingPathComponent(metadata.bundleName, isDirectory: true)
            guard FileManager.default.fileExists(atPath: app.path) else {
                continue
            }
            guard let installed = try? appBundleMetadata(app), installed.bundleID == metadata.bundleID else {
                continue
            }
            matches.append(app)
        }
        guard let match = matches.sorted(by: { $0.path < $1.path }).last else {
            throw UnfairError.io("installed app not found: \(metadata.bundleID)")
        }
        logger.log("installed app: \(match.path)")
        return match
    }

    private func cleanupInstalledApp(_ appURL: URL, bundleID: String) {
        logger.log("cleaning installed app: \(bundleID)")
        if let uicache = try? existingExecutable(["/var/jb/usr/bin/uicache", "/usr/bin/uicache", "/bin/uicache"]) {
            _ = try? FileSystem.runExecutable(uicache, arguments: ["-u", appURL.path])
        }
        try? FileManager.default.removeItem(at: appURL.deletingLastPathComponent())
    }

    private func existingExecutable(_ paths: [String]) throws -> String {
        for path in paths where access(path, X_OK) == 0 {
            return path
        }
        throw UnfairError.io("required executable missing: \(paths.joined(separator: ", "))")
    }
    #endif

    private func processAppBundle(_ appURL: URL) throws -> [MachORecord] {
        let label = appURL.lastPathComponent
        logger.log("app: \(label)")

        let records = try MachOInspector.scanBinaries(appURL: appURL, label: label)
        let encryptedRecords = records.filter(\.isEncrypted)
        logScan(records, encryptedRecords: encryptedRecords)

        guard let rootSinf = findRootSinf(appURL: appURL, records: records) else {
            throw UnfairError.missingRootSinf
        }

        try decrypt(records: encryptedRecords, rootSinf: rootSinf)
        try verifyDecryptedBinaries(in: appURL, label: label)
        return encryptedRecords
    }

    private func logScan(_ records: [MachORecord], encryptedRecords: [MachORecord]) {
        logger.log("mach-o binaries scanned: \(records.count)")
        for record in encryptedRecords {
            logger.verbose("encrypted mach-o: \(record.displayPath)")
        }
        logger.log("encrypted binaries found: \(encryptedRecords.count)")
    }

    private func decrypt(records: [MachORecord], rootSinf: URL) throws {
        let decryptor = BinaryDecryptor(logger: logger)
        let previousDirectory = FileManager.default.currentDirectoryPath
        defer { FileManager.default.changeCurrentDirectoryPath(previousDirectory) }

        for record in records {
            let binaryDir = record.url.deletingLastPathComponent()
            try validateDecryptableLocation(record.url, label: "binary")
            logger.verbose("cwd: \(binaryDir.path)")
            FileManager.default.changeCurrentDirectoryPath(binaryDir.path)
            try decryptor.decryptBinary(
                at: URL(fileURLWithPath: record.name),
                rootSinf: rootSinf,
                displayPath: record.displayPath
            )
        }
    }

    private func verifyDecryptedBinaries(in appURL: URL, label: String) throws {
        let records = try MachOInspector.scanBinaries(appURL: appURL, label: label)
        let remaining = records.filter(\.isEncrypted)
        guard remaining.isEmpty else {
            logRemainingEncryptedBinaries(remaining)
            throw UnfairError.panic("encrypted binaries remain")
        }
    }

    private func logRemainingEncryptedBinaries(_ records: [MachORecord]) {
        logger.log("panic: \(records.count) encrypted binaries still have cryptid 1")
        for record in records {
            logger.log("encrypted mach-o: \(record.displayPath)")
        }
    }

    private func extractIPA(_ input: URL, to tempDir: URL) throws {
        let archive = try Archive(url: input, accessMode: .read, pathEncoding: nil)
        for entry in archive {
            if entry.type == .symlink {
                logger.verbose("skipped symlink on extract: \(entry.path)")
                continue
            }

            let entryURL = tempDir.appendingPathComponent(entry.path)
            guard isContained(entryURL, in: tempDir) else {
                throw UnfairError.io("archive entry escapes extraction directory: \(entry.path)")
            }

            _ = try archive.extract(entry, to: entryURL)
        }
    }

    private func payloadDirectory(in root: URL) throws -> URL {
        guard let payloadURL = findPayload(in: root) else {
            throw UnfairError.io("ERROR: Payload directory missing after extract")
        }
        return payloadURL
    }

    private func findPayload(in root: URL) -> URL? {
        if (try? root.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true {
            return nil
        }

        let candidate = root.appendingPathComponent("Payload", isDirectory: true)
        let candidateValues = try? candidate.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        if candidateValues?.isSymbolicLink != true, candidateValues?.isDirectory == true {
            return candidate
        }

        guard let children = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey]) else {
            return nil
        }
        for child in children {
            if let found = findPayload(in: child) {
                return found
            }
        }
        return nil
    }

    private func appBundles(in payloadURL: URL) throws -> [URL] {
        let children = try FileManager.default.contentsOfDirectory(at: payloadURL, includingPropertiesForKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        let apps = try children.filter { url in
            guard url.pathExtension == "app" else {
                return false
            }
            let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
            return values.isSymbolicLink != true && values.isDirectory == true
        }
        guard apps.isEmpty == false else {
            throw UnfairError.io("ERROR: no Payload/*.app directory found")
        }
        return apps
    }

    private func findRootSinf(appURL: URL, records: [MachORecord]) -> URL? {
        for record in records where record.isEncrypted {
            guard record.url.deletingLastPathComponent().standardizedFileURL == appURL.standardizedFileURL else {
                continue
            }
            let source = appURL
                .appendingPathComponent("SC_Info", isDirectory: true)
                .appendingPathComponent(record.name + ".sinf")
            if FileManager.default.fileExists(atPath: source.path) {
                return source
            }
        }
        return nil
    }

    private func destinationPath(input: URL, output: URL) -> URL {
        var isDirectory: ObjCBool = false
        if FileManager.default.fileExists(atPath: output.path, isDirectory: &isDirectory), isDirectory.boolValue {
            let name = input.deletingPathExtension().lastPathComponent + ".unfair.ipa"
            return output.appendingPathComponent(name)
        }
        return output
    }

    private func copyArchive(_ source: URL, to destination: URL) throws {
        try FileSystem.createDirectory(destination.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.copyItem(at: source, to: destination)
    }

    private func prepareWorkingDirectory(_ providedWorkingDirectory: URL?, preserving input: URL) throws -> URL {
        if let providedWorkingDirectory = providedWorkingDirectory {
            let directory = providedWorkingDirectory.standardizedFileURL
            try validateXRootLocation(directory, label: "working directory")
            try FileSystem.createDirectory(directory)
            try removeWorkingDirectoryContents(in: directory, preserving: input.standardizedFileURL)
            return directory
        }
        return try createWorkingDirectory()
    }

    private func removeWorkingDirectoryContents(in directory: URL, preserving input: URL) throws {
        let children = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        )
        for child in children {
            if FileSystem.sameFile(child, input) {
                continue
            }
            try FileManager.default.removeItem(at: child)
        }
    }

    private func createWorkingDirectory() throws -> URL {
        let tmpDir = ProcessInfo.processInfo.environment["TMPDIR"] ?? NSTemporaryDirectory()
        let root = URL(fileURLWithPath: tmpDir, isDirectory: true)
            .deletingLastPathComponent()
            .appendingPathComponent("X", isDirectory: true)
            .appendingPathComponent("unfair", isDirectory: true)
        try FileSystem.createDirectory(root)
        let dir = root.appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
        try FileSystem.createDirectory(dir)
        return dir.standardizedFileURL
    }

    private func validateXRootLocation(_ url: URL, label: String) throws {
        let paths = [
            url.standardizedFileURL.path,
            url.standardizedFileURL.resolvingSymlinksInPath().path,
        ]
        guard paths.contains(where: isInsideRequiredXRoot) else {
            throw UnfairError.io("\(label) must be inside /var/folders/bg/<token>/X: \(url.path)")
        }
    }

    private func validateDecryptableLocation(_ url: URL, label: String) throws {
        let paths = [
            url.standardizedFileURL.path,
            url.standardizedFileURL.resolvingSymlinksInPath().path,
        ]
        #if os(iOS)
        guard paths.contains(where: isInsideInstalledApplicationRoot) || paths.contains(where: isInsideRequiredXRoot) else {
            throw UnfairError.io("\(label) must be inside /var/containers/Bundle/Application or /var/folders/bg/<token>/X: \(url.path)")
        }
        #else
        guard paths.contains(where: isInsideRequiredXRoot) else {
            throw UnfairError.io("\(label) must be inside /var/folders/bg/<token>/X: \(url.path)")
        }
        #endif
    }

    private func isInsideRequiredXRoot(_ path: String) -> Bool {
        var components = URL(fileURLWithPath: path).standardizedFileURL.pathComponents
        if components.count > 1, components[1] == "private" {
            components.remove(at: 1)
        }
        guard components.count > 6 else {
            return false
        }
        return components[0] == "/"
            && components[1] == "var"
            && components[2] == "folders"
            && components[3] == "bg"
            && components[5] == "X"
    }

    private func isInsideInstalledApplicationRoot(_ path: String) -> Bool {
        let standardized = URL(fileURLWithPath: path).standardizedFileURL.path
        let root = installedAppRoot.standardizedFileURL.path
        return standardized == root || standardized.hasPrefix(root + "/")
    }

    private func isContained(_ url: URL, in root: URL) -> Bool {
        let path = url.standardizedFileURL.path
        let rootPath = root.standardizedFileURL.path
        return path == rootPath || path.hasPrefix(rootPath + "/")
    }
}

private extension OperatingSystemVersion {
    init(unfairVersionString value: String) {
        let parts = value.split(separator: ".").map { Int($0) ?? 0 }
        self.init(
            majorVersion: parts.indices.contains(0) ? parts[0] : 0,
            minorVersion: parts.indices.contains(1) ? parts[1] : 0,
            patchVersion: parts.indices.contains(2) ? parts[2] : 0
        )
    }
}
