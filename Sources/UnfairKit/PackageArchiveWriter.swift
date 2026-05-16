import Foundation
import ZIPFoundation

struct ArchiveReplacement {
    var path: String
    var url: URL
}

struct PackageArchiveWriter {
    var logger: UnfairLogger

    func writeArchive(input: URL, replacements: [ArchiveReplacement], to destination: URL) throws {
        try FileSystem.createDirectory(destination.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }

        let inputArchive = try Archive(url: input, accessMode: .read, pathEncoding: nil)
        let outputArchive = try Archive(url: destination, accessMode: .create, pathEncoding: nil)
        let replacementByPath = Dictionary(uniqueKeysWithValues: replacements.map { ($0.path, $0) })
        var replacedPaths = Set<String>()

        for entry in inputArchive {
            if entry.type == .symlink {
                logger.verbose("skipped symlink in output: \(entry.path)")
                continue
            }
            if ArchivePrivacyFilter.shouldRemoveEntry(path: entry.path) {
                logger.verbose("removed privacy-sensitive archive entry: \(entry.path)")
                continue
            }
            if let replacement = replacementByPath[entry.path] {
                try addReplacement(replacement, replacing: entry, to: outputArchive)
                replacedPaths.insert(entry.path)
                continue
            }

            try copyEntry(entry, from: inputArchive, to: outputArchive)
        }

        let missing = Set(replacementByPath.keys).subtracting(replacedPaths)
        guard missing.isEmpty else {
            throw UnfairError.io("archive entry missing: \(missing.sorted().joined(separator: ", "))")
        }
    }

    private func addReplacement(_ replacement: ArchiveReplacement, replacing entry: Entry, to archive: Archive) throws {
        let attributes = entry.fileAttributes
        let modificationDate = attributes[.modificationDate] as? Date ?? Date()
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? defaultFilePermissions
        let compressionMethod: CompressionMethod = entry.isCompressed ? .deflate : .none
        let fileSize = try FileSystem.fileSize(replacement.url)
        let handle = try FileHandle(forReadingFrom: replacement.url)
        defer { try? handle.close() }
        let provider: Provider = { position, size in
            try handle.seek(toOffset: UInt64(position))
            return handle.readData(ofLength: size)
        }

        try archive.addEntry(
            with: replacement.path,
            type: .file,
            uncompressedSize: fileSize,
            modificationDate: modificationDate,
            permissions: permissions,
            compressionMethod: compressionMethod,
            provider: provider
        )
    }

    private func copyEntry(_ entry: Entry, from inputArchive: Archive, to outputArchive: Archive) throws {
        let attributes = entry.fileAttributes
        let modificationDate = attributes[.modificationDate] as? Date ?? Date()
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.uint16Value ?? defaultPermissions(for: entry)
        let compressionMethod: CompressionMethod = entry.isCompressed ? .deflate : .none
        let data = try entryData(entry, from: inputArchive)

        try outputArchive.addEntry(
            with: entry.path,
            type: entry.type,
            uncompressedSize: Int64(data.count),
            modificationDate: modificationDate,
            permissions: permissions,
            compressionMethod: compressionMethod,
            provider: { position, size in
                let start = Int(position)
                let end = Swift.min(start + size, data.count)
                return data.subdata(in: start..<end)
            }
        )
    }

    private func entryData(_ entry: Entry, from archive: Archive) throws -> Data {
        guard entry.type == .file else {
            return Data()
        }

        var data = Data()
        _ = try archive.extract(entry) { chunk in
            data.append(chunk)
        }
        return data
    }

    private func defaultPermissions(for entry: Entry) -> UInt16 {
        entry.type == .directory ? defaultDirectoryPermissions : defaultFilePermissions
    }
}
