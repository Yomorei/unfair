enum ArchivePrivacyFilter {
    static func shouldRemoveEntry(path: String) -> Bool {
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard components.count >= 3 else {
            return false
        }

        return components[0] == "Payload"
            && components[1].hasSuffix(".app")
            && components[2] == "SC_Info"
    }
}
