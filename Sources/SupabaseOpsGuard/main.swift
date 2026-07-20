import Darwin
import Foundation
import LocalAuthentication
import Security

private let service = "dev.supabase-ops-guard"

private enum CredentialName {
    static let projectURL = "project-url"
    static let serviceRoleKey = "service-role-key"
    static let databaseURL = "database-url"

    static let placeholders = [
        "{{project-url}}": projectURL,
        "{{service-role-key}}": serviceRoleKey,
        "{{database-url}}": databaseURL,
    ]
}

enum GuardError: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        }
    }
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("error: \(message)\n").utf8))
    exit(2)
}

func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    guard condition() else { throw GuardError.message(message) }
}

func validProfile(_ profile: String) -> Bool {
    profile.range(of: #"^[A-Za-z0-9_-]{1,64}$"#, options: .regularExpression) != nil
}

func authenticate(reason: String) throws -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        throw GuardError.message("macOS device-owner authentication is unavailable: \(error?.localizedDescription ?? "unknown error")")
    }

    let semaphore = DispatchSemaphore(value: 0)
    var result: Result<Void, Error> = .failure(GuardError.message("Authentication did not complete."))
    context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { success, authError in
        result = success ? .success(()) : .failure(authError ?? GuardError.message("Authentication was cancelled."))
        semaphore.signal()
    }
    semaphore.wait()
    try result.get()
    return context
}

func keychainAccount(profile: String, name: String) -> String {
    "profile:\(profile):\(name)"
}

func keychainQuery(profile: String, name: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: keychainAccount(profile: profile, name: name),
    ]
}

func saveSecret(_ value: String, profile: String, name: String) throws {
    let base = keychainQuery(profile: profile, name: name)
    let deleteStatus = SecItemDelete(base as CFDictionary)
    guard deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound else {
        throw GuardError.message("Could not replace Keychain item (status \(deleteStatus)).")
    }

    var insert = base
    insert[kSecValueData as String] = Data(value.utf8)
    let insertStatus = SecItemAdd(insert as CFDictionary, nil)
    guard insertStatus == errSecSuccess else {
        throw GuardError.message("Could not save Keychain item (status \(insertStatus)).")
    }
}

func hasSecret(profile: String, name: String) throws -> Bool {
    var query = keychainQuery(profile: profile, name: name)
    query[kSecReturnAttributes as String] = true
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw GuardError.message("Could not inspect Keychain item \(name) for profile \(profile) (status \(status)).")
    }
    return status == errSecSuccess
}

func loadSecret(profile: String, name: String, context: LAContext, reason: String) throws -> String {
    context.localizedReason = reason
    var query = keychainQuery(profile: profile, name: name)
    query[kSecReturnData as String] = true
    query[kSecUseAuthenticationContext as String] = context

    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
        throw GuardError.message("Could not read Keychain item \(name) for profile \(profile) (status \(status)).")
    }
    return value
}

func withEchoDisabled<T>(fileDescriptor: Int32 = STDIN_FILENO, _ body: () throws -> T) throws -> T {
    var original = termios()
    try require(tcgetattr(fileDescriptor, &original) == 0, "Could not read terminal settings for credential input.")

    var hidden = original
    hidden.c_lflag &= ~tcflag_t(ECHO)
    try require(tcsetattr(fileDescriptor, TCSANOW, &hidden) == 0, "Could not disable terminal echo for credential input.")

    let result: Result<T, Error>
    do {
        result = .success(try body())
    } catch {
        result = .failure(error)
    }

    try require(tcsetattr(fileDescriptor, TCSANOW, &original) == 0, "Could not restore terminal echo after credential input.")
    return try result.get()
}

func promptValue(_ label: String, optional: Bool = false, hidden: Bool = false) throws -> String? {
    try require(isatty(STDIN_FILENO) != 0, "Credential setup must run in an interactive terminal.")
    let hint = hidden ? " (input hidden; paste and press Return)" : ""
    FileHandle.standardError.write(Data("\(label)\(hint): ".utf8))

    let value: String
    if hidden {
        defer { FileHandle.standardError.write(Data("\n".utf8)) }
        value = try withEchoDisabled { readLine() ?? "" }
    } else {
        value = readLine() ?? ""
    }

    if value.isEmpty && optional { return nil }
    try require(!value.isEmpty, "\(label) cannot be empty.")
    return value
}

func normalizeProjectURL(_ value: String) -> String {
    value
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
}

func validateProjectURL(_ value: String) throws {
    guard let url = URL(string: value), url.scheme == "https", let host = url.host,
          host.hasSuffix(".supabase.co"), (url.path.isEmpty || url.path == "/"),
          url.query == nil, url.fragment == nil, url.user == nil, url.password == nil else {
        throw GuardError.message("Project URL must be an https://<project-ref>.supabase.co URL.")
    }
}

func setup(profile: String) throws {
    try require(validProfile(profile), "Invalid profile name.")
    _ = try authenticate(reason: "Set guarded credentials for profile '\(profile)'.")

    let hasProjectURL = try hasSecret(profile: profile, name: CredentialName.projectURL)
    let hasServiceRoleKey = try hasSecret(profile: profile, name: CredentialName.serviceRoleKey)
    let hasDatabaseURL = try hasSecret(profile: profile, name: CredentialName.databaseURL)

    let projectURL = try promptValue(
        hasProjectURL ? "Supabase project URL (press Return to keep existing)" : "Supabase project URL",
        optional: hasProjectURL
    )
    if let projectURL {
        let normalizedProjectURL = normalizeProjectURL(projectURL)
        try validateProjectURL(normalizedProjectURL)
        try saveSecret(normalizedProjectURL, profile: profile, name: CredentialName.projectURL)
    }

    let serviceRoleKey = try promptValue(
        hasServiceRoleKey ? "Supabase service-role key (press Return to keep existing)" : "Supabase service-role key",
        optional: hasServiceRoleKey,
        hidden: true
    )
    if let serviceRoleKey {
        try saveSecret(serviceRoleKey, profile: profile, name: CredentialName.serviceRoleKey)
    }

    let databaseURL = try promptValue(
        hasDatabaseURL ? "Database URL (press Return to keep existing)" : "Database URL (optional)",
        optional: true,
        hidden: true
    )
    if let databaseURL {
        try saveSecret(databaseURL, profile: profile, name: CredentialName.databaseURL)
    }
    print("Credentials confirmed in the macOS Keychain.")
}

func displayArgument(_ argument: String) -> String {
    if CredentialName.placeholders[argument] != nil { return argument }
    if argument.range(of: #"^[A-Za-z0-9_./:=@,+-]+$"#, options: .regularExpression) != nil {
        return argument
    }
    return "'" + argument.replacingOccurrences(of: "'", with: "'\\''") + "'"
}

final class HardDenialPolicy {
    static let shared = HardDenialPolicy()

    // Add executables here when they can conceal a permanently forbidden
    // operation from the command shown in the approval prompt.
    private let forbiddenExecutables: Set<String> = [
        "bash", "dash", "deno", "env", "fish", "ksh", "node", "osascript",
        "perl", "pgcli", "php", "psql", "python", "python3", "ruby", "sh", "zsh",
    ]

    // These arguments are forbidden whenever the Supabase CLI is the approved
    // executable, regardless of argument ordering or flags.
    private let forbiddenSupabaseArguments: Set<String> = ["reset"]

    // Add direct database-destruction forms here. Matching is performed after
    // SQL comments are removed and before any approval prompt is shown.
    private let forbiddenSQLPatterns = [
        #"\bDROP\s+(TABLE|SCHEMA|DATABASE)\b"#,
        #"\bTRUNCATE\b"#,
    ]

    private let readOnlySupabaseCommands: Set<[String]> = [
        ["status"],
        ["migration", "list"],
        ["functions", "list"],
        ["projects", "list"],
        ["db", "diff"],
        ["inspect", "db"],
        ["gen", "types"],
    ]

    func validate(command: [String]) throws {
        let executable = executableName(command)
        try require(
            !forbiddenExecutables.contains(executable),
            "Shells, interpreters, and direct SQL clients are permanently unavailable through the guard."
        )

        if executable == "supabase" {
            let arguments = Set(command.dropFirst().map { $0.lowercased() })
            try require(
                arguments.isDisjoint(with: forbiddenSupabaseArguments),
                "Supabase database reset is permanently forbidden through the guard."
            )
        }

        let inspected = textForSQLInspection(command)
        for pattern in forbiddenSQLPatterns {
            try require(
                inspected.range(of: pattern, options: [.regularExpression, .caseInsensitive]) == nil,
                "Database or table destruction is permanently forbidden through the guard."
            )
        }
    }

    func isReadOnly(command: [String]) -> Bool {
        let executable = executableName(command)
        guard executable == "supabase" else { return true }

        let arguments = command.dropFirst().map { $0.lowercased() }
        return readOnlySupabaseCommands.contains { prefix in
            arguments.starts(with: prefix)
        }
    }

    private func executableName(_ command: [String]) -> String {
        URL(fileURLWithPath: command[0]).lastPathComponent.lowercased()
    }

    private func textForSQLInspection(_ command: [String]) -> String {
        let joined = command.joined(separator: " ")
        let withoutBlockComments = joined.replacingOccurrences(
            of: #"/\*[\s\S]*?\*/"#,
            with: " ",
            options: .regularExpression
        )
        return withoutBlockComments.replacingOccurrences(
            of: #"--[^\r\n]*"#,
            with: " ",
            options: .regularExpression
        )
    }
}

func expandedArguments(_ arguments: [String], profile: String, context: LAContext?) throws -> [String] {
    try arguments.map { argument in
        if let credential = CredentialName.placeholders[argument] {
            guard let context else {
                throw GuardError.message("Read-only commands cannot request Keychain credentials.")
            }
            return try loadSecret(
                profile: profile,
                name: credential,
                context: context,
                reason: "Release \(credential) for approved command"
            )
        }
        try require(!argument.contains("{{") && !argument.contains("}}"),
                    "Unknown or embedded credential placeholder: \(argument)")
        return argument
    }
}

func executeApproved(profile: String, workingDirectoryPath: String, command: [String]) throws {
    try require(validProfile(profile), "Invalid profile name.")
    try require(!command.isEmpty, "A command is required after --.")
    try HardDenialPolicy.shared.validate(command: command)

    let workingDirectory = URL(fileURLWithPath: workingDirectoryPath).standardizedFileURL
    var isDirectory: ObjCBool = false
    try require(
        FileManager.default.fileExists(atPath: workingDirectory.path, isDirectory: &isDirectory) && isDirectory.boolValue,
        "Working directory must be an existing directory."
    )

    let renderedCommand = command.map(displayArgument).joined(separator: " ")
    let context: LAContext?
    if HardDenialPolicy.shared.isReadOnly(command: command) {
        FileHandle.standardOutput.write(Data(("Read-only command allowed\nCommand: \(renderedCommand)\n").utf8))
        context = nil
    } else {
        let request = "Working directory: \(workingDirectory.path)\nCommand: \(renderedCommand)"
        FileHandle.standardOutput.write(Data(("Approval requested\n\(request)\n").utf8))
        context = try authenticate(reason: "Approve guarded command for profile '\(profile)': \(renderedCommand)")
    }

    let expanded = try expandedArguments(command, profile: profile, context: context)

    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = expanded
    process.currentDirectoryURL = workingDirectory
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw GuardError.message("Approved command failed with exit status \(process.terminationStatus).")
    }
}

func usage() {
    print("""
    Usage:
      supabase-ops-guard setup <profile>
      supabase-ops-guard exec <profile> <working-directory> -- <command> [arguments...]

    Credential placeholders (exact arguments only):
      {{project-url}}
      {{service-role-key}}
      {{database-url}}

    The guard does not interpret commands or provider workflows. It displays the exact request,
    requires macOS device-owner authentication, substitutes requested Keychain credentials, and executes it.
    """)
}

func main(_ arguments: [String]) throws {
    guard let command = arguments.first else { usage(); return }
    switch command {
    case "help", "--help", "-h":
        usage()
    case "setup":
        try require(arguments.count == 2, "Usage: setup <profile>")
        try setup(profile: arguments[1])
    case "exec":
        try require(arguments.count >= 5, "Usage: exec <profile> <working-directory> -- <command> [arguments...]")
        try require(arguments[3] == "--", "Expected -- before the command.")
        try executeApproved(
            profile: arguments[1],
            workingDirectoryPath: arguments[2],
            command: Array(arguments.dropFirst(4))
        )
    default:
        throw GuardError.message("Unknown command: \(command)")
    }
}

do {
    try main(Array(CommandLine.arguments.dropFirst()))
} catch {
    fail(error.localizedDescription)
}
