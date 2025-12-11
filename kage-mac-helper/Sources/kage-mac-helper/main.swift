import Foundation

let args = CommandLine.arguments
guard args.count >= 2 else { exit(Int32(KageError.invalidInput.rawValue)) }
let command = args[1]

var policy: AuthPolicy = .none
if let idx = args.firstIndex(of: "--policy"), idx + 1 < args.count {
    if let p = AuthPolicy(rawValue: args[idx+1]) { policy = p }
}

let label = args.count > 2 && !args[2].starts(with: "-") ? args[2] : "default"

do {
    switch command {
    case "check":
        // checkSEAvailable currently returns true, but we could make it probe.
        // For now, if getOrCreateKey works (with fallback), we are good.
        if checkSEAvailable() { exit(Int32(KageError.success.rawValue)) } else { exit(Int32(KageError.backendUnavailable.rawValue)) }
    case "init-key":
        let _ = try getOrCreateKey(label: label, policy: policy)
        exit(Int32(KageError.success.rawValue))
    case "encrypt":
        try encrypt(label: label, policy: policy)
        exit(Int32(KageError.success.rawValue))
    case "decrypt":
        try decrypt(label: label, policy: policy)
        exit(Int32(KageError.success.rawValue))
    case "delete-key":
        try deleteKey(label: label)
        exit(Int32(KageError.success.rawValue))
    default:
        exit(Int32(KageError.invalidInput.rawValue))
    }
} catch let error as KageError {
    exit(Int32(error.rawValue))
} catch let error as NSError {
    switch error.code {
    case Int(errSecUserCanceled), Int(errSecAuthFailed):
        exit(Int32(KageError.authFailed.rawValue))
    case Int(errSecItemNotFound):
        exit(Int32(KageError.keyNotFound.rawValue))
    default:
        // fputs("Unexpected error: \(error.localizedDescription)\n", stderr)
        exit(Int32(KageError.cryptoFailed.rawValue))
    }
}

