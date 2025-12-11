import Foundation
import Security

enum AuthPolicy: String {
    case none = "none"
    case presence = "presence"
    case strong = "strong"
}

enum KageError: Int, Error {
    case success = 0
    case keyNotFound = 1
    case authFailed = 2
    case authNotEnrolled = 3
    case cryptoFailed = 4
    case invalidInput = 5
    case backendUnavailable = 6
}

func checkSEAvailable() -> Bool {
    // Basic check if Secure Enclave is available (usually implied by presence of API, but can check IsSecureEnclaveKey attribute support)
    // For now, assume yes if we are on macOS running this.
    return true
}

func deleteKey(label: String) throws {
    let tag = "com.kage.keys.\(label)".data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
        throw KageError.cryptoFailed
    }
}


func createKeyInternal(label: String, accessControl: SecAccessControl, useSE: Bool) throws -> SecKey {
    let tag = "com.kage.keys.\(label)".data(using: .utf8)!
    
    let privateKeyAttrs: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrAccessControl as String: accessControl,
        kSecAttrApplicationTag as String: tag,
    ]
    
    var attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: privateKeyAttrs
    ]
    
    if useSE {
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
    }
    
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        if let e = error?.takeRetainedValue() {
             // Debug log
             let desc = CFErrorCopyDescription(e)
             fputs("Debug: SecKeyCreateRandomKey (SE=\(useSE)) failed: \(desc as String? ?? "Unknown")\n", stderr)
             
             // If we failed with SE, rethrow to allow fallback.
             // If we failed without SE, we should probably fail.
             throw e
        }
        throw KageError.cryptoFailed
    }
    
    return key
}

func getOrCreateKey(label: String, policy: AuthPolicy) throws -> SecKey {
    let tag = "com.kage.keys.\(label)".data(using: .utf8)!
    
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tag,
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecReturnRef as String: true
    ]
    
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    
    if status == errSecSuccess {
        return (item as! SecKey)
    }
    
    // Create new key
    var accessControlError: Unmanaged<CFError>?
    var flags: SecAccessControlCreateFlags
    
    switch policy {
    case .none:
        flags = [] // No user presence required
    case .presence:
        flags = [.userPresence]
    case .strong:
        flags = [.biometryCurrentSet] // Invalidated if bio changes
    }
    
    let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &accessControlError
    )
    
    guard let accessControl = access else {
        throw KageError.cryptoFailed
    }
    
    // Try SE first
    do {
        return try createKeyInternal(label: label, accessControl: accessControl, useSE: true)
    } catch {
        let nsError = error as NSError
        // Check for missing entitlement (-34018) or unsupported (-25293)
        if nsError.code == -34018 || nsError.code == -25293 {
            // Fallback to software key
            // fputs("Warning: Secure Enclave unavailable, falling back to software keychain key.\n", stderr)
            return try createKeyInternal(label: label, accessControl: accessControl, useSE: false)
        }
        throw KageError.cryptoFailed
    }
}

func encrypt(label: String, policy: AuthPolicy) throws {
    let key = try getOrCreateKey(label: label, policy: policy)
    guard let publicKey = SecKeyCopyPublicKey(key) else {
        throw KageError.cryptoFailed
    }
    
    let inputData = FileHandle.standardInput.readDataToEndOfFile()
    guard !inputData.isEmpty else { throw KageError.invalidInput }
    
    var error: Unmanaged<CFError>?
    // ECIES encryption with SE key
    guard let ciphertext = SecKeyCreateEncryptedData(
        publicKey,
        .eciesEncryptionStandardX963SHA256AESGCM,
        inputData as CFData,
        &error
    ) else {
        throw KageError.cryptoFailed
    }
    
    FileHandle.standardOutput.write(ciphertext as Data)
}

func decrypt(label: String, policy: AuthPolicy) throws {
    // Decrypt requires private key, which might trigger auth
    let key = try getOrCreateKey(label: label, policy: policy)
    
    let inputData = FileHandle.standardInput.readDataToEndOfFile()
    guard !inputData.isEmpty else { throw KageError.invalidInput }
    
    var error: Unmanaged<CFError>?
    guard let plaintext = SecKeyCreateDecryptedData(
        key,
        .eciesEncryptionStandardX963SHA256AESGCM,
        inputData as CFData,
        &error
    ) else {
        if let e = error?.takeRetainedValue() {
            let code = CFErrorGetCode(e)
            if code == errSecUserCanceled || code == errSecAuthFailed {
                throw KageError.authFailed
            }
        }
        throw KageError.cryptoFailed
    }
    
    FileHandle.standardOutput.write(plaintext as Data)
}

