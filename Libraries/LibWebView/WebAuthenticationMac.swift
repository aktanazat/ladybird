/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

import CryptoKit
import Foundation
import LocalAuthentication
import Security

private enum PasskeyResult: UInt8 {
    case success
    case authenticationFailed
    case keyOperationFailed
}

typealias PasskeyCompletion = @convention(c) (
    UnsafeMutableRawPointer?, UInt8,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int,
    UnsafePointer<UInt8>?, Int
) -> Void

private final class PasskeyOperation: @unchecked Sendable {
    let authentication = LAContext()
    let create: Bool
    let keyData: Data
    let message: Data
    let destination: UnsafeMutableRawPointer?
    let completion: PasskeyCompletion

    init(create: Bool, keyData: Data, message: Data, destination: UnsafeMutableRawPointer?, completion: PasskeyCompletion) {
        self.create = create
        self.keyData = keyData
        self.message = message
        self.destination = destination
        self.completion = completion
    }

    func run(reason: String) {
        authentication.localizedReason = reason
        authentication.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { [self] allowed, _ in
            guard allowed else {
                finish(.authenticationFailed)
                return
            }

            do {
                if create {
                    guard let access = SecAccessControlCreateWithFlags(
                        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil
                    ) else {
                        finish(.keyOperationFailed)
                        return
                    }
                    let key = try SecureEnclave.P256.Signing.PrivateKey(
                        compactRepresentable: false, accessControl: access, authenticationContext: authentication
                    )
                    finish(.success, key.dataRepresentation, key.publicKey.x963Representation, key.publicKey.derRepresentation)
                } else {
                    let key = try SecureEnclave.P256.Signing.PrivateKey(
                        dataRepresentation: keyData, authenticationContext: authentication
                    )
                    finish(.success, try key.signature(for: message).derRepresentation)
                }
            } catch {
                finish(.keyOperationFailed)
            }
        }
    }

    private func finish(_ result: PasskeyResult, _ first: Data = Data(), _ second: Data = Data(), _ third: Data = Data()) {
        first.withUnsafeBytes { firstBytes in
            second.withUnsafeBytes { secondBytes in
                third.withUnsafeBytes { thirdBytes in
                    completion(destination, result.rawValue,
                        firstBytes.bindMemory(to: UInt8.self).baseAddress, first.count,
                        secondBytes.bindMemory(to: UInt8.self).baseAddress, second.count,
                        thirdBytes.bindMemory(to: UInt8.self).baseAddress, third.count)
                }
            }
        }
    }
}

@_cdecl("ladybird_webauthn_mac_available")
func passkeysAvailable() -> Bool {
    SecureEnclave.isAvailable && LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil)
}

private func copyBytes(_ pointer: UnsafePointer<UInt8>?, _ count: Int) -> Data {
    guard let pointer, count > 0 else { return Data() }
    return Data(bytes: pointer, count: count)
}

@_cdecl("ladybird_webauthn_mac_start")
func startPasskey(
    _ create: Bool,
    _ reason: UnsafePointer<UInt8>?, _ reasonLength: Int,
    _ key: UnsafePointer<UInt8>?, _ keyLength: Int,
    _ message: UnsafePointer<UInt8>?, _ messageLength: Int,
    _ destination: UnsafeMutableRawPointer?, _ completion: @escaping PasskeyCompletion
) -> UnsafeMutableRawPointer {
    let operation = PasskeyOperation(create: create, keyData: copyBytes(key, keyLength),
        message: copyBytes(message, messageLength), destination: destination, completion: completion)
    let operationHandle = Unmanaged.passRetained(operation)
    operation.run(reason: String(decoding: copyBytes(reason, reasonLength), as: UTF8.self))
    return operationHandle.toOpaque()
}

@_cdecl("ladybird_webauthn_mac_cancel")
func cancelPasskey(_ operation: UnsafeMutableRawPointer) {
    Unmanaged<PasskeyOperation>.fromOpaque(operation).takeUnretainedValue().authentication.invalidate()
}

@_cdecl("ladybird_webauthn_mac_release")
func releasePasskey(_ operation: UnsafeMutableRawPointer) {
    Unmanaged<PasskeyOperation>.fromOpaque(operation).release()
}
