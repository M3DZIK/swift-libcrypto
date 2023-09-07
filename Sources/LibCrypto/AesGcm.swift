import Foundation
import struct Crypto.SymmetricKey
import enum Crypto.AES

public class AesGcm {
    /// Encrypts the given text using AES GCM with the given key and random IV.
    ///
    /// - Parameters:
    ///   - data: The text to encrypt
    ///   - key: The key to use for encryption
    ///
    /// - Throws: When an error occurs while encrypting the text
    ///
    /// - Returns: The cipher text (hex encoded)
    public static func encrypt(_ data: String, key: SymmetricKey) throws -> String {
        let dataBytes = Data(data.utf8)

        let sealedBox = try AES.GCM.seal(dataBytes, using: key, nonce: AES.GCM.Nonce())
        return Hex.toHexString(sealedBox.combined!)
    }

    /// Decrypts the given text using AES GCM with the given key
    ///
    /// - Parameters:
    ///   - hex: The cipher text to decrypt
    ///   - key: The key to use for decryption
    ///
    /// - Throws: When an error occurs while encrypting the text
    ///
    /// - Returns: The decrypted text
    public static func decrypt(_ hex: String, key: SymmetricKey) throws -> String {
        let dataBytes = try Hex.fromHexString(hex)

        let sealedBox = try! AES.GCM.SealedBox(combined: dataBytes)
        let clearTestBytes = try AES.GCM.open(sealedBox, using: key)
        return String(decoding: clearTestBytes, as: UTF8.self)
    }
}
