import Foundation
import enum Crypto.Curve25519
import struct Crypto.SymmetricKey
import struct Crypto.SHA256

public class Curve25519 {
    /// Generates a new Curve25519 key pair
    ///
    /// - Returns: `Curve25519KeyPair` that contains the private and public key
    public static func generateKeyPair() -> Curve25519KeyPair {
        let privateKey = Crypto.Curve25519.KeyAgreement.PrivateKey()
        return Curve25519KeyPair(
            publicKey: privateKey.publicKey.rawRepresentation,
            privateKey: privateKey.rawRepresentation
        )
    }

    /// Returns a Curve25519 key pair with the given private key
    ///
    /// - Parameter privateKey: The private key
    ///
    /// - Throws: When the private key is invalid
    ///
    /// - Returns: `Curve25519KeyPair` that contains the private and public key
    public static func fromPrivateKey(privateKey: String) throws -> Curve25519KeyPair {
        let privateKeyBytes = try Hex.fromHexString(privateKey)
        let privateKey = try Crypto.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyBytes)
        return Curve25519KeyPair(
            publicKey: privateKey.publicKey.rawRepresentation,
            privateKey: privateKey.rawRepresentation
        )
    }

    /// Computes a shared secret given our private key and their public key
    ///
    /// - Parameters:
    ///   - ourPrivate: Our private key
    ///   - theirPublic: Their public key
    ///
    /// - Throws: When out private or their public key is invalid
    ///
    /// - Returns: `SymmetricKey`
    public static func computeSharedSecret(ourPrivate: String, theirPublic: String) throws -> SymmetricKey {
        let ourPrivateBytes = try Hex.fromHexString(ourPrivate)
        let theirPublicBytes = try Hex.fromHexString(theirPublic)

        let ourPrivate = try Crypto.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: ourPrivateBytes)
        let theirPublic = try Crypto.Curve25519.KeyAgreement.PublicKey(rawRepresentation: theirPublicBytes)

        let sharedSecret = try ourPrivate.sharedSecretFromKeyAgreement(with: theirPublic)

        return sharedSecret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
    }
}
