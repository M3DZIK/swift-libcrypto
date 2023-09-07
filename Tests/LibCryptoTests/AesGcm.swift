import XCTest
@testable import LibCrypto

final class AesGcmTests: XCTestCase {
    func testEncryptionDecryption() {
        let data = "Hello World!"

        let aliceKeys = Curve25519.generateKeyPair()
        let bobKeys = Curve25519.generateKeyPair()

        let aliceSharedSecret = try! Curve25519.computeSharedSecret(ourPrivate: aliceKeys.privateKey, theirPublic: bobKeys.publicKey)
        let cipherText = try! AesGcm.encrypt(data, key: aliceSharedSecret)

        let bobSharedSecret = try! Curve25519.computeSharedSecret(ourPrivate: bobKeys.privateKey, theirPublic: aliceKeys.publicKey)
        let decryptedText = try! AesGcm.decrypt(cipherText, key: bobSharedSecret)

        XCTAssertEqual(decryptedText, data)
    }
}
