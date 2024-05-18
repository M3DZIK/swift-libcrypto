import Foundation

public class X25519KeyPair {
    public let publicKey: String
    public let privateKey: String

    init(publicKey: String, privateKey: String) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    init(publicKey: Data, privateKey: Data) {
        self.publicKey = Hex.toHexString(publicKey)
        self.privateKey = Hex.toHexString(privateKey)
    }
}
