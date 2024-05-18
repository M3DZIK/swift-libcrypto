import XCTest
@testable import LibCrypto
@testable import Crypto

final class UnwrapTest: XCTest {
    func testSymmetricKey() throws {
        let data = X25519.generateKeyPair().privateKey.data(using: .utf8)!
        let symmetricKey = SymmetricKey(data: data)
        XCTAssert(Data(symmetricKey: symmetricKey).elementsEqual(data))
    }
}
