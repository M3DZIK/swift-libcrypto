import XCTest
@testable import LibCrypto

final class Argon2Tests: XCTestCase {
    func hashExample() throws {
        let argon2 = Argon2(parallelism: 1, memory: 65536, iterations: 1, hashLength: 32)

        let result = try! argon2.hashPasswordString(password: "secret password", salt:  Salt.generate(length: 16))

        XCTAssert(try! Argon2.verifyHashString(password: "secret password", hash: result.encodedString(), type: .id))
    }

    func validHashExample() throws {
        let hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ"
        XCTAssert(try! Argon2.verifyHashString(password: "medzik@duck.com", hash: hash, type: .id))
    }
}
