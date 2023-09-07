import XCTest
@testable import LibCrypto

final class Argon2Tests: XCTestCase {
    func testHash() {
        let argon2 = Argon2(parallelism: 1, memory: 65536, iterations: 1, hashLength: 32)
        let result = try! argon2.hashPasswordString(password: "secret password", salt: Salt.generate(length: 16))

        XCTAssert(try! Argon2.verifyHashString(password: "secret password", hash: result.encodedString(), type: .id))
    }

    func testCheckReproducible() {
        let password = "secret password"
        let salt = Salt.generate(length: 16)

        let argon2 = Argon2()
        let hash = try! argon2.hashPasswordString(password: password, salt: salt)

        let argon2_2 = Argon2()
        let hash_2 = try! argon2_2.hashPasswordString(password: password, salt: salt)

        XCTAssertEqual(hash.encodedHashBytes, hash_2.encodedHashBytes)
    }

    func testValidHash() throws {
        let hash = "$argon2id$v=19$m=15360,t=2,p=1$bWVkemlrQGR1Y2suY29t$n7wCfzdczbjclMnpvw+t/4D+mCcCFUU+hm6Z85k81PQ"
        XCTAssert(try! Argon2.verifyHashString(password: "medzik@duck.com", hash: hash, type: .id))
    }

    func testToHex() {
        let password = "secret password"
        let salt = Salt.generate(length: 16)

        let argon2 = Argon2(hashLength: 16)
        let hash = try! argon2.hashPasswordString(password: password, salt: salt)

        let hexHash = hash.hexString()

        XCTAssertEqual(32, hexHash.count)
    }
}
