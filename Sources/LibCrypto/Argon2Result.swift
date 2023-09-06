import Foundation

public class Argon2Result {
    let hashBytes: [UInt8]
    let encodedHashBytes: [UInt8]

    public init(hashBytes: [Int8], encodedHashBytes: [Int8]) {
        // Convert to UInt8 arrays and set
        self.hashBytes = hashBytes.map { UInt8(bitPattern: $0) }
        self.encodedHashBytes = encodedHashBytes.map{ UInt8(bitPattern: $0) }
    }

    public func hexString() -> String {
        return hashBytes.map{ String(format: "%02hhx", $0) }.joined()
    }

    public func encodedString() -> String {
        return String(data: Data(encodedHashBytes), encoding: .utf8)!
    }
}
