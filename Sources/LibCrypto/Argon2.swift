import Foundation
import argon2

/// Argon2 implementation
public class Argon2 {
    let parallelism: Int
    let memory: Int
    let iterations: Int
    let hashLength: Int
    let type: Argon2Type
    let version: Argon2Version

    /// Initializes a new instance
    ///
    /// - Parameters:
    ///   - parallelism The number of parallelism threads to use for hash computation
    ///   - memory The amount of memory to use when hashing, in KiB
    ///   - iterations The number of iterations
    ///   - hashLength The length of the output hash
    ///   - type The type of argon2
    public init(parallelism: Int = 1, memory: Int = 65536, iterations: Int = 3, hashLength: Int = 32, type: Argon2Type = Argon2Type.id, version: Argon2Version = Argon2Version.V13) {
        self.parallelism = parallelism
        self.memory = memory
        self.iterations = iterations
        self.hashLength = hashLength
        self.type = type
        self.version = version
    }

    /// Hashes a given `String` password
    ///
    /// - Parameters:
    ///   - password The `String` password to hash
    ///   - salt The `Salt` to use for hashing operation
    ///
    /// - Throws: `Argon2Exception` if the hashing fails in any way
    ///
    /// - Returns: `Argon2Result` that containing the hash
    public func hashPasswordString(password: String, salt: Salt) throws -> Argon2Result {
        try hashPasswordBytes(password: Data(password.utf8), salt: salt)
    }

    /// Hashes a given `Data` password
    ///
    /// - Parameters:
    ///   - password The `Data` password to hash
    ///   - salt The `Salt` to use for hashing operation
    ///
    /// - Throws: `Argon2Exception` if the hashing fails in any way
    ///
    /// - Returns: `Argon2Result` that containing the hash
    public func hashPasswordBytes(password: Data, salt: Salt) throws -> Argon2Result {
        // get length of encoded password
        let encodedLength = argon2_encodedlen(
            UInt32(iterations),
            UInt32(memory),
            UInt32(parallelism),
            UInt32(salt.bytes.count),
            UInt32(hashLength),
            Argon2.getArgon2Type(type: type)
        )

        // Allocate memory for hash
        let hash = allocPtr(length: hashLength)
        let encodedHash = allocPtr(length: encodedLength)

        defer {
            freePtr(pointer: hash, length: hashLength)
            freePtr(pointer: encodedHash, length: encodedLength)
        }

        // Perform the hash operation
        let errorCode = argon2_hash(
            UInt32(iterations),
            UInt32(memory),
            UInt32(parallelism),
            [UInt8](password),
            password.count,
            [UInt8](salt.bytes),
            salt.bytes.count,
            hash,
            hashLength,
            encodedHash,
            encodedLength,
            Argon2.getArgon2Type(type: type),
            UInt32(version.rawValue)
        )

        // Check if there were any errors
        if (errorCode != 0) {
            let errorMessage = String(cString: argon2_error_message(errorCode))
            throw Argon2Exception(message: errorMessage, errorCode: errorCode)
        }

        // Copy the arrays
        let hashArray = Array(UnsafeBufferPointer(start: hash, count: hashLength))
        let encodedHashArray = Array(UnsafeBufferPointer(start: encodedHash, count: encodedLength))

        return Argon2Result(hashBytes: hashArray, encodedHashBytes: encodedHashArray)
    }

    public static func verifyHashString(password: String, hash: String, type: Argon2Type = .id) throws -> Bool {
        return try verifyHashBytes(password: Data(password.utf8), hash: Data(hash.utf8), type: type)
    }

    public static func verifyHashBytes(password: Data, hash: Data, type: Argon2Type = .id) throws -> Bool {
        let encodedString = String(data: hash, encoding: .utf8)?.cString(using: .utf8)
        let result = argon2_verify(encodedString, [UInt8](password), password.count, getArgon2Type(type: type))
        if result != 0 /* OK */ && result != -35 /* Verification mismatch */ {
            let errorMessage = String(cString: argon2_error_message(result))
            throw Argon2Exception(message: errorMessage, errorCode: result)
        }
        // Return if it's verified or not
        return result == 0
    }

    /// A method that maps the `Argon2Type` Swift enum to the `Argon2_type` C struct
    static func getArgon2Type(type: Argon2Type) -> Argon2_type {
        if (type == .i) {
            return Argon2_i
        } else if (type == .d) {
            return Argon2_d
        } else {
            return Argon2_id
        }
    }

    /// Create and allocate a pointer with the given length
    func allocPtr(length: Int) -> UnsafeMutablePointer<Int8> {
        return UnsafeMutablePointer<Int8>.allocate(capacity: length)
    }

    /// Deinitialize and deallocate a pointer of the given length
    func freePtr(pointer: UnsafeMutablePointer<Int8>, length: Int) {
        pointer.deinitialize(count: length)
        pointer.deallocate()
    }
}
