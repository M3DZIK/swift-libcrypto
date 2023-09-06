import Foundation

public class Salt {
    // The byte array of the salt
    public let bytes: Data

    /// Initializes a new `Salt` object with the provided bytes array
    ///
    /// - Parameter length: The length of the salt to generate
    /// - Returns: The `Salt` object containing the generated salt
    public init(bytes: Data) {
        self.bytes = bytes
    }

    /// Initializes a new `Salt` object with a random salt
    ///
    /// - Parameter length: The length of the salt to generate
    /// - Returns: The `Salt` object containing the generated salt
    public static func generate(length: Int = 16) -> Salt {
        let bytes = Array((0..<length).map { _ in UInt8.random(in: 0...255) })
        return Salt(bytes: Data(bytes))
    }
}
