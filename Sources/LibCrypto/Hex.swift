import Foundation

public class Hex {
    /// Encode bytes array to hex string
    public static func toHexString(_ bytes: Data) -> String {
        return bytes.map{ String(format: "%02hhx", $0) }.joined()
    }

    /// Decode hex string to bytes array
    public static func fromHexString(_ hex: String) throws -> Data {
        guard hex.count.isMultiple(of: 2) else {
            throw HexException()
        }

        let chars = hex.map { $0 }
        let bytes = stride(from: 0, to: chars.count, by: 2)
            .map { String(chars[$0]) + String(chars[$0 + 1]) }
            .compactMap { UInt8($0, radix: 16) }

        guard hex.count / bytes.count == 2 else { throw HexException() }

        return Data(bytes)
    }
}
