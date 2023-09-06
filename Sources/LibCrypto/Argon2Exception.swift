public class Argon2Exception: Error {
    public let message: String
    public let errorCode: Argon2ErrorCode

    init(message: String, errorCode: Argon2ErrorCode) {
        self.message = message
        self.errorCode = errorCode
    }
}