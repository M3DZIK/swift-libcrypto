public class Argon2Exception: Error {
    public let message: String
    public let errorCode: Int32

    init(message: String, errorCode: Int32) {
        self.message = message
        self.errorCode = errorCode
    }
}
