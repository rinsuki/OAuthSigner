import Foundation
import CommonCrypto
import Alamofire

struct OAuthSigner {
    public enum Error: Swift.Error {
        case generateRandom(Int32)
        case failedToEncodeString
    }
    
    public var consumerKey: String
    public var consumerSecret: String
    public var oauthToken: String = ""
    public var oauthSecret: String = ""
    
    public init(consumerKey: String, consumerSecret: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
    }
    
    public init(consumerKey: String, consumerSecret: String, oauthToken: String, oauthSecret: String) {
        self.consumerKey = consumerKey
        self.consumerSecret = consumerSecret
        self.oauthToken = oauthToken
        self.oauthSecret = oauthSecret
    }
    
    private func generateRandom() throws -> Data {
        var out = Data(count: 32)
        let count = out.count
        let result = out.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        if result == errSecSuccess {
            return out
        } else {
            throw Error.generateRandom(result)
        }
    }
    
    public func signedRequest(
        _ method: HTTPMethod,
        url: URL, params: [String: String],
        currentTime: Date = Date(),
        nonce providedNonce: String? = nil
    ) throws -> URLRequest {
        let nonce: String
        if let providedNonce = providedNonce {
            nonce = providedNonce
        } else {
            nonce = try generateRandom().map { String(format: "%02X", $0) }.joined()
        }
        let currentTimestamp = Int(currentTime.timeIntervalSince1970)
        var oauthParams = [
            "oauth_consumer_key": consumerKey,
            "oauth_nonce": nonce,
            "oauth_signature_method": "HMAC-SHA1",
            "oauth_timestamp": currentTimestamp.description,
            "oauth_version": "1.0",
            "oauth_token": oauthToken,
        ]
        for (key, value) in params where key.starts(with: "oauth_") {
            oauthParams[key] = value
        }
        let mergedParams = params.merging(oauthParams, uniquingKeysWith: { $1 })
        let paramsStr = mergedParams
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .rfc3986)!)"}
            .joined(separator: "&")
        let signatureTarget = [
            method.rawValue,
            url.absoluteString.addingPercentEncoding(withAllowedCharacters: .rfc3986)!,
            paramsStr.addingPercentEncoding(withAllowedCharacters: .rfc3986)!,
        ]
            .joined(separator: "&")
        let secret = "\(consumerSecret)&\(oauthSecret)"
        
        // HMAC-SHA1
        
        guard let cKey = secret.cString(using: .utf8) else { throw Error.failedToEncodeString }
        guard let cData = signatureTarget.cString(using: .utf8) else { throw Error.failedToEncodeString }
        var result = Data(count: Int(CC_SHA1_DIGEST_LENGTH))
        result.withUnsafeMutableBytes {
            CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA1), cKey, Int(strlen(cKey)), cData, Int(strlen(cData)), $0.baseAddress)
        }
        let signature = result.base64EncodedString()
        
        oauthParams["oauth_signature"] = signature
        let header = oauthParams
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\"\($0.value.addingPercentEncoding(withAllowedCharacters: .rfc3986)!)\""}
            .joined(separator: ", ")
        let bodyParams = params.filter { (key, value) in !key.starts(with: "oauth_") }
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        if bodyParams.count > 0{
            let paramsString = bodyParams
                .sorted { $0.key < $1.key }
                .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .rfc3986)!)"}
                .joined(separator: "&")
            if method == .get {
                var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
                components.query = paramsString
                request.url = components.url
            } else {
                let paramsData = paramsString.data(using: .utf8)!
                request.addValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                request.httpBody = paramsData
            }
        }
        request.addValue("OAuth " + header, forHTTPHeaderField: "Authorization")
        return request
    }
}
