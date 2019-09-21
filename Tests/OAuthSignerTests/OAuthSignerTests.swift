import XCTest
@testable import OAuthSigner

final class OAuthSignerTests: XCTestCase {
    func testSignatureRequestToken() {
        let signer = OAuthSigner(consumerKey: "hoge", consumerSecret: "fuga")
        let request = try! signer.signedRequest(
            .post,
            url: URL(string: "https://example.com/oauth/request_token")!,
            params: ["oauth_callback": "oob"],
            currentTime: .init(timeIntervalSince1970: 1322406000),
            nonce: "nonce_for_test"
        )
        XCTAssertEqual(request.url?.absoluteString, "https://example.com/oauth/request_token")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.allHTTPHeaderFields?.count, 1)
        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "OAuth oauth_callback=\"oob\", oauth_consumer_key=\"hoge\", oauth_nonce=\"nonce_for_test\", oauth_signature=\"7djXd5PPWNpmCyaHNVTglQukugU%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1322406000\", oauth_token=\"\", oauth_version=\"1.0\"")
        XCTAssertEqual(request.httpBody, nil)
    }
    
    func testSignatureGetRequest() {
        let signer = OAuthSigner(consumerKey: "hoge", consumerSecret: "fuga", oauthToken: "piyo", oauthSecret: "iyan")
        let request = try! signer.signedRequest(
            .get,
            url: URL(string: "https://example.com/api/1.1/users/show.json")!,
            params: ["screen_name": "shibuya_rin"],
            currentTime: .init(timeIntervalSince1970: 1322406000),
            nonce: "nonce_for_test"
        )
        XCTAssertEqual(request.url?.absoluteString, "https://example.com/api/1.1/users/show.json?screen_name=shibuya_rin")
        XCTAssertEqual(request.httpMethod, "GET")
        XCTAssertEqual(request.allHTTPHeaderFields?.count, 1)
        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "OAuth oauth_consumer_key=\"hoge\", oauth_nonce=\"nonce_for_test\", oauth_signature=\"v%2BANqplewitX7qmWb7D1KZenK%2BQ%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1322406000\", oauth_token=\"piyo\", oauth_version=\"1.0\"")
        XCTAssertEqual(request.httpBody, nil)
    }
    
    func testSignaturePostRequest() {
        let signer = OAuthSigner(consumerKey: "hoge", consumerSecret: "fuga", oauthToken: "piyo", oauthSecret: "iyan")
        let request = try! signer.signedRequest(
            .post,
            url: URL(string: "https://example.com/api/1.1/statuses/update.json")!,
            params: ["status": "Hello world!"],
            currentTime: .init(timeIntervalSince1970: 1322406000),
            nonce: "nonce_for_test"
        )
        XCTAssertEqual(request.url?.absoluteString, "https://example.com/api/1.1/statuses/update.json")
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.allHTTPHeaderFields?.count, 2)
        XCTAssertEqual(request.allHTTPHeaderFields?["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertEqual(request.allHTTPHeaderFields?["Authorization"], "OAuth oauth_consumer_key=\"hoge\", oauth_nonce=\"nonce_for_test\", oauth_signature=\"E2DwObG44J%2FwYaVsG8q%2BmMzI6QQ%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_timestamp=\"1322406000\", oauth_token=\"piyo\", oauth_version=\"1.0\"")
        XCTAssertEqual(request.httpBody, "status=Hello%20world%21".data(using: .utf8))
    }

    static var allTests = [
        ("testSignatureRequestToken", testSignatureRequestToken),
    ]
}
