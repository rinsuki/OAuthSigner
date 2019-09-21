import XCTest
@testable import OAuthSigner

final class OAuthSignerTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(OAuthSigner().text, "Hello, World!")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
