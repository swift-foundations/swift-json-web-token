import Foundation
import Testing

@testable import JWT

@Suite
struct `JWT timing boundaries` {
    private static let instant = Date(timeIntervalSince1970: 1_700_000_000)

    @Test
    func `a token is expired at its expiration time`() {
        let payload = JWT.Payload(exp: Self.instant)
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming(currentTime: Self.instant, clockSkew: 0)
        }
    }

    @Test
    func `a token is valid just before its expiration time`() throws {
        let payload = JWT.Payload(exp: Self.instant)
        try payload.validateTiming(currentTime: Self.instant.addingTimeInterval(-1), clockSkew: 0)
    }

    @Test
    func `clock skew extends validity up to but not including the skewed expiration`() throws {
        let payload = JWT.Payload(exp: Self.instant)
        try payload.validateTiming(currentTime: Self.instant.addingTimeInterval(59), clockSkew: 60)
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming(currentTime: Self.instant.addingTimeInterval(60), clockSkew: 60)
        }
    }

    @Test
    func `a token is valid from its not-before time`() throws {
        let payload = JWT.Payload(nbf: Self.instant)
        try payload.validateTiming(currentTime: Self.instant, clockSkew: 0)
        #expect(throws: RFC_7519.Error.self) {
            try payload.validateTiming(currentTime: Self.instant.addingTimeInterval(-1), clockSkew: 0)
        }
    }
}
