// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-json-web-token open source project
//
// Copyright (c) 2026 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

import Foundation

extension JWT {
    /// A JWT payload carrying the registered and custom claims (RFC 7519 §4).
    public struct Payload: Hashable, Sendable {
        /// Issuer — the principal that issued the JWT (`iss`).
        public let iss: String?

        /// Subject — the principal that is the subject of the JWT (`sub`).
        public let sub: String?

        /// Audience — the recipients the JWT is intended for (`aud`).
        public let aud: Audience?

        /// Expiration time after which the JWT must not be accepted (`exp`).
        public let exp: Date?

        /// Time before which the JWT must not be accepted (`nbf`).
        public let nbf: Date?

        /// Time at which the JWT was issued (`iat`).
        public let iat: Date?

        /// A unique identifier for the JWT (`jti`).
        public let jti: String?

        /// Claims beyond the registered ones above.
        private let additionalClaims: [String: AnyCodable]?

        /// Creates a JWT payload.
        ///
        /// - Parameters:
        ///   - iss: Issuer.
        ///   - sub: Subject.
        ///   - aud: Audience.
        ///   - exp: Expiration time.
        ///   - nbf: Not-before time.
        ///   - iat: Issued-at time.
        ///   - jti: JWT ID.
        ///   - additionalClaims: Any additional custom claims.
        public init(
            iss: String? = nil,
            sub: String? = nil,
            aud: Audience? = nil,
            exp: Date? = nil,
            nbf: Date? = nil,
            iat: Date? = nil,
            jti: String? = nil,
            additionalClaims: [String: Any]? = nil
        ) {
            self.iss = iss
            self.sub = sub
            self.aud = aud
            self.exp = exp
            self.nbf = nbf
            self.iat = iat
            self.jti = jti
            self.additionalClaims = additionalClaims?.mapValues(AnyCodable.init)
        }

        /// Reads an additional (non-registered) claim.
        ///
        /// - Parameters:
        ///   - key: The claim name.
        ///   - type: The expected value type.
        /// - Returns: The value if present and of the expected type.
        public func additionalClaim<T>(_ key: String, as type: T.Type = T.self) -> T? {
            additionalClaims?[key]?.value as? T
        }

        /// Validates the timing claims (`exp` / `nbf`) against a reference time.
        ///
        /// - Parameters:
        ///   - currentTime: The reference time (defaults to now).
        ///   - clockSkew: Allowed clock skew in seconds (defaults to 60).
        /// - Throws: ``RFC_7519/Error/tokenExpired(_:)`` or
        ///   ``RFC_7519/Error/tokenNotYetValid(_:)``.
        public func validateTiming(
            currentTime: Date = Date(),
            clockSkew: TimeInterval = 60
        ) throws(RFC_7519.Error) {
            if let exp, currentTime.timeIntervalSince1970 > exp.timeIntervalSince1970 + clockSkew {
                throw .tokenExpired("Token expired at \(exp)")
            }
            if let nbf, currentTime.timeIntervalSince1970 < nbf.timeIntervalSince1970 - clockSkew {
                throw .tokenNotYetValid("Token not valid before \(nbf)")
            }
        }
    }
}

extension JWT.Payload: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case iss, sub, aud, exp, nbf, iat, jti
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)

        self.iss = try container.decodeIfPresent(String.self, forKey: .iss)
        self.sub = try container.decodeIfPresent(String.self, forKey: .sub)
        self.aud = try container.decodeIfPresent(JWT.Audience.self, forKey: .aud)

        if let expTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .exp) {
            self.exp = Date(timeIntervalSince1970: expTimestamp)
        } else {
            self.exp = nil
        }
        if let nbfTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .nbf) {
            self.nbf = Date(timeIntervalSince1970: nbfTimestamp)
        } else {
            self.nbf = nil
        }
        if let iatTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .iat) {
            self.iat = Date(timeIntervalSince1970: iatTimestamp)
        } else {
            self.iat = nil
        }

        self.jti = try container.decodeIfPresent(String.self, forKey: .jti)

        let known = Set(CodingKeys.allCases.map(\.stringValue))
        var additional: [String: AnyCodable] = [:]
        for key in dynamicContainer.allKeys where !known.contains(key.stringValue) {
            additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
        }
        self.additionalClaims = additional.isEmpty ? nil : additional
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(iss, forKey: .iss)
        try container.encodeIfPresent(sub, forKey: .sub)
        try container.encodeIfPresent(aud, forKey: .aud)
        if let exp {
            try container.encode(exp.timeIntervalSince1970, forKey: .exp)
        }
        if let nbf {
            try container.encode(nbf.timeIntervalSince1970, forKey: .nbf)
        }
        if let iat {
            try container.encode(iat.timeIntervalSince1970, forKey: .iat)
        }
        try container.encodeIfPresent(jti, forKey: .jti)

        if let additionalClaims {
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in additionalClaims {
                guard let codingKey = DynamicCodingKey(stringValue: key) else { continue }
                try dynamicContainer.encode(value, forKey: codingKey)
            }
        }
    }
}
