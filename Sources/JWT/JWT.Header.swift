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
    /// A JWT header (JOSE header) as defined by RFC 7519 / RFC 7515.
    public struct Header: Hashable, Sendable {
        /// Token type — typically `"JWT"` (`typ`).
        public let typ: String?

        /// Algorithm used to sign the JWT (`alg`).
        public let alg: String

        /// Content type, used for nested JWTs (`cty`).
        public let cty: String?

        /// Key ID — a hint indicating which key secured the JWT (`kid`).
        public let kid: String?

        /// Header parameters beyond the registered ones above.
        private let additionalParameters: [String: AnyCodable]?

        /// Creates a JWT header.
        ///
        /// - Parameters:
        ///   - alg: The signing algorithm (required).
        ///   - typ: The token type (defaults to `"JWT"`).
        ///   - cty: The content type.
        ///   - kid: The key ID.
        ///   - additionalParameters: Any additional header parameters.
        public init(
            alg: String,
            typ: String? = "JWT",
            cty: String? = nil,
            kid: String? = nil,
            additionalParameters: [String: Any]? = nil
        ) {
            self.alg = alg
            self.typ = typ
            self.cty = cty
            self.kid = kid
            self.additionalParameters = additionalParameters?.mapValues(AnyCodable.init)
        }

        /// Reads an additional (non-registered) header parameter.
        ///
        /// - Parameters:
        ///   - key: The parameter name.
        ///   - type: The expected value type.
        /// - Returns: The value if present and of the expected type.
        public func additionalParameter<T>(_ key: String, as type: T.Type = T.self) -> T? {
            additionalParameters?[key]?.value as? T
        }
    }
}

extension JWT.Header: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case typ, alg, cty, kid
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)

        self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
        self.alg = try container.decode(String.self, forKey: .alg)
        self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
        self.kid = try container.decodeIfPresent(String.self, forKey: .kid)

        let known = Set(CodingKeys.allCases.map(\.stringValue))
        var additional: [String: AnyCodable] = [:]
        for key in dynamicContainer.allKeys where !known.contains(key.stringValue) {
            additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
        }
        self.additionalParameters = additional.isEmpty ? nil : additional
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(typ, forKey: .typ)
        try container.encode(alg, forKey: .alg)
        try container.encodeIfPresent(cty, forKey: .cty)
        try container.encodeIfPresent(kid, forKey: .kid)

        if let additionalParameters {
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in additionalParameters {
                guard let codingKey = DynamicCodingKey(stringValue: key) else { continue }
                try dynamicContainer.encode(value, forKey: codingKey)
            }
        }
    }
}
