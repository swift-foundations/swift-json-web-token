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

// A JWT's canonical serialized form is its RFC 7519 compact serialization —
// the single string `header.payload.signature`. `Codable` therefore encodes to
// and decodes from that string via a single-value container, rather than a
// memberwise object.
//
// This mirrors the in-repo precedent of ``JWT/Audience`` (which encodes as its
// canonical string-or-array form) and avoids the pitfalls of memberwise
// synthesis, which would (1) leak the `internal` `headerBase64URL` /
// `payloadBase64URL` implementation details into the wire format, (2) encode
// `signature` in an encoder-dependent way (an array of integers under the
// default `JSONEncoder`), and (3) produce a JSON object that no JWT consumer
// expects where the string form is required (e.g. `{"token": "eyJ..."}`).
//
// The compact string losslessly captures every verification-significant byte,
// so the round trip preserves the exact signing input.
extension JWT: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let token = try container.decode(String.self)
        do {
            self = try JWT.parse(from: token)
        } catch {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid JWT compact serialization",
                    underlyingError: error
                )
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        let serialized: String
        do {
            serialized = try compactSerialization()
        } catch {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "JWT could not be serialized to its compact form",
                    underlyingError: error
                )
            )
        }
        var container = encoder.singleValueContainer()
        try container.encode(serialized)
    }
}
