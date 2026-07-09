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

/// A JSON Web Token (JWT) as defined by RFC 7519.
///
/// A JWT carries a set of claims between two parties. In its compact
/// serialization it consists of three Base64URL-encoded parts separated by
/// periods: `header.payload.signature`.
///
/// This is the *typed* claims layer. The header and payload are decoded into
/// the strongly-typed ``JWT/Header`` and ``JWT/Payload`` values; the underlying
/// RFC 7519 structural byte layer lives upstream in `RFC_7519`.
///
/// ```swift
/// let jwt = try JWT.hmacSHA256(
///     issuer: "example.com",
///     subject: "user123",
///     secretKey: "your-secret-key"
/// )
/// let token = try jwt.compactSerialization()
/// ```
public struct JWT: Sendable {
    /// The decoded, strongly-typed JWT header.
    public let header: Header

    /// The decoded, strongly-typed JWT payload (claims).
    public let payload: Payload

    /// The raw signature bytes.
    public let signature: Data

    /// Original Base64URL-encoded header, preserved from parsing so that the
    /// signing input can be reproduced byte-for-byte during verification.
    let headerBase64URL: String?

    /// Original Base64URL-encoded payload, preserved from parsing.
    let payloadBase64URL: String?

    /// Creates a JWT from its typed components.
    ///
    /// - Parameters:
    ///   - header: The JWT header.
    ///   - payload: The JWT payload (claims).
    ///   - signature: The signature bytes.
    public init(header: Header, payload: Payload, signature: Data) {
        self.header = header
        self.payload = payload
        self.signature = signature
        self.headerBase64URL = nil
        self.payloadBase64URL = nil
    }

    /// Creates a JWT from its typed components, preserving the original
    /// Base64URL-encoded header and payload strings.
    init(
        header: Header,
        payload: Payload,
        signature: Data,
        headerBase64URL: String,
        payloadBase64URL: String
    ) {
        self.header = header
        self.payload = payload
        self.signature = signature
        self.headerBase64URL = headerBase64URL
        self.payloadBase64URL = payloadBase64URL
    }

    /// Parses a JWT from its compact serialization (`header.payload.signature`).
    ///
    /// - Parameter token: The JWT string.
    /// - Returns: The parsed, typed JWT.
    /// - Throws: ``RFC_7519/Error`` on malformed input.
    public static func parse(from token: String) throws(RFC_7519.Error) -> JWT {
        let components = token.components(separatedBy: ".")
        guard components.count == 3 else {
            throw .invalidFormat("JWT must have exactly 3 parts separated by dots")
        }

        guard let headerData = Data(base64URLEncoded: components[0]) else {
            throw .invalidFormat("Invalid base64url encoding in header")
        }
        let header: Header
        do {
            header = try JSONDecoder().decode(Header.self, from: headerData)
        } catch {
            throw .invalidFormat("Invalid JSON in header: \(error)")
        }

        guard let payloadData = Data(base64URLEncoded: components[1]) else {
            throw .invalidFormat("Invalid base64url encoding in payload")
        }
        let payload: Payload
        do {
            payload = try JSONDecoder().decode(Payload.self, from: payloadData)
        } catch {
            throw .invalidFormat("Invalid JSON in payload: \(error)")
        }

        guard let signature = Data(base64URLEncoded: components[2]) else {
            throw .invalidFormat("Invalid base64url encoding in signature")
        }

        return JWT(
            header: header,
            payload: payload,
            signature: signature,
            headerBase64URL: components[0],
            payloadBase64URL: components[1]
        )
    }

    /// Serializes the JWT to its compact form (`header.payload.signature`).
    ///
    /// - Returns: The compact JWT string.
    /// - Throws: ``RFC_7519/Error`` if the header or payload cannot be encoded.
    public func compactSerialization() throws(RFC_7519.Error) -> String {
        let headerBase64: String
        let payloadBase64: String

        if let originalHeader = headerBase64URL, let originalPayload = payloadBase64URL {
            headerBase64 = originalHeader
            payloadBase64 = originalPayload
        } else {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            do {
                headerBase64 = try encoder.encode(header).base64URLEncodedString()
                payloadBase64 = try encoder.encode(payload).base64URLEncodedString()
            } catch {
                throw .encodingFailed("Failed to encode JWT: \(error)")
            }
        }

        let signatureBase64 = signature.base64URLEncodedString()
        return "\(headerBase64).\(payloadBase64).\(signatureBase64)"
    }

    /// The signing input (`BASE64URL(header).BASE64URL(payload)`) as ASCII bytes.
    ///
    /// Per RFC 7515 this is the exact byte sequence that is signed and verified.
    ///
    /// - Returns: The signing input bytes.
    /// - Throws: ``RFC_7519/Error`` if the header or payload cannot be encoded.
    public func signingInput() throws(RFC_7519.Error) -> Data {
        if let originalHeader = headerBase64URL, let originalPayload = payloadBase64URL {
            return Data("\(originalHeader).\(originalPayload)".utf8)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let headerBase64: String
        let payloadBase64: String
        do {
            headerBase64 = try encoder.encode(header).base64URLEncodedString()
            payloadBase64 = try encoder.encode(payload).base64URLEncodedString()
        } catch {
            throw .encodingFailed("Failed to encode JWT signing input: \(error)")
        }

        return Data("\(headerBase64).\(payloadBase64)".utf8)
    }
}
