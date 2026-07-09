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

// Re-export the RFC 7519 structural layer so consumers of the typed claims
// layer also see the `RFC_7519` namespace (and `RFC_7519.Error`).
@_exported import RFC_7519
