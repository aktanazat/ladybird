/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/HashMap.h>
#include <AK/JsonObject.h>
#include <AK/kmalloc.h>
#include <AK/Optional.h>
#include <AK/Vector.h>
#include <LibWebCommon/WebDriver/Response.h>

namespace WebView::WebAuthentication {

enum class Requirement : u8 {
    Discouraged,
    Preferred,
    Required,
};

enum class Attachment : u8 {
    Any,
    Platform,
    CrossPlatform,
};

struct Request {
    String rp_id;
    String client_data_json;
    Vector<String> credential_ids;
    Optional<String> user_handle;
    String user_name;
    Requirement resident_key { Requirement::Preferred };
    Requirement user_verification { Requirement::Preferred };
    Attachment attachment { Attachment::Any };
};

struct Credential {
    String id;
    String rp_id;
    Optional<String> user_handle;
    String user_name;
    ByteBuffer key;
    u32 sign_count { 0 };
    bool discoverable { false };
};

JsonObject failure(StringView exception, StringView message);
bool is_matching_credential(Request const&, Credential const&);
ErrorOr<String> create_credential_id();
ErrorOr<JsonObject> registration_result(Request const&, Credential const&, bool verified, StringView transport, ReadonlyBytes public_key_x963, ReadonlyBytes public_key_spki);
ErrorOr<ByteBuffer> assertion_data(Credential const&, bool verified, u32 sign_count);
ErrorOr<ByteBuffer> assertion_signature_input(Request const&, ReadonlyBytes authenticator_data);
ErrorOr<JsonObject> assertion_result(Request const&, Credential const&, StringView transport, ReadonlyBytes authenticator_data, ReadonlyBytes signature);

class VirtualAuthenticators {
    AK_ALLOC_WITH_KMALLOC;

public:
    bool is_empty() const { return m_authenticators.is_empty(); }
    bool has_user_verifying_platform_authenticator() const;

    Web::WebDriver::Response run_command(StringView command, Vector<String> const& arguments, JsonValue const& payload);
    JsonObject perform(Request const&);

private:
    struct Authenticator {
        String transport;
        bool has_resident_key;
        bool has_user_verification;
        bool user_consenting;
        bool user_verified;
        HashMap<String, Credential> credentials;
    };

    Web::WebDriver::Response add_authenticator(JsonValue const&);
    static Web::WebDriver::Response add_credential(Authenticator&, JsonValue const&);
    static JsonObject make_credential(Authenticator&, Request const&, bool verified);
    static JsonObject get_assertion(Authenticator&, Request const&, bool verified);

    HashMap<String, Authenticator> m_authenticators;
};

}
