/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Base64.h>
#include <AK/JsonArray.h>
#include <AK/NumericLimits.h>
#include <AK/Random.h>
#include <AK/ScopeGuard.h>
#include <LibCrypto/Hash/Hash.h>
#include <LibCrypto/OpenSSL.h>
#include <LibWebCommon/WebDriver/Error.h>
#include <LibWebView/WebAuthentication.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace WebView::WebAuthentication {

static ErrorOr<String> encode(ReadonlyBytes bytes)
{
    return encode_base64url(bytes, AK::OmitPadding::Yes);
}

static ErrorOr<ByteBuffer> decode(StringView value)
{
    auto decoded = TRY(decode_base64url(value));
    if (TRY(encode(decoded.bytes())) != value)
        return Error::from_string_literal("Invalid base64url encoding");
    return decoded;
}

JsonObject failure(StringView exception, StringView message)
{
    JsonObject result;
    result.set("error"sv, exception);
    result.set("message"sv, message);
    return result;
}

static JsonObject operation_failed()
{
    return failure("UnknownError"sv, "The authenticator could not complete the operation"sv);
}

bool is_matching_credential(Request const& request, Credential const& credential)
{
    if (credential.rp_id != request.rp_id)
        return false;
    if (request.credential_ids.is_empty())
        return credential.discoverable;
    return request.credential_ids.contains_slow(credential.id);
}

ErrorOr<String> create_credential_id()
{
    Array<u8, 32> bytes;
    fill_with_random(bytes.span());
    return encode(bytes.span());
}

static ErrorOr<ByteBuffer> make_authenticator_data(Credential const& credential, bool verified, u32 sign_count, bool attested)
{
    auto hash = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, credential.rp_id.bytes());
    auto data = TRY(ByteBuffer::copy(hash.bytes()));
    u8 flags = 0x01; // User present.
    if (verified)
        flags |= 0x04;
    if (attested)
        flags |= 0x40;
    Array<u8, 5> flags_and_counter {
        flags,
        static_cast<u8>(sign_count >> 24),
        static_cast<u8>(sign_count >> 16),
        static_cast<u8>(sign_count >> 8),
        static_cast<u8>(sign_count),
    };
    TRY(data.try_append(flags_and_counter.span()));
    return data;
}

// CTAP2 canonical CBOR for an ES256 public key (COSE_Key, RFC 9052).
static ErrorOr<void> append_public_key(ByteBuffer& data, ReadonlyBytes point)
{
    if (point.size() != 65 || point[0] != 4)
        return Error::from_string_literal("Expected an uncompressed P-256 public key");
    constexpr Array<u8, 10> cose_header {
        0xa5,       // Five entries.
        0x01, 0x02, // kty: EC2.
        0x03, 0x26, // alg: ES256.
        0x20, 0x01, // crv: P-256.
        0x21, 0x58, 0x20, // x: 32-byte string.
    };
    constexpr Array<u8, 3> y_header { 0x22, 0x58, 0x20 };
    TRY(data.try_append(cose_header.span()));
    TRY(data.try_append(point.slice(1, 32)));
    TRY(data.try_append(y_header.span()));
    return data.try_append(point.slice(33, 32));
}

static ErrorOr<ByteBuffer> none_attestation(ReadonlyBytes authenticator_data)
{
    // The keys are ordered by length, then lexicographically, for canonical CBOR.
    constexpr Array<u8, 28> header {
        0xa3,
        0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e',
        0x67, 'a', 't', 't', 'S', 't', 'm', 't', 0xa0,
        0x68, 'a', 'u', 't', 'h', 'D', 'a', 't', 'a',
    };
    auto result = TRY(ByteBuffer::copy(header.span()));
    auto length = authenticator_data.size();
    // The authenticator data always exceeds 23 bytes and the credential ID is bounded.
    if (length <= 0xff) {
        Array<u8, 2> bytes_header { 0x58, static_cast<u8>(length) };
        TRY(result.try_append(bytes_header.span()));
    } else {
        Array<u8, 3> bytes_header { 0x59, static_cast<u8>(length >> 8), static_cast<u8>(length) };
        TRY(result.try_append(bytes_header.span()));
    }
    TRY(result.try_append(authenticator_data));
    return result;
}

static ErrorOr<JsonObject> credential_result(Request const& request, Credential const& credential, StringView transport, ReadonlyBytes authenticator_data)
{
    JsonObject result;
    result.set("id"sv, credential.id);
    result.set("clientDataJSON"sv, TRY(encode(request.client_data_json.bytes())));
    result.set("authenticatorData"sv, TRY(encode(authenticator_data)));
    result.set("transport"sv, transport);
    return result;
}

ErrorOr<JsonObject> registration_result(Request const& request, Credential const& credential, bool verified, StringView transport, ReadonlyBytes public_key_x963, ReadonlyBytes public_key_spki)
{
    auto data = TRY(make_authenticator_data(credential, verified, 0, true));
    auto id = TRY(decode(credential.id));
    Array<u8, 18> attested_header {};
    // Anonymous registration has an all-zero AAGUID, followed by the credential ID length in network byte order.
    attested_header[16] = static_cast<u8>(id.size() >> 8);
    attested_header[17] = static_cast<u8>(id.size());
    TRY(data.try_append(attested_header.span()));
    TRY(data.try_append(id.bytes()));
    TRY(append_public_key(data, public_key_x963));
    auto result = TRY(credential_result(request, credential, transport, data.bytes()));
    auto attestation = TRY(none_attestation(data.bytes()));
    result.set("attestationObject"sv, TRY(encode(attestation.bytes())));
    result.set("publicKey"sv, TRY(encode(public_key_spki)));
    result.set("publicKeyAlgorithm"sv, -7);
    result.set("discoverable"sv, credential.discoverable);
    return result;
}

ErrorOr<ByteBuffer> assertion_data(Credential const& credential, bool verified, u32 sign_count)
{
    return make_authenticator_data(credential, verified, sign_count, false);
}

ErrorOr<ByteBuffer> assertion_signature_input(Request const& request, ReadonlyBytes authenticator_data)
{
    auto signed_data = TRY(ByteBuffer::copy(authenticator_data));
    auto hash = Crypto::Hash::digest(Crypto::Hash::HashKind::SHA256, request.client_data_json.bytes());
    TRY(signed_data.try_append(hash.bytes()));
    return signed_data;
}

ErrorOr<JsonObject> assertion_result(Request const& request, Credential const& credential, StringView transport, ReadonlyBytes authenticator_data, ReadonlyBytes signature)
{
    auto result = TRY(credential_result(request, credential, transport, authenticator_data));
    result.set("signature"sv, TRY(encode(signature)));
    if (credential.user_handle.has_value() && request.credential_ids.is_empty())
        result.set("userHandle"sv, *credential.user_handle);
    return result;
}

static ErrorOr<Crypto::OpenSSL_PKEY> import_key(ReadonlyBytes bytes)
{
    auto* start = bytes.data();
    auto* info = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &start, static_cast<long>(bytes.size()));
    auto cleanup = ScopeGuard([&] { PKCS8_PRIV_KEY_INFO_free(info); });
    if (!info || start != bytes.data() + bytes.size())
        return Error::from_string_literal("Invalid PKCS#8 key");
    auto key = TRY(Crypto::OpenSSL_PKEY::wrap(EVP_PKCS82PKEY(info)));
    char group[32];
    size_t group_length = 0;
    if (EVP_PKEY_is_a(key.ptr(), "EC") != 1
        || EVP_PKEY_get_group_name(key.ptr(), group, sizeof(group), &group_length) != 1
        || StringView { group, group_length } != "prime256v1"sv)
        return Error::from_string_literal("Expected a P-256 key");
    auto context = TRY(Crypto::OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key.ptr(), nullptr)));
    OPENSSL_TRY(EVP_PKEY_pairwise_check(context.ptr()));
    return key;
}

static ErrorOr<ByteBuffer> encode_der(auto* key, auto encode_key)
{
    auto size = encode_key(key, nullptr);
    if (size <= 0)
        return Error::from_string_literal("Could not encode key");
    auto data = TRY(ByteBuffer::create_uninitialized(size));
    auto* cursor = data.data();
    if (encode_key(key, &cursor) != size)
        return Error::from_string_literal("Could not encode key");
    return data;
}

static ErrorOr<ByteBuffer> export_private_key(EVP_PKEY* key)
{
    auto* pkcs8 = OPENSSL_TRY_PTR(EVP_PKEY2PKCS8(key));
    auto cleanup = ScopeGuard([&] { PKCS8_PRIV_KEY_INFO_free(pkcs8); });
    return encode_der(pkcs8, i2d_PKCS8_PRIV_KEY_INFO);
}

static ErrorOr<ByteBuffer> sign(EVP_PKEY* key, ReadonlyBytes message)
{
    auto context = TRY(Crypto::OpenSSL_MD_CTX::wrap(EVP_MD_CTX_new()));
    OPENSSL_TRY(EVP_DigestSignInit(context.ptr(), nullptr, EVP_sha256(), nullptr, key));
    size_t length = 0;
    OPENSSL_TRY(EVP_DigestSign(context.ptr(), nullptr, &length, message.data(), message.size()));
    auto signature = TRY(ByteBuffer::create_uninitialized(length));
    OPENSSL_TRY(EVP_DigestSign(context.ptr(), signature.data(), &length, message.data(), message.size()));
    signature.resize(length);
    return signature;
}

static Web::WebDriver::Error invalid_argument(StringView message)
{
    return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::InvalidArgument, message);
}

bool VirtualAuthenticators::has_user_verifying_platform_authenticator() const
{
    for (auto const& [_, authenticator] : m_authenticators) {
        if (authenticator.transport == "internal"sv && authenticator.has_user_verification)
            return true;
    }
    return false;
}

Web::WebDriver::Response VirtualAuthenticators::add_authenticator(JsonValue const& payload)
{
    if (!payload.is_object())
        return invalid_argument("Expected an authenticator configuration"sv);
    auto const& options = payload.as_object();
    auto protocol = options.get_string("protocol"sv);
    auto transport = options.get_string("transport"sv);
    if (!protocol.has_value() || !protocol->is_one_of("ctap1/u2f"sv, "ctap2"sv, "ctap2_1"sv))
        return invalid_argument("Unknown authenticator protocol"sv);
    if (!transport.has_value() || !transport->is_one_of("usb"sv, "nfc"sv, "ble"sv, "smart-card"sv, "internal"sv, "hybrid"sv))
        return invalid_argument("Unknown authenticator transport"sv);
    for (auto option : { "hasResidentKey"sv, "hasUserVerification"sv, "isUserConsenting"sv, "isUserVerified"sv }) {
        if (options.has(option) && !options.get_bool(option).has_value())
            return invalid_argument("Authenticator flags must be boolean"sv);
    }
    if (auto extensions = options.get("extensions"sv); extensions.has_value()) {
        if (!extensions->is_array())
            return invalid_argument("Authenticator extensions must be an array"sv);
        if (!extensions->as_array().is_empty())
            return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnsupportedOperation, "Authenticator extensions are unavailable"sv);
    }
    bool ctap2 = *protocol != "ctap1/u2f"sv;
    auto id = generate_random_uuid();
    m_authenticators.set(id, Authenticator {
        transport.release_value(),
        ctap2 && options.get_bool("hasResidentKey"sv).value_or(false),
        ctap2 && options.get_bool("hasUserVerification"sv).value_or(false),
        options.get_bool("isUserConsenting"sv).value_or(true),
        options.get_bool("isUserVerified"sv).value_or(false),
        {},
    });
    return JsonValue { move(id) };
}

Web::WebDriver::Response VirtualAuthenticators::add_credential(Authenticator& authenticator, JsonValue const& payload)
{
    if (!payload.is_object())
        return invalid_argument("Expected credential parameters"sv);
    auto const& options = payload.as_object();
    auto id = options.get_string("credentialId"sv);
    auto rp_id = options.get_string("rpId"sv);
    auto resident = options.get_bool("isResidentCredential"sv);
    auto counter = options.get_u32("signCount"sv);
    auto private_key = options.get_string("privateKey"sv);
    auto user_handle = options.get_string("userHandle"sv);
    if (!id.has_value() || !rp_id.has_value() || !resident.has_value() || !counter.has_value() || !private_key.has_value() || (options.has("userHandle"sv) && !user_handle.has_value()))
        return invalid_argument("Incomplete credential parameters"sv);
    if (id->is_empty() || id->bytes().size() > 1364 || decode(*id).is_error() || rp_id->is_empty())
        return invalid_argument("Invalid credential or relying party ID"sv);
    if (*resident && (!authenticator.has_resident_key || !user_handle.has_value()))
        return invalid_argument("A discoverable credential needs a user handle and a compatible authenticator"sv);
    if (user_handle.has_value() && (user_handle->is_empty() || user_handle->bytes().size() > 86 || decode(*user_handle).is_error()))
        return invalid_argument("Invalid user handle"sv);
    if (private_key->bytes().size() > 4096)
        return invalid_argument("Invalid private key"sv);
    auto key = decode(*private_key);
    if (key.is_error() || import_key(key.value().bytes()).is_error())
        return invalid_argument("Expected a PKCS#8 P-256 private key"sv);
    if (authenticator.credentials.contains(*id))
        return invalid_argument("This credential is already present"sv);
    Credential credential { *id, rp_id.release_value(), user_handle.map([](String const& value) { return String { value }; }), {}, key.release_value(), *counter, *resident };
    authenticator.credentials.set(id.release_value(), move(credential));
    return JsonValue {};
}

Web::WebDriver::Response VirtualAuthenticators::run_command(StringView command, Vector<String> const& arguments, JsonValue const& payload)
{
    if (command == "addAuthenticator"sv)
        return add_authenticator(payload);
    if (arguments.is_empty())
        return invalid_argument("Missing virtual authenticator ID"sv);
    auto authenticator = m_authenticators.find(arguments[0]);
    if (authenticator == m_authenticators.end())
        return invalid_argument("Unknown virtual authenticator"sv);
    auto& state = authenticator->value;
    if (command == "removeAuthenticator"sv) {
        m_authenticators.remove(authenticator);
    } else if (command == "addCredential"sv) {
        return add_credential(state, payload);
    } else if (command == "getCredentials"sv) {
        JsonArray result;
        for (auto const& [_, credential] : state.credentials) {
            auto key = encode(credential.key.bytes());
            if (key.is_error())
                return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownError, "Could not encode credential"sv);
            JsonObject item;
            item.set("credentialId"sv, credential.id);
            item.set("rpId"sv, credential.rp_id);
            item.set("isResidentCredential"sv, credential.discoverable);
            item.set("privateKey"sv, key.release_value());
            item.set("signCount"sv, credential.sign_count);
            if (credential.user_handle.has_value())
                item.set("userHandle"sv, *credential.user_handle);
            result.must_append(move(item));
        }
        return JsonValue { move(result) };
    } else if (command == "removeCredential"sv) {
        if (arguments.size() != 2 || !state.credentials.remove(arguments[1]))
            return invalid_argument("Unknown credential"sv);
    } else if (command == "removeAllCredentials"sv) {
        state.credentials.clear();
    } else if (command == "setUserVerified"sv) {
        auto verified = payload.is_object() ? payload.as_object().get_bool("isUserVerified"sv) : Optional<bool> {};
        if (!verified.has_value())
            return invalid_argument("isUserVerified must be a boolean"sv);
        state.user_verified = *verified;
    } else {
        return Web::WebDriver::Error::from_code(Web::WebDriver::ErrorCode::UnknownCommand, "Unknown WebAuthn command"sv);
    }
    return JsonValue {};
}

JsonObject VirtualAuthenticators::make_credential(Authenticator& authenticator, Request const& request, bool verified)
{
    for (auto const& [_, credential] : authenticator.credentials) {
        if (credential.rp_id == request.rp_id && request.credential_ids.contains_slow(credential.id))
            return failure("InvalidStateError"sv, "The authenticator already has an excluded credential"sv);
    }

    auto generate = [&]() -> ErrorOr<JsonObject> {
        auto key = TRY(Crypto::OpenSSL_PKEY::wrap(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1")));
        Array<u8, 65> point;
        size_t length = 0;
        OPENSSL_TRY(EVP_PKEY_get_octet_string_param(key.ptr(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size(), &length));
        auto spki = TRY(encode_der(key.ptr(), i2d_PUBKEY));
        auto id = TRY(create_credential_id());
        auto discoverable = authenticator.has_resident_key && request.resident_key != Requirement::Discouraged;
        Credential credential { id, request.rp_id, request.user_handle, request.user_name, TRY(export_private_key(key.ptr())), 0, discoverable };
        auto result = TRY(registration_result(request, credential, verified, authenticator.transport, point.span().slice(0, length), spki.bytes()));
        if (discoverable) {
            authenticator.credentials.remove_all_matching([&](auto const&, Credential const& existing) {
                return existing.discoverable && existing.rp_id == request.rp_id && existing.user_handle == request.user_handle;
            });
        }
        authenticator.credentials.set(move(id), move(credential));
        return result;
    };
    auto result = generate();
    return result.is_error() ? operation_failed() : result.release_value();
}

JsonObject VirtualAuthenticators::get_assertion(Authenticator& authenticator, Request const& request, bool verified)
{
    for (auto& [_, credential] : authenticator.credentials) {
        if (!is_matching_credential(request, credential))
            continue;
        auto issue = [&]() -> ErrorOr<JsonObject> {
            auto key = TRY(import_key(credential.key.bytes()));
            auto counter = credential.sign_count < NumericLimits<u32>::max() ? credential.sign_count + 1 : credential.sign_count;
            auto data = TRY(assertion_data(credential, verified, counter));
            auto message = TRY(assertion_signature_input(request, data.bytes()));
            auto signature = TRY(sign(key.ptr(), message.bytes()));
            auto result = TRY(assertion_result(request, credential, authenticator.transport, data.bytes(), signature.bytes()));
            credential.sign_count = counter;
            return result;
        };
        auto result = issue();
        return result.is_error() ? operation_failed() : result.release_value();
    }
    return failure("NotAllowedError"sv, "No matching credential was available"sv);
}

JsonObject VirtualAuthenticators::perform(Request const& request)
{
    for (auto& [_, authenticator] : m_authenticators) {
        bool platform = authenticator.transport == "internal"sv;
        bool verified = authenticator.has_user_verification && authenticator.user_verified && request.user_verification != Requirement::Discouraged;
        if (!authenticator.user_consenting || (request.user_verification == Requirement::Required && !verified))
            continue;
        if ((request.attachment == Attachment::Platform && !platform) || (request.attachment == Attachment::CrossPlatform && platform))
            continue;
        if (request.user_handle.has_value()) {
            if (request.resident_key == Requirement::Required && !authenticator.has_resident_key)
                continue;
            return make_credential(authenticator, request, verified);
        }
        for (auto const& [id, credential] : authenticator.credentials) {
            if (is_matching_credential(request, credential))
                return get_assertion(authenticator, request, verified);
        }
    }
    return failure("NotAllowedError"sv, "No matching virtual authenticator or credential was available"sv);
}

}
