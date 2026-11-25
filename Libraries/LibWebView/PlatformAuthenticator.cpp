/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Base64.h>
#include <AK/JsonArray.h>
#include <AK/Random.h>
#include <AK/ScopeGuard.h>
#include <LibCore/Directory.h>
#include <LibCore/EventLoop.h>
#include <LibCore/System.h>
#include <LibWebView/PlatformAuthenticator.h>
#include <LibWebView/ViewImplementation.h>

#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
#    include <errno.h>
#    include <sys/file.h>
#    include <unistd.h>
#endif

namespace WebView::WebAuthentication {

#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)

struct PlatformCompletion {
    AK_ALLOC_WITH_KMALLOC;

    ThreadSafeWeakRef<PlatformOperation> operation;
    NonnullRefPtr<Core::WeakEventLoopReference> event_loop;
};

using PlatformCallback = void (*)(void*, u8, u8 const*, size_t, u8 const*, size_t, u8 const*, size_t);

extern "C" {
bool ladybird_webauthn_mac_available();
void* ladybird_webauthn_mac_start(bool create, u8 const* reason, size_t reason_length, u8 const* key, size_t key_length, u8 const* message, size_t message_length, void* state, PlatformCallback);
void ladybird_webauthn_mac_cancel(void*);
void ladybird_webauthn_mac_release(void*);
}

constexpr StringView credential_store_name = "passkeys.json"sv;
constexpr size_t max_store_size = 2 * MiB;

static ErrorOr<Vector<Credential>> load_credentials(Core::Directory const& directory)
{
    auto file = directory.open(credential_store_name, Core::File::OpenMode::Read | Core::File::OpenMode::NoFollow | Core::File::OpenMode::Nonblocking);
    if (file.is_error() && file.error().is_errno() && file.error().code() == ENOENT)
        return Vector<Credential> {};
    auto owned_file = TRY(move(file));
    auto status = TRY(owned_file->stat());
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() || (status.st_mode & 0077) != 0 || status.st_size < 0 || static_cast<u64>(status.st_size) > max_store_size)
        return Error::from_string_literal("Invalid passkey store");
    auto bytes = TRY(owned_file->read_until_eof());
    auto json = TRY(JsonValue::from_string(StringView { bytes.bytes() }));
    if (!json.is_array())
        return Error::from_string_literal("Invalid passkey store");

    Vector<Credential> credentials;
    for (auto const& value : json.as_array().values()) {
        if (!value.is_object())
            return Error::from_string_literal("Invalid passkey record");
        auto const& info = value.as_object();
        auto id = info.get_string("id"sv);
        auto rp_id = info.get_string("rpId"sv);
        auto user_handle = info.get_string("userHandle"sv);
        auto user_name = info.get_string("userName"sv);
        auto key = info.get_string("key"sv);
        auto discoverable = info.get_bool("discoverable"sv);
        if (!id.has_value() || !rp_id.has_value() || !user_handle.has_value() || !user_name.has_value() || !key.has_value() || !discoverable.has_value())
            return Error::from_string_literal("Incomplete passkey record");
        TRY(credentials.try_append({ *id, *rp_id, String { *user_handle }, *user_name, TRY(decode_base64url(*key)), 0, *discoverable }));
    }
    return credentials;
}

// Returns false if an existing credential excludes this registration.
static ErrorOr<bool> store_credential(Core::Directory const& directory, Request const& request, Credential const& credential)
{
    auto lock = TRY(directory.open(".passkeys.lock"sv, Core::File::OpenMode::ReadWrite | Core::File::OpenMode::NoFollow | Core::File::OpenMode::Nonblocking, 0600));
    auto status = TRY(lock->stat());
    if (!S_ISREG(status.st_mode) || status.st_uid != getuid() || (status.st_mode & 0077) != 0)
        return Error::from_string_literal("Invalid passkey store lock");
    if (flock(lock->fd(), LOCK_EX | LOCK_NB) < 0)
        return Error::from_errno(errno);
    auto credentials = TRY(load_credentials(directory));
    JsonArray json;
    auto add = [&](Credential const& credential) -> ErrorOr<void> {
        JsonObject info;
        info.set("id"sv, credential.id);
        info.set("rpId"sv, credential.rp_id);
        info.set("userHandle"sv, *credential.user_handle);
        info.set("userName"sv, credential.user_name);
        info.set("discoverable"sv, credential.discoverable);
        info.set("key"sv, TRY(encode_base64url(credential.key.bytes(), AK::OmitPadding::Yes)));
        return json.append(move(info));
    };
    for (auto const& existing : credentials) {
        if (existing.rp_id == credential.rp_id && request.credential_ids.contains_slow(existing.id))
            return false;
        if (credential.discoverable && existing.discoverable && existing.rp_id == credential.rp_id && existing.user_handle == credential.user_handle)
            continue;
        TRY(add(existing));
    }
    TRY(add(credential));
    auto bytes = JsonValue { move(json) }.serialized();
    if (bytes.bytes().size() > max_store_size)
        return Error::from_string_literal("Passkey store is full");

    auto temp_name = TRY(String::formatted(".passkeys-{}.json", generate_random_uuid()));
    auto temp_file = TRY(directory.open(temp_name, Core::File::OpenMode::Write | Core::File::OpenMode::MustBeNew | Core::File::OpenMode::NoFollow, 0600));
    auto cleanup = ArmedScopeGuard([&] { (void)unlinkat(directory.fd(), temp_name.to_byte_string().characters(), 0); });
    TRY(temp_file->write_until_depleted(bytes.bytes()));
    if (fsync(temp_file->fd()) < 0)
        return Error::from_errno(errno);
    TRY(Core::System::renameat(directory.fd(), temp_name, directory.fd(), credential_store_name));
    cleanup.disarm();
    return true;
}

#endif

bool PlatformOperation::is_available()
{
#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
    return ladybird_webauthn_mac_available();
#else
    return false;
#endif
}

PlatformOperation::PlatformOperation(Request request, String origin, ByteString profile_data_directory, Function<bool()> is_current, Function<void(JsonObject)> on_complete)
    : m_request(move(request))
    , m_origin(move(origin))
    , m_profile_data_directory(move(profile_data_directory))
    , m_is_current(move(is_current))
    , m_on_complete(move(on_complete))
{
}

PlatformOperation::~PlatformOperation()
{
    cancel();
}

void PlatformOperation::cancel()
{
    m_on_complete = nullptr;
    if (auto cancel_chooser = move(m_cancel_chooser))
        cancel_chooser();
#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
    if (auto* operation = exchange(m_platform_handle, nullptr)) {
        ladybird_webauthn_mac_cancel(operation);
        ladybird_webauthn_mac_release(operation);
    }
#endif
}

void PlatformOperation::start([[maybe_unused]] ViewImplementation& view)
{
#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
    if (m_request.user_handle.has_value()) {
        start_authentication();
        return;
    }

    auto credentials = [&]() -> ErrorOr<Vector<Credential>> {
        auto directory = TRY(Core::Directory::create(m_profile_data_directory, Core::Directory::CreateDirectories::No));
        return load_credentials(directory);
    }();
    if (credentials.is_error())
        return finish(failure("UnknownError"sv, "The browser could not read its passkey store"sv));

    for (auto& credential : credentials.value()) {
        if (is_matching_credential(m_request, credential))
            m_candidates.append(move(credential));
    }
    if (m_candidates.is_empty())
        return finish(failure("NotAllowedError"sv, "No passkey is available for this site"sv));
    if (m_candidates.size() == 1) {
        select_credential(0);
        return;
    }

    Vector<String> names;
    for (auto const& credential : m_candidates)
        names.append(credential.user_name);
    if (view.on_choose_webauthn_credential) {
        m_cancel_chooser = view.on_choose_webauthn_credential(m_origin, names, [weak_this = make_weak_ref()](Optional<u32> choice) {
            if (auto self = weak_this.strong_ref())
                self->select_credential(choice);
        });
        if (m_cancel_chooser)
            return;
    }
#endif
    finish(failure("NotAllowedError"sv, "The browser could not select a passkey"sv));
}

void PlatformOperation::select_credential(Optional<u32> choice)
{
    // The chooser has already been taken down by whoever supplied the result.
    m_cancel_chooser = nullptr;
    if (!m_on_complete)
        return;
    if (!choice.has_value() || *choice >= m_candidates.size())
        return finish(failure("NotAllowedError"sv, "The passkey chooser was dismissed"sv));

    m_selected = move(m_candidates[*choice]);
    m_candidates.clear();
    start_authentication();
}

void PlatformOperation::start_authentication()
{
    if (!m_is_current())
        return finish(failure("NotAllowedError"sv, "The requesting site is no longer active"sv));
#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
    ByteBuffer message;
    ReadonlyBytes key;
    if (m_selected.has_value()) {
        auto data = assertion_data(*m_selected, true, 0);
        if (data.is_error())
            return finish(failure("UnknownError"sv, "Could not prepare authenticator data"sv));
        m_authenticator_data = data.release_value();
        auto input = assertion_signature_input(m_request, m_authenticator_data.bytes());
        if (input.is_error())
            return finish(failure("UnknownError"sv, "Could not prepare the signature input"sv));
        message = input.release_value();
        key = m_selected->key.bytes();
    }

    auto reason = MUST(String::formatted("{} {}", m_selected.has_value() ? "Use a passkey for"sv : "Create a passkey for"sv, m_origin));
    auto completion = make<PlatformCompletion>(make_weak_ref(), Core::EventLoop::current_weak());
    m_platform_handle = ladybird_webauthn_mac_start(!m_selected.has_value(), reason.bytes().data(), reason.bytes().size(),
        key.data(), key.size(), message.data(), message.size(), completion.leak_ptr(),
        [](void* state, u8 result, u8 const* first, size_t first_size, u8 const* second, size_t second_size, u8 const* third, size_t third_size) {
            auto completion = adopt_own(*static_cast<PlatformCompletion*>(state));
            auto event_loop = completion->event_loop->take();
            if (!event_loop)
                return;
            // LocalAuthentication calls back off-thread. The Hub runs a Core event loop.
            event_loop->deferred_invoke([operation = move(completion->operation), result,
                                           first = MUST(ByteBuffer::copy({ first, first_size })),
                                           second = MUST(ByteBuffer::copy({ second, second_size })),
                                           third = MUST(ByteBuffer::copy({ third, third_size }))] {
                if (auto self = operation.strong_ref())
                    self->complete_authentication(static_cast<Result>(result), first.bytes(), second.bytes(), third.bytes());
            });
        });
#else
    finish(failure("NotAllowedError"sv, "No platform authenticator is available"sv));
#endif
}

void PlatformOperation::complete_authentication([[maybe_unused]] Result result, [[maybe_unused]] ReadonlyBytes first, [[maybe_unused]] ReadonlyBytes second, [[maybe_unused]] ReadonlyBytes third)
{
#if defined(LADYBIRD_HAS_SECURE_ENCLAVE)
    if (auto* handle = exchange(m_platform_handle, nullptr))
        ladybird_webauthn_mac_release(handle);
    if (!m_on_complete)
        return;
    if (!m_is_current())
        return finish(failure("NotAllowedError"sv, "The requesting site is no longer active"sv));
    if (result == Result::AuthenticationFailed)
        return finish(failure("NotAllowedError"sv, "System authentication did not complete"sv));
    if (result == Result::KeyOperationFailed)
        return finish(failure("UnknownError"sv, "The Secure Enclave could not complete the key operation"sv));

    auto response = [&]() -> ErrorOr<JsonObject> {
        if (m_selected.has_value())
            return assertion_result(m_request, *m_selected, "internal"sv, m_authenticator_data.bytes(), first);

        auto id = TRY(create_credential_id());
        auto resident = m_request.resident_key != Requirement::Discouraged;
        Credential credential { move(id), m_request.rp_id, m_request.user_handle, m_request.user_name, TRY(ByteBuffer::copy(first)), 0, resident };
        auto response = TRY(registration_result(m_request, credential, true, "internal"sv, second, third));
        auto directory = TRY(Core::Directory::create(m_profile_data_directory, Core::Directory::CreateDirectories::No));
        if (!TRY(store_credential(directory, m_request, credential)))
            return failure("InvalidStateError"sv, "The authenticator already has an excluded credential"sv);
        return response;
    }();
    if (!response.is_error())
        return finish(response.release_value());
#endif
    finish(failure("UnknownError"sv, "Could not complete the platform passkey operation"sv));
}

void PlatformOperation::finish(JsonObject response)
{
    if (auto on_complete = move(m_on_complete))
        on_complete(move(response));
}

}
