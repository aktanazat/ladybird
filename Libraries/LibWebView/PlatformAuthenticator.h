/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteString.h>
#include <AK/Function.h>
#include <AK/ThreadSafeWeakable.h>
#include <LibWebView/Forward.h>
#include <LibWebView/WebAuthentication.h>

namespace WebView::WebAuthentication {

class PlatformOperation final
    : public AtomicRefCounted<PlatformOperation>
    , public ThreadSafeWeakable<PlatformOperation> {
public:
    AK_ALLOC_WITH_KMALLOC;

    static bool is_available();

    PlatformOperation(Request, String origin, ByteString profile_data_directory, Function<bool()> is_current, Function<void(JsonObject)> on_complete);
    ~PlatformOperation();

    void start(ViewImplementation&);
    void cancel();

private:
    void select_credential(Optional<u32>);
    void start_authentication();
    enum class Result : u8 {
        Success,
        AuthenticationFailed,
        KeyOperationFailed,
    };
    void complete_authentication(Result, ReadonlyBytes first, ReadonlyBytes second, ReadonlyBytes third);
    void finish(JsonObject);

    Request m_request;
    String m_origin;
    ByteString m_profile_data_directory;
    Function<bool()> m_is_current;
    Function<void(JsonObject)> m_on_complete;
    Vector<Credential> m_candidates;
    Optional<Credential> m_selected;
    ByteBuffer m_authenticator_data;
    Function<void()> m_cancel_chooser;
    [[maybe_unused]] void* m_platform_handle { nullptr };
};

}
