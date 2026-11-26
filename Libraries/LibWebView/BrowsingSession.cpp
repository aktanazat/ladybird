/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWebView/BlobURLStore.h>
#include <LibWebView/BrowsingSession.h>
#include <LibWebView/CookieJar.h>
#include <LibWebView/HSTSStore.h>
#include <LibWebView/OriginPrivateFileSystem.h>
#include <LibWebView/PermissionManager.h>
#include <LibWebView/StorageJar.h>

namespace WebView {

static u64 s_next_id { 1 };

BrowsingSession::BrowsingSession(IsPrivate is_private)
    : m_id(s_next_id++)
    , m_is_private(is_private)
{
}

BrowsingSession::~BrowsingSession() = default;

OriginPrivateFileSystem* BrowsingSession::origin_private_file_system()
{
    if (!m_origin_private_file_system) {
        auto store = OriginPrivateFileSystem::create(m_origin_private_file_system_directory);
        if (store.is_error())
            return nullptr;
        m_origin_private_file_system = store.release_value();
    }
    return m_origin_private_file_system.ptr();
}

NonnullRefPtr<BrowsingSession> BrowsingSession::create(IsPrivate is_private)
{
    auto session = adopt_ref(*new BrowsingSession(is_private));

    if (is_private == IsPrivate::Yes) {
        session->cookie_jar = CookieJar::create(IsPrivate::Yes);
        session->storage_jar = StorageJar::create();
        session->blob_url_store = make<BlobURLStore>();
        session->hsts_store = HSTSStore::create();
    }

    return session;
}

}
