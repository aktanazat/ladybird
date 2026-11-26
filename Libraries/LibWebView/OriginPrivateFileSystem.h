/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/HashMap.h>
#include <AK/NonnullOwnPtr.h>
#include <LibDatabase/Database.h>
#include <LibWebCommon/StorageAPI/OriginPrivateFileSystem.h>

namespace WebView {

// One store per browsing session. All access is serialized by the browser's event loop.
class OriginPrivateFileSystem {
public:
    static ErrorOr<NonnullOwnPtr<OriginPrivateFileSystem>> create(Optional<ByteString> const& directory);
    Web::FileSystem::Reply request(void const* owner, String const& bucket, Web::FileSystem::Request const&);
    void release(void const* owner, u64 token);
    void release_all(void const* owner);

private:
    struct Statements {
        Database::StatementID entry_kind;
        Database::StatementID insert_entry;
        Database::StatementID children;
        Database::StatementID has_children;
        Database::StatementID delete_entry;
        Database::StatementID read_file;
        Database::StatementID write_file;
    };

    OriginPrivateFileSystem(NonnullRefPtr<Database::Database>, Statements);
    struct OpenFile {
        void const* owner;
        String bucket;
        String path;
        ByteBuffer staged_bytes;
    };

    ErrorOr<Web::FileSystem::Reply> perform_request(void const* owner, String const& bucket, Web::FileSystem::Request const&);
    ErrorOr<Web::FileSystem::Reply> perform_open_file_request(void const* owner, String const& bucket, Web::FileSystem::Request const&);
    ErrorOr<Web::FileSystem::Reply> read_file(String const& bucket, String const& path);
    ErrorOr<void> write_file(String const& bucket, String const& path, ReadonlyBytes);

    ErrorOr<Optional<bool>> entry_kind(String const& bucket, String const& path);

    NonnullRefPtr<Database::Database> m_database;
    Statements m_statements;
    HashMap<u64, OpenFile> m_open_files;
    u64 m_next_token { 1 };
};

}
