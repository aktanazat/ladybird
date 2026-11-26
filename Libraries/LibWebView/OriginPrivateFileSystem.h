/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibDatabase/Database.h>
#include <LibWebCommon/StorageAPI/OriginPrivateFileSystem.h>

namespace WebView {

// One store per browsing session. All access is serialized by the browser's event loop.
class OriginPrivateFileSystem {
public:
    static ErrorOr<NonnullOwnPtr<OriginPrivateFileSystem>> create(Optional<ByteString> const& directory);
    Web::FileSystem::Reply request(String const& bucket, Web::FileSystem::Request const&);

private:
    struct Statements {
        Database::StatementID entry_kind;
        Database::StatementID insert_entry;
        Database::StatementID children;
        Database::StatementID has_children;
        Database::StatementID delete_entry;
        Database::StatementID read_file;
    };

    OriginPrivateFileSystem(NonnullRefPtr<Database::Database>, Statements);
    ErrorOr<Web::FileSystem::Reply> perform_request(String const& bucket, Web::FileSystem::Request const&);

    ErrorOr<Optional<bool>> entry_kind(String const& bucket, String const& path);

    NonnullRefPtr<Database::Database> m_database;
    Statements m_statements;
};

}
