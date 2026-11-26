/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/StringBuilder.h>
#include <AK/Time.h>
#include <LibDatabase/ResultRow.h>
#include <LibWebView/OriginPrivateFileSystem.h>

namespace WebView {

using Web::FileSystem::Operation;
using Web::FileSystem::Reply;
using Web::FileSystem::Request;
using Web::FileSystem::Status;

static constexpr size_t max_name_size = 4096;
static constexpr size_t max_file_size = 64 * MiB;

// https://fs.spec.whatwg.org/#valid-file-name
static bool valid_name(String const& name)
{
    auto view = name.bytes_as_string_view();
    if (view.is_empty() || view == "."sv || view == ".."sv || view.contains('/') || view.contains('\0'))
        return false;
#if defined(AK_OS_WINDOWS)
    if (view.contains('\\'))
        return false;
#endif
    return view.length() <= max_name_size;
}

OriginPrivateFileSystem::OriginPrivateFileSystem(NonnullRefPtr<Database::Database> database, Statements statements)
    : m_database(move(database))
    , m_statements(statements)
{
}

ErrorOr<NonnullOwnPtr<OriginPrivateFileSystem>> OriginPrivateFileSystem::create(Optional<ByteString> const& directory)
{
    Database::Database::Options options { .synchronous = Database::Database::Synchronous::Full };
    auto database = directory.has_value()
        ? TRY(Database::Database::create(*directory, "OriginPrivateFileSystem"sv, options))
        : TRY(Database::Database::create_memory_backed(options));
    Database::Migration migrations[] = {
        { 1, R"sql(
            CREATE TABLE IF NOT EXISTS Entries (
                bucket TEXT NOT NULL,
                path TEXT NOT NULL,
                parent TEXT NOT NULL,
                name TEXT NOT NULL,
                directory INTEGER NOT NULL,
                contents BLOB NOT NULL,
                modified INTEGER NOT NULL,
                PRIMARY KEY (bucket, path)
            ) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS EntriesByParent ON Entries (bucket, parent);
        )sql" },
    };
    if (TRY(database->migrate("OriginPrivateFileSystem"sv, migrations)) != Database::MigrationOutcome::Success)
        return Error::from_string_literal("Unsupported origin private file system schema");

    Statements statements {
        TRY(database->prepare_statement("SELECT directory FROM Entries WHERE bucket = ? AND path = ?;"sv)),
        TRY(database->prepare_statement("INSERT INTO Entries VALUES (?, ?, ?, ?, ?, X'', ?);"sv)),
        TRY(database->prepare_statement("SELECT name, directory FROM Entries WHERE bucket = ? AND parent = ? ORDER BY path;"sv)),
        TRY(database->prepare_statement("SELECT 1 FROM Entries WHERE bucket = ? AND parent = ? LIMIT 1;"sv)),
        TRY(database->prepare_statement("DELETE FROM Entries WHERE bucket = ? AND (path = ? OR (path >= ? AND path < ?));"sv)),
        TRY(database->prepare_statement("SELECT contents, modified FROM Entries WHERE bucket = :bucket AND path = :path AND directory = 0;"sv)),
    };
    return adopt_own(*new OriginPrivateFileSystem(move(database), statements));
}

ErrorOr<Optional<bool>> OriginPrivateFileSystem::entry_kind(String const& bucket, String const& path)
{
    // Each bucket has an implicit root directory.
    if (path.is_empty())
        return Optional<bool> { true };
    Optional<bool> is_directory;
    TRY(m_database->try_execute_statement(m_statements.entry_kind, [&](auto statement) -> ErrorOr<void> {
        is_directory = m_database->result_column<i64>(statement, 0) != 0;
        return {};
    }, bucket, path));
    return is_directory;
}

Reply OriginPrivateFileSystem::request(String const& bucket, Request const& request)
{
    auto result = perform_request(bucket, request);
    if (result.is_error())
        return { Status::IOError };
    return result.release_value();
}

ErrorOr<Reply> OriginPrivateFileSystem::perform_request(String const& bucket, Request const& request)
{
    // Entry names are database values. They never form part of a host file system path.
    StringBuilder builder;
    for (auto const& component : request.path) {
        if (!valid_name(component))
            return Reply { Status::InvalidName };
        TRY(builder.try_append('/'));
        TRY(builder.try_append(component));
    }
    auto path = TRY(builder.to_string());

    if (request.operation == Operation::OpenRoot)
        return Reply { path.is_empty() ? Status::Success : Status::InvalidName };

    auto kind = TRY(entry_kind(bucket, path));
    if (!kind.has_value())
        return Reply { Status::NotFound };

    if (request.operation == Operation::ReadFile) {
        if (*kind)
            return Reply { Status::NotFound };
        return m_database->try_execute_bound_statement_one<Reply>(m_statements.read_file, [&](auto bind) -> ErrorOr<void> {
            TRY(bind(":bucket"sv, bucket));
            return bind(":path"sv, path);
        }, [&](Database::ResultRow& row) -> ErrorOr<Reply> {
            return Reply { .status = Status::Success, .bytes = TRY(row.read_blob("contents"sv, max_file_size)), .last_modified = TRY(row.read_integer<i64>("modified"sv)) };
        });
    }

    if (!*kind)
        return Reply { Status::NotFound };

    if (request.operation == Operation::List) {
        Reply reply { Status::Success };
        TRY(m_database->try_execute_statement(m_statements.children, [&](auto statement) -> ErrorOr<void> {
            return reply.entries.try_append(Web::FileSystem::DirectoryEntry {
                m_database->result_column<String>(statement, 0),
                m_database->result_column<i64>(statement, 1) != 0,
            });
        }, bucket, path));
        return reply;
    }

    if (!valid_name(request.name))
        return Reply { Status::InvalidName };

    auto child_path = TRY(String::formatted("{}/{}", path, request.name));
    auto child_kind = TRY(entry_kind(bucket, child_path));
    if (request.operation == Operation::Remove) {
        if (!child_kind.has_value())
            return Reply { Status::Success };
        if (*child_kind && !request.option) {
            bool has_children = false;
            TRY(m_database->try_execute_statement(m_statements.has_children, [&](auto) -> ErrorOr<void> {
                has_children = true;
                return {};
            }, bucket, child_path));
            if (has_children)
                return Reply { Status::InvalidModification };
        }

        // With BINARY collation, all descendants are between the '/' suffix and the next character, '0'.
        auto first_descendant = TRY(String::formatted("{}/", child_path));
        auto after_descendants = TRY(String::formatted("{}0", child_path));
        TRY(m_database->try_execute_statement(m_statements.delete_entry, {}, bucket, child_path, first_descendant, after_descendants));
        return Reply { Status::Success };
    }

    bool wants_directory = request.operation == Operation::GetDirectory;
    if (child_kind.has_value())
        return Reply { *child_kind == wants_directory ? Status::Success : Status::TypeMismatch };
    if (!request.option)
        return Reply { Status::NotFound };
    TRY(m_database->try_execute_statement(m_statements.insert_entry, {}, bucket, child_path, path, request.name, wants_directory, UnixDateTime::now().milliseconds_since_epoch()));
    return Reply { Status::Success };
}

}
