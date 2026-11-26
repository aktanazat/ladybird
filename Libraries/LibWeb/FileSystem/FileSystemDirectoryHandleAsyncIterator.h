/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/HashTable.h>
#include <LibWeb/WebIDL/AsyncIterator.h>

namespace Web::FileSystem {

class FileSystemDirectoryHandle;

class FileSystemDirectoryHandleAsyncIterator final : public WebIDL::AsyncIterator {
    GC_CELL(FileSystemDirectoryHandleAsyncIterator, WebIDL::AsyncIterator);
    GC_DECLARE_ALLOCATOR(FileSystemDirectoryHandleAsyncIterator);

public:
    static GC::Ref<JS::HostObject> create(JS::Realm&, JS::Object::PropertyKind, FileSystemDirectoryHandle&);

private:
    FileSystemDirectoryHandleAsyncIterator(JS::Realm&, JS::Object::PropertyKind, FileSystemDirectoryHandle&);
    virtual void visit_edges(GC::Cell::Visitor&) override;
    virtual GC::Ref<WebIDL::Promise> next_iteration_result(JS::Realm&) override;

    GC::Ref<FileSystemDirectoryHandle> m_directory;
    HashTable<String> m_past_results;
};

}
