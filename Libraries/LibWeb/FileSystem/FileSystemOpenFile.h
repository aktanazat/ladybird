/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/FileSystem/FileSystemFileHandle.h>

namespace Web::FileSystem {

// Owns a browser-side lock and releases it if script drops the stream or handle.
class FileSystemOpenFile final : public GC::Cell {
    GC_CELL(FileSystemOpenFile, GC::Cell);
    GC_DECLARE_ALLOCATOR(FileSystemOpenFile);

public:
    static GC::Ref<FileSystemOpenFile> create(FileSystemFileHandle&, u64 token);
    Reply request(Operation, u64 offset = 0, ReadonlyBytes = {});
    JS::Realm& realm() const { return m_handle->realm(); }

private:
    FileSystemOpenFile(FileSystemFileHandle&, u64, Function<void(u64)>);
    virtual void visit_edges(GC::Cell::Visitor&) override;
    virtual void finalize() override;

    GC::Ref<FileSystemFileHandle> m_handle;
    u64 m_token;
    Function<void(u64)> m_abandon;
};

}
