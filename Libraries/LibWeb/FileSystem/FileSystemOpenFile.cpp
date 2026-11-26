/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/FileSystem/FileSystemOpenFile.h>
#include <LibWeb/Page/Page.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemOpenFile);

GC::Ref<FileSystemOpenFile> FileSystemOpenFile::create(FileSystemFileHandle& handle, u64 token)
{
    auto& client = page_for(handle.environment())->client();
    return handle.heap().allocate<FileSystemOpenFile>(handle, token, client.origin_private_file_system_release_callback());
}

FileSystemOpenFile::FileSystemOpenFile(FileSystemFileHandle& handle, u64 token, Function<void(u64)> abandon)
    : m_handle(handle)
    , m_token(token)
    , m_abandon(move(abandon))
{
}

void FileSystemOpenFile::visit_edges(GC::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_handle);
}

void FileSystemOpenFile::finalize()
{
    if (m_token != 0 && m_abandon)
        m_abandon(m_token);
}

Reply FileSystemOpenFile::request(Operation operation, u64 offset, ReadonlyBytes chunk)
{
    if (m_token == 0)
        return { Status::Closed };
    auto bytes = ByteBuffer::copy(chunk);
    if (bytes.is_error())
        return { Status::QuotaExceeded };
    auto reply = m_handle->request({ .operation = operation, .token = m_token, .offset = offset, .bytes = bytes.release_value() });
    if (operation == Operation::Commit || operation == Operation::Close) {
        if (reply.status != Status::Success && m_abandon)
            m_abandon(m_token);
        m_token = 0;
    }
    return reply;
}

}
