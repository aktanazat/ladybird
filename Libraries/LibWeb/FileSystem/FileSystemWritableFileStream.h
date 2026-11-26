/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/FileSystemWritableFileStream.h>
#include <LibWeb/Streams/WritableStream.h>

namespace Web::FileSystem {

class FileSystemWritableFileStream : public Streams::WritableStream {
    WEB_RUST_INTERFACE(FileSystemWritableFileStream, file_system_writable_file_stream)
};

}
