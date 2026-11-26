/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/FileSystemFileHandle.h>
#include <LibWeb/FileSystem/FileSystemHandle.h>

namespace Web::FileSystem {

class FileSystemFileHandle final : public FileSystemHandle {
    WEB_WRAPPABLE(FileSystemFileHandle, FileSystemHandle);
    GC_DECLARE_ALLOCATOR(FileSystemFileHandle);

public:
    static GC::Ref<FileSystemFileHandle> create(HTML::EnvironmentSettingsObject&, StorageAPI::StorageKey, Vector<String>);
    GC::Ref<WebIDL::Promise> get_file();
    GC::Ref<WebIDL::Promise> create_writable(Bindings::FileSystemCreateWritableOptions const&);

private:
    FileSystemFileHandle(HTML::EnvironmentSettingsObject&, StorageAPI::StorageKey, Vector<String>);
};

}
