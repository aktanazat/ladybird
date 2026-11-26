/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/FileSystemDirectoryHandle.h>
#include <LibWeb/FileSystem/FileSystemHandle.h>

namespace Web::FileSystem {

class FileSystemDirectoryHandle final : public FileSystemHandle {
    WEB_WRAPPABLE(FileSystemDirectoryHandle, FileSystemHandle);
    GC_DECLARE_ALLOCATOR(FileSystemDirectoryHandle);

public:
    static GC::Ref<FileSystemDirectoryHandle> create(HTML::EnvironmentSettingsObject&, StorageAPI::StorageKey, Vector<String>);

    GC::Ref<WebIDL::Promise> get_file_handle(Utf16String const&, Bindings::FileSystemGetFileOptions const&);
    GC::Ref<WebIDL::Promise> get_directory_handle(Utf16String const&, Bindings::FileSystemGetDirectoryOptions const&);
    GC::Ref<WebIDL::Promise> remove_entry(Utf16String const&, Bindings::FileSystemRemoveOptions const&);
    GC::Ref<WebIDL::Promise> resolve(FileSystemHandle const& possible_descendant) const;

    GC::Ref<FileSystemHandle> child_handle(String const&, bool is_directory) const;

private:
    FileSystemDirectoryHandle(HTML::EnvironmentSettingsObject&, StorageAPI::StorageKey, Vector<String>);
    GC::Ref<WebIDL::Promise> get_child(Utf16String const&, Operation, bool create);
};

}
