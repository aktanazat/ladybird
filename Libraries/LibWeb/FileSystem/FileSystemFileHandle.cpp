/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileAPI/File.h>
#include <LibWeb/FileSystem/FileSystemFileHandle.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemFileHandle);

GC::Ref<FileSystemFileHandle> FileSystemFileHandle::create(HTML::EnvironmentSettingsObject& environment, StorageAPI::StorageKey key, Vector<String> path)
{
    return GC::Heap::the().allocate<FileSystemFileHandle>(environment, move(key), move(path));
}

FileSystemFileHandle::FileSystemFileHandle(HTML::EnvironmentSettingsObject& environment, StorageAPI::StorageKey key, Vector<String> path)
    : FileSystemHandle(environment, move(key), move(path), Bindings::FileSystemHandleKind::File)
{
}

// https://fs.spec.whatwg.org/#dom-filesystemfilehandle-getfile
GC::Ref<WebIDL::Promise> FileSystemFileHandle::get_file()
{
    // Locate the file and take a snapshot of its bytes and modification timestamp on the storage queue.
    auto convert = GC::create_function(heap(), GC::captures(*this), [](auto& self, Reply& reply) -> JS::Value {
        auto& realm = self.realm();
        auto file = FileAPI::File::create(reply.bytes.bytes(), self.name(), {}, reply.last_modified);
        return Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, file);
    });
    return run_operation({ Operation::ReadFile, path() }, convert);
}

}
