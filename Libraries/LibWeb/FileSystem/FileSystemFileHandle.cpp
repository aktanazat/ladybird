/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/HostClassBuilder.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileAPI/File.h>
#include <LibWeb/FileSystem/FileSystemFileHandle.h>
#include <LibWeb/FileSystem/FileSystemOpenFile.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemFileHandle);

extern "C" JS::Object* web_rust_file_system_create_writable(JSVM*, JS::Realm*, FileSystemOpenFile*);

extern "C" WebIDL::Promise* web_file_system_writable_command(FileSystemOpenFile* file, u8 command, u64 offset, ReadonlyBytes bytes, bool* success);
extern "C" void web_file_system_abandon_writable(FileSystemOpenFile* file);

extern "C" WebIDL::Promise* web_file_system_writable_command(FileSystemOpenFile* file, u8 command, u64 offset, ReadonlyBytes bytes, bool* success)
{
    static constexpr Operation operations[] = { Operation::Write, Operation::Resize, Operation::Commit, Operation::Close };
    VERIFY(command < array_size(operations));
    auto& realm = file->realm();
    auto reply = file->request(operations[command], offset, bytes);
    auto promise = WebIDL::create_promise(realm);
    *success = reply.status == Status::Success;
    if (*success)
        WebIDL::resolve_promise(promise);
    else
        reject(realm, promise, reply.status);
    return promise.ptr();
}

extern "C" void web_file_system_abandon_writable(FileSystemOpenFile* file)
{
    (void)file->request(Operation::Close);
}

// https://fs.spec.whatwg.org/#dom-filesystemfilehandle-createwritable
GC::Ref<WebIDL::Promise> FileSystemFileHandle::create_writable(Bindings::FileSystemCreateWritableOptions const& options)
{
    // Locate the entry, take a shared lock and optionally snapshot its existing data.
    auto convert = GC::create_function(heap(), GC::captures(*this), [](auto& self, Reply& reply) -> JS::Value {
        auto& realm = self.realm();
        auto file = FileSystemOpenFile::create(self, reply.value);
        return web_rust_file_system_create_writable(JS::HostABI::vm_to_abi(realm.vm()), &realm, file.ptr());
    });
    return run_operation({ .operation = Operation::OpenWritable, .path = path(), .option = options.keep_existing_data }, convert);
}

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
