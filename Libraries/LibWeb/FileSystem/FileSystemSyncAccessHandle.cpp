/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/HostClassBuilder.h>
#include <LibWeb/FileSystem/FileSystemOpenFile.h>

namespace Web::FileSystem {

extern "C" JS::Object* web_rust_file_system_create_sync_access_handle(JSVM*, JS::Realm*, FileSystemOpenFile*);

extern "C" u8 web_file_system_sync_command(FileSystemOpenFile* file, u8 command, u64 offset, u64 length, ReadonlyBytes data, u64* value, void* destination, void (*receive)(void*, ReadonlyBytes));

extern "C" u8 web_file_system_sync_command(FileSystemOpenFile* file, u8 command, u64 offset, u64 length, ReadonlyBytes data, u64* value, void* destination, void (*receive)(void*, ReadonlyBytes))
{
    static constexpr Operation operations[] = { Operation::Read, Operation::Write, Operation::Resize, Operation::Size, Operation::Flush, Operation::Close };
    VERIFY(command < array_size(operations));
    auto reply = file->request(operations[command], offset, data, length);
    if (reply.status != Status::Success)
        return reply.status == Status::QuotaExceeded ? 1 : 2;
    *value = reply.value;
    if (receive)
        receive(destination, reply.bytes.bytes());
    return 0;
}

// https://fs.spec.whatwg.org/#dom-filesystemfilehandle-createsyncaccesshandle
GC::Ref<WebIDL::Promise> FileSystemFileHandle::create_sync_access_handle()
{
    // Locate the entry and take an exclusive lock before creating the new handle in the worker's realm.
    auto convert = GC::create_function(heap(), GC::captures(*this), [](auto& self, Reply& reply) -> JS::Value {
        auto& realm = self.realm();
        auto file = FileSystemOpenFile::create(self, reply.value);
        return web_rust_file_system_create_sync_access_handle(JS::HostABI::vm_to_abi(realm.vm()), &realm, file.ptr());
    });
    return run_operation({ Operation::OpenSync, path() }, convert);
}

}
