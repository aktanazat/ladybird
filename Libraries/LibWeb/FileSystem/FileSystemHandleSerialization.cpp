/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/StringBuilder.h>
#include <LibJS/Runtime/Realm.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileSystem/FileSystemDirectoryHandle.h>
#include <LibWeb/FileSystem/FileSystemFileHandle.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/StorageAPI/StorageKey.h>

namespace Web::FileSystem {

extern "C" {
bool web_file_system_serialize_handle(JS::Object*, void*, void (*)(void*, bool, ReadonlyBytes, ReadonlyBytes));
JS::Object* web_file_system_deserialize_handle(JS::Realm*, u16 interface_name, bool opaque, ReadonlyBytes origin, ReadonlyBytes path);
}

// https://fs.spec.whatwg.org/#api-filesystemhandle
bool web_file_system_serialize_handle(JS::Object* object, void* state, void (*write)(void*, bool, ReadonlyBytes, ReadonlyBytes))
{
    auto* handle = Bindings::impl_from<FileSystemHandle>(object);
    if (!handle)
        return false;

    StringBuilder path;
    for (auto const& component : handle->path()) {
        if (!path.is_empty() && path.try_append('/').is_error())
            return false;
        if (path.try_append(component).is_error())
            return false;
    }

    auto origin = handle->environment().origin();
    if (origin.is_opaque()) {
        auto const& nonce = origin.opaque_data().nonce;
        write(state, true, { nonce.data(), nonce.size() }, path.string_view().bytes());
    } else {
        auto serialized_origin = origin.serialize();
        write(state, false, serialized_origin.bytes(), path.string_view().bytes());
    }
    return true;
}

JS::Object* web_file_system_deserialize_handle(JS::Realm* realm, u16 interface_name, bool opaque, ReadonlyBytes origin_bytes, ReadonlyBytes path_bytes)
{
    // 1. Reject a handle serialized by an origin other than the target realm's origin.
    auto& environment = HTML::relevant_settings_object(realm->global_object());
    auto origin = environment.origin();
    if (opaque != origin.is_opaque())
        return nullptr;
    if (opaque) {
        auto const& nonce = origin.opaque_data().nonce;
        if (ReadonlyBytes { nonce.data(), nonce.size() } != origin_bytes)
            return nullptr;
    } else {
        auto serialized_origin = origin.serialize();
        if (serialized_origin.bytes() != origin_bytes)
            return nullptr;
    }

    // 2. Restore the locator within the target environment's storage bucket.
    auto key = StorageAPI::obtain_a_storage_key(environment);
    if (!key.has_value())
        return nullptr;

    Vector<String> path;
    if (!path_bytes.is_empty()) {
        for (auto component : StringView { path_bytes }.split_view('/', SplitBehavior::KeepEmpty)) {
            if (component.is_empty() || component == "."sv || component == ".."sv || component.contains('\0'))
                return nullptr;
            auto name = String::from_utf8(component);
            if (name.is_error() || path.try_append(name.release_value()).is_error())
                return nullptr;
        }
    }
    auto& wrapper_world = Bindings::host_defined_wrapper_world(*realm);
    if (interface_name == to_underlying(Bindings::InterfaceName::FileSystemDirectoryHandle))
        return Bindings::wrap(wrapper_world, *realm, FileSystemDirectoryHandle::create(environment, key.release_value(), move(path))).ptr();
    if (interface_name == to_underlying(Bindings::InterfaceName::FileSystemFileHandle) && !path.is_empty())
        return Bindings::wrap(wrapper_world, *realm, FileSystemFileHandle::create(environment, key.release_value(), move(path))).ptr();
    return nullptr;
}

}
