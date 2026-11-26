/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/Array.h>
#include <LibJS/Runtime/PrimitiveString.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileSystem/FileSystemDirectoryHandle.h>
#include <LibWeb/FileSystem/FileSystemFileHandle.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemDirectoryHandle);

GC::Ref<FileSystemDirectoryHandle> FileSystemDirectoryHandle::create(HTML::EnvironmentSettingsObject& environment, StorageAPI::StorageKey key, Vector<String> path)
{
    return GC::Heap::the().allocate<FileSystemDirectoryHandle>(environment, move(key), move(path));
}

FileSystemDirectoryHandle::FileSystemDirectoryHandle(HTML::EnvironmentSettingsObject& environment, StorageAPI::StorageKey key, Vector<String> path)
    : FileSystemHandle(environment, move(key), move(path), Bindings::FileSystemHandleKind::Directory)
{
}

GC::Ref<FileSystemHandle> FileSystemDirectoryHandle::child_handle(String const& name, bool is_directory) const
{
    auto child_path = path();
    child_path.append(name);
    if (is_directory)
        return FileSystemDirectoryHandle::create(environment(), storage_key(), move(child_path));
    return FileSystemFileHandle::create(environment(), storage_key(), move(child_path));
}

GC::Ref<WebIDL::Promise> FileSystemDirectoryHandle::get_child(Utf16String const& name, Operation operation, bool create)
{
    // The storage queue validates the name, locates this directory, and either finds or creates the child.
    // If it succeeds, resolve the promise with a handle to the child's locator.
    auto child_name = name.to_utf8();
    auto convert = GC::create_function(heap(), GC::captures(*this, child_name, operation == Operation::GetDirectory), [](auto& self, auto& child_name, auto& is_directory, Reply&) -> JS::Value {
        auto& realm = self.realm();
        return Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, self.child_handle(child_name, is_directory));
    });
    return run_operation({ operation, path(), move(child_name), create }, convert);
}

// https://fs.spec.whatwg.org/#dom-filesystemdirectoryhandle-getfilehandle
GC::Ref<WebIDL::Promise> FileSystemDirectoryHandle::get_file_handle(Utf16String const& name, Bindings::FileSystemGetFileOptions const& options)
{
    return get_child(name, Operation::GetFile, options.create);
}

// https://fs.spec.whatwg.org/#dom-filesystemdirectoryhandle-getdirectoryhandle
GC::Ref<WebIDL::Promise> FileSystemDirectoryHandle::get_directory_handle(Utf16String const& name, Bindings::FileSystemGetDirectoryOptions const& options)
{
    return get_child(name, Operation::GetDirectory, options.create);
}

// https://fs.spec.whatwg.org/#dom-filesystemdirectoryhandle-removeentry
GC::Ref<WebIDL::Promise> FileSystemDirectoryHandle::remove_entry(Utf16String const& name, Bindings::FileSystemRemoveOptions const& options)
{
    // Validate the name and remove the child on the storage queue, recursing only when requested.
    auto convert = GC::create_function(heap(), [](Reply&) -> JS::Value { return JS::js_undefined(); });
    return run_operation({ Operation::Remove, path(), name.to_utf8(), options.recursive }, convert);
}

// https://fs.spec.whatwg.org/#dom-filesystemdirectoryhandle-resolve
GC::Ref<WebIDL::Promise> FileSystemDirectoryHandle::resolve(FileSystemHandle const& child) const
{
    auto& realm = this->realm();
    auto result = WebIDL::create_promise(realm);
    auto const& root_path = path();
    auto const& child_path = child.path();

    // A different file system root or a non-matching path prefix resolves to null.
    if (storage_key() != child.storage_key() || root_path.size() > child_path.size()) {
        WebIDL::resolve_promise(result, JS::js_null());
        return result;
    }
    for (size_t i = 0; i < root_path.size(); ++i) {
        if (root_path[i] != child_path[i]) {
            WebIDL::resolve_promise(result, JS::js_null());
            return result;
        }
    }

    // Resolve with the path segments beyond the directory's path.
    auto relative_path = JS::Array::create_from<String>(realm, child_path.span().slice(root_path.size()), [&](auto const& component) {
        return JS::PrimitiveString::create(realm.vm(), Utf16String::from_utf8(component));
    });
    WebIDL::resolve_promise(result, relative_path);
    return result;
}

}
