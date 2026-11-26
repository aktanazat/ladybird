/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/HostClassBuilder.h>
#include <LibJS/Runtime/Array.h>
#include <LibJS/Runtime/PrimitiveString.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileSystem/FileSystemDirectoryHandle.h>
#include <LibWeb/FileSystem/FileSystemDirectoryHandleAsyncIterator.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemDirectoryHandleAsyncIterator);

static constexpr JSHostClass iterator_host_class = JS::make_host_class(JS_HOST_CLASS_OBJECT, "FileSystemDirectoryHandleAsyncIterator"sv, nullptr, nullptr, nullptr, 0);

FileSystemDirectoryHandleAsyncIterator::FileSystemDirectoryHandleAsyncIterator(JS::Realm& realm, JS::Object::PropertyKind kind, FileSystemDirectoryHandle& directory)
    : AsyncIterator(realm, kind)
    , m_directory(directory)
{
}

GC::Ref<JS::HostObject> FileSystemDirectoryHandleAsyncIterator::create(JS::Realm& realm, JS::Object::PropertyKind kind, FileSystemDirectoryHandle& directory)
{
    auto iterator = realm.create<FileSystemDirectoryHandleAsyncIterator>(realm, kind, directory);
    auto& prototype = Bindings::ensure_web_prototype<Bindings::FileSystemDirectoryHandleAsyncIteratorPrototype>(realm, "FileSystemDirectoryHandleAsyncIterator"_utf16_fly_string);
    return JS::HostObject::create(realm, iterator_host_class, prototype, {}, iterator);
}

void FileSystemDirectoryHandleAsyncIterator::visit_edges(GC::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_directory);
}

// https://fs.spec.whatwg.org/#directory-iteration
GC::Ref<WebIDL::Promise> FileSystemDirectoryHandleAsyncIterator::next_iteration_result(JS::Realm&)
{
    // On the storage queue, locate the directory and find a child not in past results.
    auto convert = GC::create_function(heap(), GC::captures(*this), [](auto& self, Reply& reply) -> JS::Value {
        auto& realm = self.promise_realm();
        for (auto const& child : reply.entries) {
            if (self.m_past_results.set(child.name) != AK::HashSetResult::InsertedNewEntry)
                continue;

            // Append the name to past results and return the key, handle, or key-handle pair.
            auto name = JS::PrimitiveString::create(realm.vm(), Utf16String::from_utf8(child.name));
            if (self.iteration_kind() == JS::Object::PropertyKind::Key)
                return name;
            auto handle = self.m_directory->child_handle(child.name, child.is_directory);
            auto wrapper = Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, handle);
            if (self.iteration_kind() == JS::Object::PropertyKind::Value)
                return wrapper;
            return JS::Array::create_from(realm, { name, wrapper });
        }
        // If no unvisited children remain, signal the end of iteration.
        return JS::js_special_empty_value();
    });
    return m_directory->run_operation({ Operation::List, m_directory->path() }, convert);
}

}
