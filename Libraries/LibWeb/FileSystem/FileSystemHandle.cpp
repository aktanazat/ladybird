/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibJS/Runtime/Realm.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/FileSystem/FileSystemDirectoryHandle.h>
#include <LibWeb/HTML/EventLoop/EventLoop.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HTML/WorkerGlobalScope.h>
#include <LibWeb/Page/Page.h>
#include <LibWeb/StorageAPI/StorageKey.h>
#include <LibWeb/WebIDL/DOMException.h>
#include <LibWeb/WebIDL/QuotaExceededError.h>

namespace Web::FileSystem {

GC_DEFINE_ALLOCATOR(FileSystemHandle);

FileSystemHandle::FileSystemHandle(HTML::EnvironmentSettingsObject& environment, StorageAPI::StorageKey key, Vector<String> path, Bindings::FileSystemHandleKind kind)
    : m_environment(environment)
    , m_key(move(key))
    , m_path(move(path))
    , m_kind(kind)
{
}

void FileSystemHandle::visit_edges(GC::Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_environment);
}

JS::Realm& FileSystemHandle::realm() const
{
    return m_environment->realm();
}

// https://fs.spec.whatwg.org/#dom-filesystemhandle-name
Utf16String FileSystemHandle::name() const
{
    // The root has an empty name. Otherwise return the last path component.
    if (m_path.is_empty())
        return {};
    return Utf16String::from_utf8(m_path.last());
}

// https://fs.spec.whatwg.org/#dom-filesystemhandle-issameentry
GC::Ref<WebIDL::Promise> FileSystemHandle::is_same_entry(FileSystemHandle const& other) const
{
    // Locators backed by the same bucket, kind and path represent the same entry.
    auto promise = WebIDL::create_promise(realm());
    WebIDL::resolve_promise(promise, JS::Value(m_key == other.m_key && m_kind == other.m_kind && m_path == other.m_path));
    return promise;
}

Page* page_for(HTML::EnvironmentSettingsObject& environment)
{
    auto& global = environment.global_object();
    if (auto* window = Bindings::impl_from<HTML::Window>(&global))
        return &window->page();
    if (auto* worker = Bindings::impl_from<HTML::WorkerGlobalScope>(&global))
        return worker->page();
    return nullptr;
}

Reply request(HTML::EnvironmentSettingsObject& environment, Request const& request)
{
    auto* page = page_for(environment);
    if (!page)
        return {};
    return page->client().request_origin_private_file_system(environment.id, request);
}

Reply FileSystemHandle::request(Request const& command) const
{
    return FileSystem::request(environment(), command);
}

void reject(JS::Realm& realm, WebIDL::Promise const& promise, Status status)
{
    switch (status) {
    case Status::InvalidName:
        WebIDL::reject_promise_with_exception(realm, promise, WebIDL::SimpleException { WebIDL::SimpleExceptionType::TypeError, "Invalid file name"_utf16 });
        return;
    case Status::Unavailable:
        WebIDL::reject_promise(realm, promise, WebIDL::SecurityError::create("The origin private file system is unavailable"_utf16));
        return;
    case Status::NotFound:
        WebIDL::reject_promise(realm, promise, WebIDL::NotFoundError::create("The file system entry does not exist"_utf16));
        return;
    case Status::TypeMismatch:
        WebIDL::reject_promise(realm, promise, WebIDL::TypeMismatchError::create("The entry has a different kind"_utf16));
        return;
    case Status::InvalidModification:
        WebIDL::reject_promise(realm, promise, WebIDL::InvalidModificationError::create("The entry cannot be removed without recursion"_utf16));
        return;
    case Status::Locked:
        WebIDL::reject_promise(realm, promise, WebIDL::NoModificationAllowedError::create("The file system entry is locked"_utf16));
        return;
    case Status::QuotaExceeded:
        WebIDL::reject_promise(realm, promise, WebIDL::QuotaExceededError::create("The file exceeds the origin private file system's size limit"_utf16));
        return;
    case Status::IOError:
        WebIDL::reject_promise(realm, promise, WebIDL::UnknownError::create("The file system operation failed"_utf16));
        return;
    case Status::Closed:
        WebIDL::reject_promise(realm, promise, WebIDL::InvalidStateError::create("The file is closed"_utf16));
        return;
    case Status::Success:
        VERIFY_NOT_REACHED();
    }
    VERIFY_NOT_REACHED();
}

GC::Ref<WebIDL::Promise> FileSystemHandle::run_operation(Request command, GC::Ref<GC::Function<JS::Value(Reply&)>> convert)
{
    auto promise = WebIDL::create_promise(realm());
    // The browser serializes requests on its storage queue. Complete the promise on the storage task source.
    HTML::queue_global_task(HTML::Task::Source::Storage, environment().global_object(),
        GC::create_function(heap(), GC::captures(*this, promise, move(command), convert), [](auto& self, auto& promise, auto& command, auto& convert) {
            auto reply = self.request(command);
            if (reply.status != Status::Success) {
                reject(self.realm(), promise, reply.status);
                return;
            }
            WebIDL::resolve_promise(promise, convert->function()(reply));
        }));
    return promise;
}

// https://fs.spec.whatwg.org/#dom-storagemanager-getdirectory
GC::Ref<WebIDL::Promise> get_directory(HTML::EnvironmentSettingsObject& environment)
{
    // 1–2. Let promise be a new promise and let settings be this's relevant settings object.
    auto& realm = environment.realm();
    auto promise = WebIDL::create_promise(realm);

    // 3. Obtain the default storage bucket's file system and resolve with a handle to its root.
    HTML::queue_global_task(HTML::Task::Source::Storage, environment.global_object(),
        GC::create_function(realm.heap(), GC::captures(environment, promise), [](auto& environment, auto& promise) {
            auto& realm = environment.realm();
            auto key = StorageAPI::obtain_a_storage_key(environment);
            if (!key.has_value()) {
                reject(realm, promise, Status::Unavailable);
                return;
            }
            auto reply = request(environment, { Operation::OpenRoot });
            if (reply.status != Status::Success) {
                reject(realm, promise, reply.status);
                return;
            }
            auto directory = FileSystemDirectoryHandle::create(environment, key.release_value(), {});
            WebIDL::resolve_promise(promise, Bindings::wrap(Bindings::host_defined_wrapper_world(realm), realm, directory));
        }));

    // 4. Return promise.
    return promise;
}

}
