/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/FileSystemHandle.h>
#include <LibWeb/Bindings/Wrappable.h>
#include <LibWeb/WebIDL/Promise.h>
#include <LibWebCommon/StorageAPI/OriginPrivateFileSystem.h>
#include <LibWebCommon/StorageAPI/StorageKey.h>

namespace Web::FileSystem {

class FileSystemHandle : public Bindings::GCAllocatedWrappable {
    WEB_WRAPPABLE(FileSystemHandle, Bindings::GCAllocatedWrappable);
    GC_DECLARE_ALLOCATOR(FileSystemHandle);

public:
    Bindings::FileSystemHandleKind kind() const { return m_kind; }
    Utf16String name() const;
    GC::Ref<WebIDL::Promise> is_same_entry(FileSystemHandle const& other) const;

    auto const& path() const { return m_path; }
    auto const& storage_key() const { return m_key; }
    HTML::EnvironmentSettingsObject& environment() const { return *m_environment; }
    JS::Realm& realm() const;

    Reply request(Request const&) const;
    GC::Ref<WebIDL::Promise> run_operation(Request, GC::Ref<GC::Function<JS::Value(Reply&)>>);

protected:
    FileSystemHandle(HTML::EnvironmentSettingsObject&, StorageAPI::StorageKey, Vector<String>, Bindings::FileSystemHandleKind);
    virtual void visit_edges(GC::Cell::Visitor&) override;

private:
    GC::Ref<HTML::EnvironmentSettingsObject> m_environment;
    StorageAPI::StorageKey m_key;
    Vector<String> m_path;
    Bindings::FileSystemHandleKind m_kind;
};

Page* page_for(HTML::EnvironmentSettingsObject&);
Reply request(HTML::EnvironmentSettingsObject&, Request const&);
void reject(JS::Realm&, WebIDL::Promise const&, Status);
GC::Ref<WebIDL::Promise> get_directory(HTML::EnvironmentSettingsObject&);

}
