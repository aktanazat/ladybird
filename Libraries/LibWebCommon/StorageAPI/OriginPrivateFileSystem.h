/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/String.h>
#include <AK/Vector.h>
#include <LibGC/Forward.h>
#include <LibIPC/Forward.h>
#include <LibWebCommon/Export.h>

namespace Web::FileSystem {

enum class Operation : u8 {
    OpenRoot,
    GetFile,
    GetDirectory,
    Remove,
    List,
    ReadFile,
};

enum class Status : u8 {
    Unavailable,
    Success,
    InvalidName,
    NotFound,
    TypeMismatch,
    InvalidModification,
    Locked,
    QuotaExceeded,
    IOError,
};

struct Request {
    Operation operation;
    Vector<String> path {};
    String name {};
    bool option { false };
};

struct DirectoryEntry {
    String name;
    bool is_directory;
};

struct Reply {
    Status status { Status::Unavailable };
    Vector<DirectoryEntry> entries {};
    ByteBuffer bytes {};
    i64 last_modified { 0 };
};

}

GC_UNTRACED_CAPTURE(Web::FileSystem::Request);

namespace IPC {

template<> WEBCOMMON_API ErrorOr<void> encode(Encoder&, Web::FileSystem::Request const&);
template<> WEBCOMMON_API ErrorOr<Web::FileSystem::Request> decode(Decoder&);
template<> WEBCOMMON_API ErrorOr<void> encode(Encoder&, Web::FileSystem::Reply const&);
template<> WEBCOMMON_API ErrorOr<Web::FileSystem::Reply> decode(Decoder&);

}
