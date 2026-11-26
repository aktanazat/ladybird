/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibIPC/Decoder.h>
#include <LibIPC/Encoder.h>
#include <LibWebCommon/StorageAPI/OriginPrivateFileSystem.h>

namespace IPC {

using namespace Web::FileSystem;

template<>
ErrorOr<void> encode(Encoder& encoder, Request const& request)
{
    TRY(encoder.encode(to_underlying(request.operation)));
    TRY(encoder.encode(request.path));
    TRY(encoder.encode(request.name));
    TRY(encoder.encode(request.option));
    TRY(encoder.encode(request.token));
    TRY(encoder.encode(request.offset));
    TRY(encoder.encode(request.bytes));
    return encoder.encode(request.length);
}

template<>
ErrorOr<Request> decode(Decoder& decoder)
{
    auto operation = TRY(decoder.decode<u8>());
    if (operation > to_underlying(Operation::Flush))
        return Error::from_string_literal("Invalid file system operation");
    return Request {
        static_cast<Operation>(operation),
        TRY(decoder.decode<Vector<String>>()),
        TRY(decoder.decode<String>()),
        TRY(decoder.decode<bool>()),
        TRY(decoder.decode<u64>()),
        TRY(decoder.decode<u64>()),
        TRY(decoder.decode<ByteBuffer>()),
        TRY(decoder.decode<u64>()),
    };
}

template<>
ErrorOr<void> encode(Encoder& encoder, DirectoryEntry const& entry)
{
    TRY(encoder.encode(entry.name));
    return encoder.encode(entry.is_directory);
}

template<>
ErrorOr<DirectoryEntry> decode(Decoder& decoder)
{
    return DirectoryEntry { TRY(decoder.decode<String>()), TRY(decoder.decode<bool>()) };
}

template<>
ErrorOr<void> encode(Encoder& encoder, Reply const& reply)
{
    TRY(encoder.encode(to_underlying(reply.status)));
    TRY(encoder.encode(reply.entries));
    TRY(encoder.encode(reply.bytes));
    TRY(encoder.encode(reply.last_modified));
    return encoder.encode(reply.value);
}

template<>
ErrorOr<Reply> decode(Decoder& decoder)
{
    auto status = TRY(decoder.decode<u8>());
    if (status > to_underlying(Status::Closed))
        return Error::from_string_literal("Invalid file system status");
    return Reply {
        static_cast<Status>(status),
        TRY(decoder.decode<Vector<DirectoryEntry>>()),
        TRY(decoder.decode<ByteBuffer>()),
        TRY(decoder.decode<i64>()),
        TRY(decoder.decode<u64>()),
    };
}

}
