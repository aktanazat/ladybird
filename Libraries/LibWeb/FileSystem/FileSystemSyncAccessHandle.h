/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibWeb/Bindings/FileSystemSyncAccessHandle.h>
#include <LibWeb/Bindings/RustInterface.h>

namespace Web::FileSystem {

class FileSystemSyncAccessHandle : public Bindings::RustInterfaceCell {
    WEB_RUST_INTERFACE(FileSystemSyncAccessHandle, file_system_sync_access_handle)
};

}
