/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use core::cell::Cell;
use core::ffi::c_void;

use ak::Utf16String;
use libjs_rust::api::{Gc, Object, Realm, Trace, Vm};

use crate::bindings::conversions::{BufferSource, BufferSourceExtent};
use crate::bindings::cpp_cell::CppCell;
use crate::bindings::interface::{Wrappable, allocate, wrap};
use crate::bindings::{CallContext, Exception, WebIdlResult};
use crate::webidl::buffers::AllowSharedBufferSource;

unsafe extern "C" {
    fn web_file_system_sync_command(
        file: *mut c_void,
        operation: u8,
        offset: u64,
        length: u64,
        data: ak::Span<'_, u8>,
        value: &mut u64,
        destination: *mut c_void,
        receive: Option<unsafe extern "C" fn(*mut c_void, ak::Span<'_, u8>)>,
    ) -> u8;
}

pub(crate) struct FileSystemReadWriteOptions {
    pub(crate) at: Option<u64>,
}

#[repr(u8)]
enum Operation {
    Read,
    Write,
    Resize,
    Size,
    Flush,
    Close,
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct FileSystemSyncAccessHandle {
    file: CppCell,
    cursor: Cell<u64>,
    closed: Cell<bool>,
}

impl Wrappable for FileSystemSyncAccessHandle {
    const TRACED_ON_OWNER_THREAD_ONLY: bool = true;
}

impl FileSystemSyncAccessHandle {
    fn ensure_open(&self) -> WebIdlResult<()> {
        if self.closed.get() {
            return Err(invalid_state());
        }
        Ok(())
    }

    fn command(&self, operation: Operation, offset: u64, data: &[u8], target: Option<&mut ReadTarget>) -> WebIdlResult<u64> {
        let (length, destination, receive) = match target {
            Some(target) => (
                target.extent.byte_length as u64,
                (target as *mut ReadTarget).cast(),
                Some(receive_bytes as unsafe extern "C" fn(*mut c_void, ak::Span<'_, u8>)),
            ),
            None => (0, core::ptr::null_mut(), None),
        };
        let mut value = 0;
        // SAFETY: The cell is a live FileSystemOpenFile. The inputs and optional read target are lent for the call.
        let status = unsafe {
            web_file_system_sync_command(self.file.as_ptr(), operation as u8, offset, length, ak::Span::new(data), &mut value, destination, receive)
        };
        match status {
            0 => Ok(value),
            1 => Err(Exception::Dom("QuotaExceededError", Utf16String::from_utf8("The file exceeds the origin private file system's size limit"))),
            _ => Err(invalid_state()),
        }
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-read
    pub(crate) fn read(&self, _: &mut CallContext, buffer: AllowSharedBufferSource, options: FileSystemReadWriteOptions) -> WebIdlResult<u64> {
        self.ensure_open()?;
        let buffer = BufferSource::from(buffer);
        let mut target = ReadTarget { extent: buffer.extent(), read: 0 };
        if target.extent.is_out_of_bounds || target.extent.buffer.is_detached() {
            return Err(Exception::type_error("The destination buffer is detached or out of bounds"));
        }

        // Read starting at the supplied position or the file cursor. The broker clamps reads at EOF.
        let start = options.at.unwrap_or(self.cursor.get());
        let cursor = self.command(Operation::Read, start, &[], Some(&mut target))?;
        self.cursor.set(cursor);
        Ok(target.read as u64)
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-write
    pub(crate) fn write(&self, _: &mut CallContext, buffer: AllowSharedBufferSource, options: FileSystemReadWriteOptions) -> WebIdlResult<u64> {
        self.ensure_open()?;
        let buffer = BufferSource::from(buffer);
        // SAFETY: Only native memory is allocated while copying the bytes.
        let bytes = unsafe { buffer.with_bytes(<[u8]>::to_vec) };
        let position = options.at.unwrap_or(self.cursor.get());
        let written = self.command(Operation::Write, position, &bytes, None)?;
        self.cursor.set(position + written);
        Ok(written)
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-truncate
    pub(crate) fn truncate(&self, _: &mut CallContext, new_size: u64) -> WebIdlResult<()> {
        self.ensure_open()?;
        self.command(Operation::Resize, new_size, &[], None)?;
        self.cursor.set(self.cursor.get().min(new_size));
        Ok(())
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-getsize
    pub(crate) fn get_size(&self, _: &mut CallContext) -> WebIdlResult<u64> {
        self.ensure_open()?;
        self.command(Operation::Size, 0, &[], None)
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-flush
    pub(crate) fn flush(&self, _: &mut CallContext) -> WebIdlResult<()> {
        self.ensure_open()?;
        self.command(Operation::Flush, 0, &[], None)?;
        Ok(())
    }

    // https://fs.spec.whatwg.org/#dom-filesystemsyncaccesshandle-close
    pub(crate) fn close(&self, _: &mut CallContext) -> WebIdlResult<()> {
        if !self.closed.replace(true) {
            // Closing waits for the browser's acknowledgement that the exclusive lock is released.
            let _ = self.command(Operation::Close, 0, &[], None);
        }
        Ok(())
    }
}

fn invalid_state() -> Exception {
    Exception::Dom("InvalidStateError", Utf16String::from_utf8("The sync access handle is unavailable"))
}

struct ReadTarget {
    extent: BufferSourceExtent,
    read: usize,
}

/// # Safety
///
/// The caller passes the live read target and bytes lent for the call.
unsafe extern "C" fn receive_bytes(destination: *mut c_void, bytes: ak::Span<'_, u8>) {
    // SAFETY: The synchronous caller lends a live ReadTarget until this function returns.
    let target = unsafe { &mut *destination.cast::<ReadTarget>() };
    let bytes = bytes.as_slice();
    if !bytes.is_empty() {
        target.extent.buffer.overwrite(target.extent.byte_offset, bytes);
    }
    target.read = bytes.len();
}

/// Creates a dedicated worker's access handle for a locked entry.
///
/// # Safety
///
/// `file` is a live C++ FileSystemOpenFile in the given realm.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_rust_file_system_create_sync_access_handle(vm: &Vm, realm: Gc<Realm>, file: *mut c_void) -> *mut Object {
    // SAFETY: The caller passes a live cell.
    let file = unsafe { CppCell::from_raw(file) };
    let cx = CallContext::new(vm, realm);
    let handle = allocate(vm, |_| FileSystemSyncAccessHandle {
        file,
        cursor: Cell::new(0),
        closed: Cell::new(false),
    });
    wrap(&cx, handle).as_ptr()
}
