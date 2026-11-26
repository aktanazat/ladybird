/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use core::cell::Cell;
use core::ffi::c_void;

use libjs_rust::api::{EmbedderClass, EmbedderValue, Gc, Object, PropertyKey, Realm, Trace, Value, Vm};

use crate::bindings::conversions::{BufferSource, FromJs, ToJs, UsvString};
use crate::bindings::cpp_cell::CppCell;
use crate::bindings::interface::{Inherits, Ref, Wrappable, allocate, create_dictionary_object, set_dictionary_member, wrap};
use crate::bindings::promise::{WebIdlPromise, create_rejected_promise_from_exception, create_resolved_promise, promise_from_abi};
use crate::bindings::{CallContext, Exception, MustNotThrow, WebIdlResult};
use crate::file_api::blob::{AnyBlob, BlobPart};
use crate::streams::algorithms::{AbortAlgorithm, CloseAlgorithm, SizeAlgorithm, StartAlgorithm, WriteAlgorithm};
use crate::streams::writable_stream::{WritableStream, acquire_writable_stream_default_writer, create_writable_stream};
use crate::streams::writable_stream_default_writer::{writable_stream_default_writer_release, writable_stream_default_writer_write};

unsafe extern "C" {
    fn web_file_system_writable_command(
        file: *mut c_void,
        command: u8,
        offset: u64,
        bytes: ak::Span<'_, u8>,
        success: &mut bool,
    ) -> *mut c_void;
    fn web_file_system_abandon_writable(file: *mut c_void);
}

#[derive(Clone, Copy)]
pub(crate) enum WriteCommandType {
    Write,
    Seek,
    Truncate,
}

pub(crate) struct WriteParams {
    pub(crate) r#type: WriteCommandType,
    pub(crate) size: Option<Option<u64>>,
    pub(crate) position: Option<Option<u64>>,
    pub(crate) data: Option<Option<BlobPart>>,
}

pub(crate) enum FileSystemWriteChunkType {
    BufferSource(BufferSource),
    Blob(AnyBlob),
    USVString(UsvString),
    WriteParams(WriteParams),
}

#[repr(u8)]
enum BrokerCommand {
    Write,
    Resize,
    Commit,
    Close,
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct WritableFile {
    file: CppCell,
    cursor: Cell<u64>,
}

static WRITABLE_FILE_CLASS: EmbedderClass<WritableFile> =
    EmbedderClass::new("OPFS Writable File").traced_on_owner_thread_only();

impl EmbedderValue for WritableFile {
    const CLASS: &'static EmbedderClass<Self> = &WRITABLE_FILE_CLASS;
}

impl WritableFile {
    fn command(&self, command: BrokerCommand, offset: u64, bytes: &[u8]) -> (WebIdlPromise, bool) {
        let mut success = false;
        // SAFETY: This cell is a live FileSystemOpenFile. The command borrows the bytes and returns a live promise.
        let promise = unsafe {
            promise_from_abi(web_file_system_writable_command(
                self.file.as_ptr(), command as u8, offset, ak::Span::new(bytes), &mut success,
            ))
        };
        (promise, success)
    }

    // https://fs.spec.whatwg.org/#write-a-chunk
    pub(crate) fn write(&self, cx: &CallContext, chunk: Value) -> WebIdlPromise {
        // 1. Convert the chunk to FileSystemWriteChunkType, including writes made through a default writer.
        match self.write_chunk(cx, chunk) {
            Ok(promise) => promise,
            Err(exception) => {
                // The write error puts the stream into the errored state, so discard the staging buffer.
                self.abandon();
                create_rejected_promise_from_exception(cx.vm(), cx.realm(), exception)
            }
        }
    }

    fn write_chunk(&self, cx: &CallContext, chunk: Value) -> WebIdlResult<WebIdlPromise> {
        let input = FileSystemWriteChunkType::from_js(cx.vm(), chunk)?;
        // OPFS grants readwrite access to the bucket. Apply the command to its independent staging buffer.
        let mut position = self.cursor.get();
        let data = match input {
            FileSystemWriteChunkType::BufferSource(buffer) => BlobPart::BufferSource(buffer),
            FileSystemWriteChunkType::Blob(blob) => BlobPart::Blob(blob),
            FileSystemWriteChunkType::USVString(string) => BlobPart::USVString(string),
            FileSystemWriteChunkType::WriteParams(params) => match params.r#type {
                WriteCommandType::Seek => {
                    let position = params.position.flatten().ok_or_else(|| Exception::type_error("Seek requires a position"))?;
                    self.cursor.set(position);
                    return Ok(create_resolved_promise(cx.vm(), cx.realm(), Value::UNDEFINED));
                }
                WriteCommandType::Truncate => {
                    let size = params.size.flatten().ok_or_else(|| Exception::type_error("Truncate requires a size"))?;
                    let (promise, success) = self.command(BrokerCommand::Resize, size, &[]);
                    if success {
                        self.cursor.set(self.cursor.get().min(size));
                    } else {
                        self.abandon();
                    }
                    return Ok(promise);
                }
                WriteCommandType::Write => {
                    if let Some(offset) = params.position.flatten() {
                        position = offset;
                    }
                    params.data.flatten().ok_or_else(|| Exception::type_error("Write requires data"))?
                }
            },
        };
        let bytes = match &data {
            BlobPart::BufferSource(buffer) => {
                // SAFETY: Only native memory is allocated while copying the bytes.
                unsafe { buffer.with_bytes(<[u8]>::to_vec) }
            }
            BlobPart::Blob(blob) => blob.raw_bytes().to_vec(),
            BlobPart::USVString(string) => string.to_utf8().into_bytes(),
        };
        let (promise, success) = self.command(BrokerCommand::Write, position, &bytes);
        if success {
            self.cursor.set(position + bytes.len() as u64);
        } else {
            self.abandon();
        }
        Ok(promise)
    }

    pub(crate) fn close(&self) -> WebIdlPromise {
        self.command(BrokerCommand::Commit, 0, &[]).0
    }

    pub(crate) fn abort(&self) -> WebIdlPromise {
        self.command(BrokerCommand::Close, 0, &[]).0
    }

    fn abandon(&self) {
        // SAFETY: This cell is a live FileSystemOpenFile.
        unsafe { web_file_system_abandon_writable(self.file.as_ptr()) };
    }
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct FileSystemWritableFileStream {
    stream: Ref<WritableStream>,
}

impl Wrappable for FileSystemWritableFileStream {
    const TRACED_ON_OWNER_THREAD_ONLY: bool = true;
}

impl Inherits<WritableStream> for FileSystemWritableFileStream {
    fn parent(&self) -> &WritableStream {
        &self.stream
    }
}

impl FileSystemWritableFileStream {
    pub(crate) fn stream(&self) -> Ref<WritableStream> {
        self.stream
    }

    // https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-write
    pub(crate) fn write(&self, cx: &mut CallContext, data: FileSystemWriteChunkType) -> WebIdlResult<WebIdlPromise> {
        let chunk = match data {
            FileSystemWriteChunkType::BufferSource(buffer) => buffer.to_js(cx)?,
            FileSystemWriteChunkType::Blob(blob) => blob_to_js(cx, blob),
            FileSystemWriteChunkType::USVString(string) => string.to_js(cx)?,
            FileSystemWriteChunkType::WriteParams(params) => {
                let object = command_object(cx, params.r#type)?;
                if let Some(size) = params.size {
                    set_dictionary_member(cx, object, &PropertyKey::from_utf8("size"), nullable_number(size))?;
                }
                if let Some(position) = params.position {
                    set_dictionary_member(cx, object, &PropertyKey::from_utf8("position"), nullable_number(position))?;
                }
                if let Some(data) = params.data {
                    let data = match data {
                        None => Value::NULL,
                        Some(BlobPart::BufferSource(buffer)) => buffer.to_js(cx)?,
                        Some(BlobPart::Blob(blob)) => blob_to_js(cx, blob),
                        Some(BlobPart::USVString(string)) => string.to_js(cx)?,
                    };
                    set_dictionary_member(cx, object, &PropertyKey::from_utf8("data"), data)?;
                }
                Value::from_object(object)
            }
        };
        self.write_to_stream(cx, chunk)
    }

    // https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-seek
    pub(crate) fn seek(&self, cx: &mut CallContext, position: u64) -> WebIdlResult<WebIdlPromise> {
        let command = command_object(cx, WriteCommandType::Seek)?;
        set_dictionary_member(cx, command, &PropertyKey::from_utf8("position"), Value::from_f64(position as f64))?;
        self.write_to_stream(cx, Value::from_object(command))
    }

    // https://fs.spec.whatwg.org/#dom-filesystemwritablefilestream-truncate
    pub(crate) fn truncate(&self, cx: &mut CallContext, size: u64) -> WebIdlResult<WebIdlPromise> {
        let command = command_object(cx, WriteCommandType::Truncate)?;
        set_dictionary_member(cx, command, &PropertyKey::from_utf8("size"), Value::from_f64(size as f64))?;
        self.write_to_stream(cx, Value::from_object(command))
    }

    fn write_to_stream(&self, cx: &CallContext, chunk: Value) -> WebIdlResult<WebIdlPromise> {
        // Acquire a writer, queue the write, then release the stream's writer lock.
        let writer = acquire_writable_stream_default_writer(cx, self.stream)?;
        let promise = writable_stream_default_writer_write(cx.vm(), writer, chunk);
        writable_stream_default_writer_release(cx.vm(), writer);
        Ok(promise)
    }
}

fn nullable_number(value: Option<u64>) -> Value {
    value.map_or(Value::NULL, |value| Value::from_f64(value as f64))
}

fn blob_to_js(cx: &CallContext, blob: AnyBlob) -> Value {
    Value::from_object(match blob {
        AnyBlob::Blob(blob) => wrap(cx, blob),
        AnyBlob::File(file) => wrap(cx, file),
    })
}

fn command_object(cx: &CallContext, command: WriteCommandType) -> WebIdlResult<Gc<Object>> {
    let object = create_dictionary_object(cx);
    // Define absent members as undefined to keep the internal command independent of Object.prototype.
    for name in ["size", "position", "data"] {
        set_dictionary_member(cx, object, &PropertyKey::from_utf8(name), Value::UNDEFINED)?;
    }
    let name = match command {
        WriteCommandType::Write => "write",
        WriteCommandType::Seek => "seek",
        WriteCommandType::Truncate => "truncate",
    };
    set_dictionary_member(cx, object, &PropertyKey::from_utf8("type"), ak::Utf16String::from_utf8(name).to_js(cx)?)?;
    Ok(object)
}

/// Create a writable stream for a locked OPFS entry and return its JavaScript wrapper.
///
/// # Safety
///
/// `file` is a live C++ FileSystemOpenFile in the given realm.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn web_rust_file_system_create_writable(
    vm: &Vm,
    realm: Gc<Realm>,
    file: *mut c_void,
) -> *mut Object {
    // SAFETY: The caller passes a live cell.
    let file = unsafe { CppCell::from_raw(file) };
    let cx = CallContext::new(vm, realm);

    // https://fs.spec.whatwg.org/#create-a-new-filesystemwritablefilestream
    // Set up the stream with write, close and abort algorithms and a high-water mark of one.
    let file = WritableFile { file, cursor: Cell::new(0) };
    let file = WRITABLE_FILE_CLASS.allocate(vm, |_| file);
    let stream = create_writable_stream(
        &cx,
        StartAlgorithm::ReturnsUndefined,
        WriteAlgorithm::FileSystem(file),
        CloseAlgorithm::FileSystem(file),
        AbortAlgorithm::FileSystem(file),
        1.0,
        SizeAlgorithm::ReturnsOne,
    ).must();
    wrap(&cx, allocate(vm, |_| FileSystemWritableFileStream { stream })).as_ptr()
}
