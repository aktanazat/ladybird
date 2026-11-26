/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use core::ffi::c_void;
use core::ptr::NonNull;

use ak::{Span, Utf16String};
use libjs_rust::api::{Gc, Object, Realm, Value};

use crate::bindings::structured_data::{SerializationReader, SerializationWriter};
use crate::bindings::{Exception, WebIdlResult};

unsafe extern "C" {
    fn web_file_system_serialize_handle(
        object: *mut c_void,
        state: *mut c_void,
        write: unsafe extern "C" fn(*mut c_void, bool, Span<'_, u8>, Span<'_, u8>),
    ) -> bool;
    fn web_file_system_deserialize_handle(
        realm: *mut c_void,
        interface_name: u16,
        opaque: bool,
        origin: Span<'_, u8>,
        path: Span<'_, u8>,
    ) -> *mut c_void;
}

fn data_clone_error() -> Exception {
    Exception::Dom(
        "DataCloneError",
        Utf16String::from_utf8("Cannot deserialize a file system handle for this origin"),
    )
}

/// https://fs.spec.whatwg.org/#api-filesystemhandle
pub(crate) fn serialization_steps(object: Gc<Object>, serialized: &mut SerializationWriter) -> WebIdlResult<()> {
    unsafe extern "C" fn write_fields(state: *mut c_void, opaque: bool, origin: Span<'_, u8>, path: Span<'_, u8>) {
        // SAFETY: The serializer and the byte slices are lent for this call.
        let writer = unsafe { &mut *state.cast::<SerializationWriter>() };
        // 1. Set serialized.[[Origin]] to the handle's relevant settings object's origin.
        writer.write_bool(opaque);
        writer.write_bytes(origin.as_slice());
        // 2. Set serialized.[[Locator]] to the handle's locator. Its kind is the serialized interface.
        writer.write_bytes(path.as_slice());
    }

    // SAFETY: The object and writer are live, and the callback writes only borrowed data.
    if unsafe {
        web_file_system_serialize_handle(
            object.as_ptr().cast(),
            core::ptr::from_mut(serialized).cast(),
            write_fields,
        )
    } {
        Ok(())
    } else {
        Err(Exception::Dom(
            "DataCloneError",
            Utf16String::from_utf8("Cannot serialize the file system handle"),
        ))
    }
}

pub(crate) fn deserialization_steps(
    realm: Gc<Realm>,
    interface_name: u16,
    serialized: &mut SerializationReader,
) -> WebIdlResult<Value> {
    let opaque = serialized.read_bool()?;
    let origin = serialized.read_borrowed_bytes()?;
    let path = serialized.read_borrowed_bytes()?;
    // SAFETY: The realm is live and the byte slices are lent for the call.
    let wrapper = unsafe {
        web_file_system_deserialize_handle(
            realm.as_ptr().cast(),
            interface_name,
            opaque,
            Span::new(origin),
            Span::new(path),
        )
    };
    let wrapper = NonNull::new(wrapper.cast::<Object>()).ok_or_else(data_clone_error)?;
    // SAFETY: LibWeb returns a live wrapper in the given realm.
    Ok(Value::from_object(unsafe { Gc::from_non_null(wrapper) }))
}
