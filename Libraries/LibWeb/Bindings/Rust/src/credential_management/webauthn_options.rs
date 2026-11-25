/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use ak::Utf16String;
use libjs_rust::api::{ArrayBuffer, ArrayBufferShared, Gc, MarkedVec, Trace};

use crate::bindings::conversions::BufferSource;
use crate::bindings::{CallContext, Exception, WebIdlResult};

#[derive(Clone)]
pub(crate) struct PublicKeyCredentialRpEntity {
    pub(crate) name: Utf16String,
    pub(crate) id: Option<Utf16String>,
}

#[derive(Clone)]
pub(crate) struct PublicKeyCredentialUserEntity {
    pub(crate) name: Utf16String,
    pub(crate) display_name: Utf16String,
    pub(crate) id: BufferSource,
}

pub(crate) struct PublicKeyCredentialUserEntityJSON {
    pub(crate) name: Utf16String,
    pub(crate) display_name: Utf16String,
    pub(crate) id: Utf16String,
}

#[derive(Clone)]
pub(crate) struct PublicKeyCredentialParameters {
    pub(crate) r#type: Utf16String,
    pub(crate) alg: i32,
}

#[derive(Clone, Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct PublicKeyCredentialDescriptor {
    pub(crate) r#type: Utf16String,
    pub(crate) id: BufferSource,
    pub(crate) transports: Option<Vec<Utf16String>>,
}

pub(crate) struct PublicKeyCredentialDescriptorJSON {
    pub(crate) r#type: Utf16String,
    pub(crate) id: Utf16String,
    pub(crate) transports: Option<Vec<Utf16String>>,
}

#[derive(Clone)]
pub(crate) struct AuthenticatorSelectionCriteria {
    pub(crate) authenticator_attachment: Option<Utf16String>,
    pub(crate) resident_key: Option<Utf16String>,
    pub(crate) require_resident_key: bool,
    pub(crate) user_verification: Utf16String,
}

#[derive(Clone)]
pub(crate) struct AuthenticationExtensionsClientInputs {
    pub(crate) cred_props: Option<bool>,
}

pub(crate) struct PublicKeyCredentialCreationOptions<'vm> {
    pub(crate) rp: PublicKeyCredentialRpEntity,
    pub(crate) user: PublicKeyCredentialUserEntity,
    pub(crate) challenge: BufferSource,
    pub(crate) pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub(crate) timeout: Option<u32>,
    pub(crate) exclude_credentials: MarkedVec<'vm, PublicKeyCredentialDescriptor>,
    pub(crate) authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) attestation: Utf16String,
    pub(crate) attestation_formats: Vec<Utf16String>,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
}

pub(crate) struct PublicKeyCredentialRequestOptions<'vm> {
    pub(crate) challenge: BufferSource,
    pub(crate) timeout: Option<u32>,
    pub(crate) rp_id: Option<Utf16String>,
    pub(crate) allow_credentials: MarkedVec<'vm, PublicKeyCredentialDescriptor>,
    pub(crate) user_verification: Utf16String,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
}

pub(crate) struct PublicKeyCredentialCreationOptionsJSON {
    pub(crate) rp: PublicKeyCredentialRpEntity,
    pub(crate) user: PublicKeyCredentialUserEntityJSON,
    pub(crate) challenge: Utf16String,
    pub(crate) pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub(crate) timeout: Option<u32>,
    pub(crate) exclude_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    pub(crate) authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) attestation: Utf16String,
    pub(crate) attestation_formats: Vec<Utf16String>,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
}

pub(crate) struct PublicKeyCredentialRequestOptionsJSON {
    pub(crate) challenge: Utf16String,
    pub(crate) timeout: Option<u32>,
    pub(crate) rp_id: Option<Utf16String>,
    pub(crate) allow_credentials: Vec<PublicKeyCredentialDescriptorJSON>,
    pub(crate) user_verification: Utf16String,
    pub(crate) hints: Vec<Utf16String>,
    pub(crate) extensions: Option<AuthenticationExtensionsClientInputs>,
}

pub(super) fn string(value: &Utf16String) -> String {
    String::from_utf16_lossy(&value.to_utf16())
}

pub(super) fn encode_buffer(source: &BufferSource) -> String {
    // SAFETY: Encoding the bytes neither runs script nor allocates GC cells.
    unsafe { source.with_bytes(|bytes| string(&ak::encode_base64(bytes, ak::Base64Alphabet::Base64Url, true))) }
}

pub(super) fn decode_buffer(cx: &CallContext, encoded: &Utf16String) -> WebIdlResult<Gc<ArrayBuffer>> {
    let decoded = ak::decode_base64(
        encoded.as_units(),
        ak::Base64Alphabet::Base64Url,
        ak::LastChunkHandling::Loose,
        None,
    );
    if decoded.error.is_some() || ak::encode_base64(&decoded.bytes, ak::Base64Alphabet::Base64Url, true) != *encoded {
        return Err(Exception::Dom(
            "EncodingError",
            Utf16String::from_ascii(b"Invalid base64url data"),
        ));
    }
    Ok(ArrayBuffer::try_create_written_by(
        cx.vm(),
        cx.realm(),
        decoded.bytes.len(),
        ArrayBufferShared::No,
        |target| {
            target.write_copy_of_slice(&decoded.bytes);
            decoded.bytes.len()
        },
    )?)
}
