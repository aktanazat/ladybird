/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! Public key credentials and the browser-process connection, https://www.w3.org/TR/webauthn-3/.

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use ak::{Span, Utf16String};
use libjs_rust::api::{
    ArrayBuffer, EmbedderCell, EmbedderClass, EmbedderValue, Gc, JSONObject, MarkedVec, Object, Trace, Utf16View,
    Value, Vm,
};
use serde_json::{Value as Json, json};

use super::authenticator_assertion_response::AuthenticatorAssertionResponse;
use super::authenticator_attestation_response::AuthenticatorAttestationResponse;
use super::authenticator_response::{AnyAuthenticatorResponse, AuthenticatorResponse};
use super::credential::Credential;
pub(crate) use super::webauthn_options::{
    AuthenticationExtensionsClientInputs, AuthenticatorSelectionCriteria, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialDescriptor, PublicKeyCredentialDescriptorJSON,
    PublicKeyCredentialParameters, PublicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptionsJSON,
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, PublicKeyCredentialUserEntityJSON,
};
use super::webauthn_options::{decode_buffer, encode_buffer, string};
use crate::bindings::conversions::{BufferSource, UsvString};
use crate::bindings::global_object::window_from_global_object;
use crate::bindings::interface::{
    Inherits, Ref, Wrappable, allocate, cell_into_abi, with_temporary_execution_context_and_callbacks, wrap,
};
use crate::bindings::promise::{
    WebIdlPromise, create_resolved_promise, promise_realm, reject_promise, reject_promise_with_exception,
    resolve_promise,
};
use crate::bindings::{CallContext, Exception, WebIdlResult};
use crate::dom::abort_signal::AbortSignal;

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct PublicKeyCredential {
    credential: Credential,
    raw_id: Gc<ArrayBuffer>,
    response: AnyAuthenticatorResponse,
    attachment: Utf16String,
    #[gc(untraced)]
    json: Json,
}

impl Wrappable for PublicKeyCredential {}

impl Inherits<Credential> for PublicKeyCredential {
    fn parent(&self) -> &Credential {
        &self.credential
    }
}

impl PublicKeyCredential {
    pub(crate) fn raw_id(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.raw_id)
    }

    pub(crate) fn response(&self, _: &mut CallContext) -> WebIdlResult<AnyAuthenticatorResponse> {
        Ok(self.response)
    }

    pub(crate) fn authenticator_attachment(&self, _: &mut CallContext) -> WebIdlResult<Option<Utf16String>> {
        Ok(Some(self.attachment.clone()))
    }

    pub(crate) fn get_client_extension_results(&self, cx: &mut CallContext) -> WebIdlResult<Gc<Object>> {
        json_object(cx, &self.json["clientExtensionResults"])
    }

    pub(crate) fn to_json(&self, cx: &mut CallContext) -> WebIdlResult<Gc<Object>> {
        json_object(cx, &self.json)
    }

    pub(crate) fn is_user_verifying_platform_authenticator_available(
        cx: &mut CallContext,
        promise: WebIdlPromise,
    ) -> WebIdlResult<()> {
        start(
            cx,
            promise,
            None,
            30_000,
            Completion::Availability,
            json!({"operation": "availability"}),
        )
    }

    pub(crate) fn is_conditional_mediation_available(cx: &mut CallContext) -> WebIdlResult<WebIdlPromise> {
        Ok(create_resolved_promise(cx.vm(), cx.realm(), Value::from_bool(false)))
    }

    pub(crate) fn get_client_capabilities(cx: &mut CallContext, promise: WebIdlPromise) -> WebIdlResult<()> {
        start(
            cx,
            promise,
            None,
            30_000,
            Completion::Capabilities,
            json!({"operation": "availability"}),
        )
    }

    pub(crate) fn parse_creation_options_from_json<'vm>(
        cx: &mut CallContext<'vm>,
        options: PublicKeyCredentialCreationOptionsJSON,
    ) -> WebIdlResult<PublicKeyCredentialCreationOptions<'vm>> {
        let buffers = MarkedVec::new(cx.vm());
        let decode = |value: &Utf16String| -> WebIdlResult<BufferSource> {
            let buffer = decode_buffer(cx, value)?;
            buffers.push(buffer);
            Ok(BufferSource::ArrayBuffer(buffer))
        };
        let user = PublicKeyCredentialUserEntity {
            name: options.user.name,
            display_name: options.user.display_name,
            id: decode(&options.user.id)?,
        };
        let challenge = decode(&options.challenge)?;
        let exclude_credentials = MarkedVec::with_capacity(cx.vm(), options.exclude_credentials.len());
        for entry in options.exclude_credentials {
            exclude_credentials.push(PublicKeyCredentialDescriptor {
                r#type: entry.r#type,
                id: decode(&entry.id)?,
                transports: entry.transports,
            });
        }
        Ok(PublicKeyCredentialCreationOptions {
            rp: options.rp,
            user,
            challenge,
            pub_key_cred_params: options.pub_key_cred_params,
            timeout: options.timeout,
            exclude_credentials,
            authenticator_selection: options.authenticator_selection,
            hints: options.hints,
            attestation: options.attestation,
            attestation_formats: options.attestation_formats,
            extensions: options.extensions,
        })
    }

    pub(crate) fn parse_request_options_from_json<'vm>(
        cx: &mut CallContext<'vm>,
        options: PublicKeyCredentialRequestOptionsJSON,
    ) -> WebIdlResult<PublicKeyCredentialRequestOptions<'vm>> {
        let buffers = MarkedVec::new(cx.vm());
        let decode = |value: &Utf16String| -> WebIdlResult<BufferSource> {
            let buffer = decode_buffer(cx, value)?;
            buffers.push(buffer);
            Ok(BufferSource::ArrayBuffer(buffer))
        };
        let challenge = decode(&options.challenge)?;
        let allow_credentials = MarkedVec::with_capacity(cx.vm(), options.allow_credentials.len());
        for entry in options.allow_credentials {
            allow_credentials.push(PublicKeyCredentialDescriptor {
                r#type: entry.r#type,
                id: decode(&entry.id)?,
                transports: entry.transports,
            });
        }
        Ok(PublicKeyCredentialRequestOptions {
            challenge,
            timeout: options.timeout,
            rp_id: options.rp_id,
            allow_credentials,
            user_verification: options.user_verification,
            hints: options.hints,
            extensions: options.extensions,
        })
    }
}

fn json_object(cx: &CallContext, document: &Json) -> WebIdlResult<Gc<Object>> {
    let json = Utf16String::from_utf8(&document.to_string());
    let value = JSONObject::parse_json(cx.vm(), Utf16View::of_string(&json), None)?;
    if !value.is_object() {
        return Err(Exception::type_error("Expected a WebAuthn object"));
    }
    Ok(value.as_object())
}

#[derive(Clone, Copy, Trace)]
#[gc(crate = libjs_rust)]
enum Completion {
    Registration { request_credential_properties: bool },
    Authentication,
    Availability,
    Capabilities,
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
struct PendingOperation {
    promise: WebIdlPromise,
    completion: Completion,
}

static PENDING_OPERATION: EmbedderClass<PendingOperation> = EmbedderClass::new("PendingWebAuthentication");

impl EmbedderValue for PendingOperation {
    const CLASS: &'static EmbedderClass<Self> = &PENDING_OPERATION;
}

unsafe extern "C" {
    fn web_webauthn_request(
        window: *mut c_void,
        signal: *mut c_void,
        timeout: u32,
        json: Span<'_, u8>,
        state: *mut c_void,
        completed: unsafe extern "C" fn(&Vm, *mut c_void, Value, Span<'_, u8>),
    );
}

fn start(
    cx: &CallContext,
    promise: WebIdlPromise,
    signal: Option<Ref<AbortSignal>>,
    timeout: u32,
    completion: Completion,
    request: Json,
) -> WebIdlResult<()> {
    let Some(window) = window_from_global_object(cx.realm().global_object()) else {
        return Err(Exception::Dom(
            "NotAllowedError",
            Utf16String::from_ascii(b"WebAuthn requires a window"),
        ));
    };
    let serialized = request.to_string();
    let operation = PENDING_OPERATION.allocate(cx.vm(), |_| PendingOperation { promise, completion });
    // SAFETY: The window, signal and operation are live. C++ copies the JSON and roots the operation until completion.
    unsafe {
        web_webauthn_request(
            window.as_ptr(),
            signal.map(cell_into_abi).unwrap_or(ptr::null_mut()),
            timeout,
            Span::new(serialized.as_bytes()),
            operation.as_ptr().cast(),
            completed,
        );
    }
    Ok(())
}

fn authenticator_error(name: &str, message: &str) -> Exception {
    let message = Utf16String::from_utf8(message);
    match name {
        "InvalidStateError" => Exception::Dom("InvalidStateError", message),
        "NotAllowedError" => Exception::Dom("NotAllowedError", message),
        "NotSupportedError" => Exception::Dom("NotSupportedError", message),
        "SecurityError" => Exception::Dom("SecurityError", message),
        "TypeError" => Exception::TypeError(message),
        _ => Exception::Dom("UnknownError", message),
    }
}

unsafe extern "C" fn completed(vm: &Vm, state: *mut c_void, abort: Value, json: Span<'_, u8>) {
    // SAFETY: The C++ operation owns the cell created by start() until this callback returns.
    let Some(state) = NonNull::new(state.cast::<EmbedderCell<PendingOperation>>()) else {
        return;
    };
    let operation = unsafe { Gc::from_non_null(state) };
    let realm = promise_realm(operation.promise);
    with_temporary_execution_context_and_callbacks(realm, || {
        if !abort.is_undefined() {
            reject_promise(vm, operation.promise, abort);
            return;
        }

        let cx = CallContext::new(vm, realm);
        let result = serde_json::from_slice::<Json>(json.as_slice())
            .map_err(|_| authenticator_error("UnknownError", "The authenticator returned an invalid response"))
            .and_then(|reply| complete(&cx, operation.completion, reply));
        match result {
            Ok(value) => resolve_promise(vm, operation.promise, value),
            Err(error) => reject_promise_with_exception(vm, operation.promise, error),
        }
    });
}

fn complete(cx: &CallContext, completion: Completion, reply: Json) -> WebIdlResult<Value> {
    let available = reply["available"].as_bool().unwrap_or(false);
    match completion {
        Completion::Availability => return Ok(Value::from_bool(available)),
        Completion::Capabilities => {
            return Ok(Value::from_object(json_object(
                cx,
                &json!({
                    "conditionalCreate": false,
                    "conditionalGet": false,
                    "hybridTransport": false,
                    "passkeyPlatformAuthenticator": available,
                    "relatedOrigins": false,
                    "userVerifyingPlatformAuthenticator": available,
                }),
            )?));
        }
        _ => {}
    }

    if let Some(error) = reply["error"].as_str() {
        return Err(authenticator_error(
            error,
            reply["message"].as_str().unwrap_or("WebAuthn failed"),
        ));
    }

    let buffers = MarkedVec::new(cx.vm());
    let decode = |name: &str| -> WebIdlResult<Gc<ArrayBuffer>> {
        let value = reply[name]
            .as_str()
            .ok_or_else(|| authenticator_error("UnknownError", "Incomplete authenticator response"))?;
        let buffer = decode_buffer(cx, &Utf16String::from_utf8(value))?;
        buffers.push(buffer);
        Ok(buffer)
    };
    let id = reply["id"]
        .as_str()
        .ok_or_else(|| authenticator_error("UnknownError", "Missing credential ID"))?;
    let transport = reply["transport"]
        .as_str()
        .ok_or_else(|| authenticator_error("UnknownError", "Missing authenticator transport"))?;
    let attachment = if transport == "internal" {
        "platform"
    } else {
        "cross-platform"
    };
    let raw_id = decode("id")?;
    let response = AuthenticatorResponse {
        client_data: decode("clientDataJSON")?,
    };
    let authenticator_data = decode("authenticatorData")?;
    let mut extensions = json!({});
    let mut response_json = json!({
        "clientDataJSON": reply["clientDataJSON"],
        "authenticatorData": reply["authenticatorData"],
    });
    let response = match completion {
        Completion::Registration {
            request_credential_properties,
        } => {
            let attestation_object = decode("attestationObject")?;
            let public_key = decode("publicKey")?;
            let algorithm = reply["publicKeyAlgorithm"]
                .as_i64()
                .and_then(|value| i32::try_from(value).ok())
                .ok_or_else(|| authenticator_error("UnknownError", "Missing public key algorithm"))?;
            response_json["attestationObject"] = reply["attestationObject"].clone();
            response_json["publicKey"] = reply["publicKey"].clone();
            response_json["publicKeyAlgorithm"] = json!(algorithm);
            response_json["transports"] = json!([transport]);
            if request_credential_properties {
                extensions["credProps"] = json!({"rk": reply["discoverable"].as_bool().unwrap_or(false)});
            }
            AnyAuthenticatorResponse::AuthenticatorAttestationResponse(allocate(cx.vm(), |_| {
                AuthenticatorAttestationResponse {
                    response,
                    attestation_object,
                    authenticator_data,
                    public_key,
                    algorithm,
                    transport: Utf16String::from_utf8(transport),
                }
            }))
        }
        Completion::Authentication => {
            let signature = decode("signature")?;
            let user_handle = if reply["userHandle"].is_string() {
                Some(decode("userHandle")?)
            } else {
                None
            };
            response_json["signature"] = reply["signature"].clone();
            if user_handle.is_some() {
                response_json["userHandle"] = reply["userHandle"].clone();
            }
            AnyAuthenticatorResponse::AuthenticatorAssertionResponse(allocate(cx.vm(), |_| {
                AuthenticatorAssertionResponse {
                    response,
                    authenticator_data,
                    signature,
                    user_handle,
                }
            }))
        }
        _ => return Err(authenticator_error("UnknownError", "Unexpected authenticator response")),
    };
    let result = allocate(cx.vm(), |_| PublicKeyCredential {
        credential: Credential::new(UsvString::from_utf8(id), "public-key"),
        raw_id,
        response,
        attachment: Utf16String::from_utf8(attachment),
        json: json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "authenticatorAttachment": attachment,
            "response": response_json,
            "clientExtensionResults": extensions,
        }),
    });
    Ok(Value::from_object(wrap(cx, result)))
}

fn credential_ids(descriptors: &[PublicKeyCredentialDescriptor]) -> Vec<String> {
    descriptors
        .iter()
        .filter(|descriptor| string(&descriptor.r#type) == "public-key")
        .map(|descriptor| encode_buffer(&descriptor.id))
        .collect()
}

pub(super) fn register(
    cx: &CallContext,
    promise: WebIdlPromise,
    options: PublicKeyCredentialCreationOptions<'_>,
    signal: Option<Ref<AbortSignal>>,
) -> WebIdlResult<()> {
    if signal.is_some_and(|signal| signal.aborted()) {
        if let Some(signal) = signal {
            reject_promise(cx.vm(), promise, signal.reason());
        }
        return Ok(());
    }
    let supports_es256 = options.pub_key_cred_params.is_empty()
        || options
            .pub_key_cred_params
            .iter()
            .any(|parameter| parameter.alg == -7 && string(&parameter.r#type) == "public-key");
    if !supports_es256 {
        return Err(authenticator_error(
            "NotSupportedError",
            "The authenticator supports ES256",
        ));
    }
    let user_handle = encode_buffer(&options.user.id);
    if user_handle.is_empty() || user_handle.len() > 86 {
        return Err(Exception::type_error("The user handle must contain 1 to 64 bytes"));
    }
    let selection = options.authenticator_selection.as_ref();
    let resident_key = selection
        .and_then(|selection| selection.resident_key.as_ref())
        .map(string)
        .unwrap_or_else(|| {
            if selection.is_some_and(|selection| selection.require_resident_key) {
                "required"
            } else {
                "discouraged"
            }
            .to_owned()
        });
    let request = json!({
        "operation": "create",
        "rpId": options.rp.id.as_ref().map(string),
        "challenge": encode_buffer(&options.challenge),
        "userHandle": user_handle,
        "userName": string(&options.user.name),
        "algorithm": -7,
        "credentialIds": credential_ids(&options.exclude_credentials.values()),
        "residentKey": resident_key,
        "userVerification": selection.map(|selection| string(&selection.user_verification)),
        "attachment": selection.and_then(|selection| selection.authenticator_attachment.as_ref()).map(string),
    });
    start(
        cx,
        promise,
        signal,
        options.timeout.unwrap_or(120_000).clamp(1, 300_000),
        Completion::Registration {
            request_credential_properties: options.extensions.and_then(|value| value.cred_props).unwrap_or(false),
        },
        request,
    )
}

pub(super) fn authenticate(
    cx: &CallContext,
    promise: WebIdlPromise,
    options: PublicKeyCredentialRequestOptions<'_>,
    signal: Option<Ref<AbortSignal>>,
) -> WebIdlResult<()> {
    let ids = credential_ids(&options.allow_credentials.values());
    if ids.is_empty() && !options.allow_credentials.is_empty() {
        return Err(authenticator_error(
            "NotAllowedError",
            "No compatible credentials were provided",
        ));
    }
    let request = json!({
        "operation": "get",
        "rpId": options.rp_id.as_ref().map(string),
        "challenge": encode_buffer(&options.challenge),
        "credentialIds": ids,
        "userVerification": string(&options.user_verification),
    });
    start(
        cx,
        promise,
        signal,
        options.timeout.unwrap_or(120_000).clamp(1, 300_000),
        Completion::Authentication,
        request,
    )
}
