/*
 * Copyright (c) 2025, Altomani Gianluca <altomanigianluca@gmail.com>
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

//! CredentialsContainer, https://w3c.github.io/webappsec-credential-management/#credentialscontainer

use core::ffi::c_void;

use libjs_rust::api::{ErrorKind, ErrorType, Trace, Vm};

use super::credential::{AnyCredential, CredentialMediationRequirement};
use super::federated_credential::{FederatedCredentialInit, FederatedCredentialRequestOptions};
use super::password_credential::PasswordCredentialInit;
use super::public_key_credential::{self, PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions};
use crate::bindings::interface::{Ref, Wrappable, allocate, cell_into_abi};
use crate::bindings::promise::{WebIdlPromise, reject_promise_with_exception};
use crate::bindings::{CallContext, Exception, WebIdlResult};
use crate::dom::abort_signal::AbortSignal;

/// https://w3c.github.io/webappsec-credential-management/#dictdef-credentialrequestoptions
#[expect(dead_code, reason = "password and federated credentials are separate operations")]
pub(crate) struct CredentialRequestOptions<'vm> {
    pub(crate) federated: Option<FederatedCredentialRequestOptions>,
    pub(crate) mediation: CredentialMediationRequirement,
    pub(crate) password: bool,
    pub(crate) public_key: Option<PublicKeyCredentialRequestOptions<'vm>>,
    pub(crate) signal: Option<Ref<AbortSignal>>,
}

/// https://w3c.github.io/webappsec-credential-management/#dictdef-credentialcreationoptions
#[expect(dead_code, reason = "password and federated credentials are separate operations")]
pub(crate) struct CredentialCreationOptions<'vm> {
    pub(crate) federated: Option<FederatedCredentialInit>,
    pub(crate) mediation: CredentialMediationRequirement,
    pub(crate) password: Option<PasswordCredentialInit>,
    pub(crate) public_key: Option<PublicKeyCredentialCreationOptions<'vm>>,
    pub(crate) signal: Option<Ref<AbortSignal>>,
}

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct CredentialsContainer;

impl Wrappable for CredentialsContainer {}

fn reject_not_implemented_promise(vm: &Vm, promise: WebIdlPromise, operation: &str) {
    let throw = vm
        .throw_completion::<()>(ErrorKind::InternalError, ErrorType::NotImplemented, &[&operation])
        .expect_err("throwing a completion throws");
    reject_promise_with_exception(vm, promise, Exception::from(throw));
}

impl CredentialsContainer {
    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-get
    pub(crate) fn get(
        &self,
        cx: &mut CallContext,
        promise: WebIdlPromise,
        options: CredentialRequestOptions<'_>,
    ) -> WebIdlResult<()> {
        if let Some(public_key) = options.public_key {
            let result = if matches!(
                options.mediation,
                CredentialMediationRequirement::Silent | CredentialMediationRequirement::Conditional
            ) {
                Err(Exception::Dom(
                    "NotAllowedError",
                    ak::Utf16String::from_ascii(b"WebAuthn requires interactive mediation"),
                ))
            } else {
                public_key_credential::authenticate(cx, promise, public_key, options.signal)
            };
            if let Err(error) = result {
                reject_promise_with_exception(cx.vm(), promise, error);
            }
            return Ok(());
        }
        eprintln!("FIXME: Unimplemented CredentialsContainer::get()");
        reject_not_implemented_promise(cx.vm(), promise, "get");
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-store
    pub(crate) fn store(&self, cx: &mut CallContext, promise: WebIdlPromise, _: AnyCredential) -> WebIdlResult<()> {
        eprintln!("FIXME: Unimplemented CredentialsContainer::store()");
        reject_not_implemented_promise(cx.vm(), promise, "store");
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-create
    pub(crate) fn create(
        &self,
        cx: &mut CallContext,
        promise: WebIdlPromise,
        options: CredentialCreationOptions<'_>,
    ) -> WebIdlResult<()> {
        if let Some(public_key) = options.public_key {
            if let Err(error) = public_key_credential::register(cx, promise, public_key, options.signal) {
                reject_promise_with_exception(cx.vm(), promise, error);
            }
            return Ok(());
        }
        eprintln!("FIXME: Unimplemented CredentialsContainer::create()");
        reject_not_implemented_promise(cx.vm(), promise, "create");
        Ok(())
    }

    // https://w3c.github.io/webappsec-credential-management/#dom-credentialscontainer-preventsilentaccess
    pub(crate) fn prevent_silent_access(&self, cx: &mut CallContext, promise: WebIdlPromise) -> WebIdlResult<()> {
        eprintln!("FIXME: Unimplemented CredentialsContainer::prevent_silent_access()");
        reject_not_implemented_promise(cx.vm(), promise, "prevent silent access");
        Ok(())
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn web_rust_credentials_container_create(vm: &Vm) -> *mut c_void {
    cell_into_abi(allocate(vm, |_| CredentialsContainer))
}
