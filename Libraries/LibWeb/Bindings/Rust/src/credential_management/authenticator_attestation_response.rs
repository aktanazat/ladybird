/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use ak::Utf16String;
use libjs_rust::api::{ArrayBuffer, Gc, Trace};

use super::authenticator_response::AuthenticatorResponse;
use crate::bindings::interface::{Inherits, Wrappable};
use crate::bindings::{CallContext, WebIdlResult};

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct AuthenticatorAttestationResponse {
    pub(crate) response: AuthenticatorResponse,
    pub(crate) attestation_object: Gc<ArrayBuffer>,
    pub(crate) authenticator_data: Gc<ArrayBuffer>,
    pub(crate) public_key: Gc<ArrayBuffer>,
    pub(crate) algorithm: i32,
    pub(crate) transport: Utf16String,
}

impl Wrappable for AuthenticatorAttestationResponse {}

impl Inherits<AuthenticatorResponse> for AuthenticatorAttestationResponse {
    fn parent(&self) -> &AuthenticatorResponse {
        &self.response
    }
}

impl AuthenticatorAttestationResponse {
    pub(crate) fn attestation_object(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.attestation_object)
    }

    pub(crate) fn get_transports(&self, _: &mut CallContext) -> WebIdlResult<Vec<Utf16String>> {
        Ok(vec![self.transport.clone()])
    }

    pub(crate) fn get_authenticator_data(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.authenticator_data)
    }

    pub(crate) fn get_public_key(&self, _: &mut CallContext) -> WebIdlResult<Option<Gc<ArrayBuffer>>> {
        Ok(Some(self.public_key))
    }

    pub(crate) fn get_public_key_algorithm(&self, _: &mut CallContext) -> WebIdlResult<i32> {
        Ok(self.algorithm)
    }
}
