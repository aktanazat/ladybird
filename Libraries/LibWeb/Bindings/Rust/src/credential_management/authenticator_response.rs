/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use libjs_rust::api::{ArrayBuffer, Gc, ThrowCompletionOr, Trace, Value};

use super::authenticator_assertion_response::AuthenticatorAssertionResponse;
use super::authenticator_attestation_response::AuthenticatorAttestationResponse;
use crate::bindings::conversions::ToJs;
use crate::bindings::interface::{Ref, Wrappable};
use crate::bindings::{CallContext, WebIdlResult};

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct AuthenticatorResponse {
    pub(crate) client_data: Gc<ArrayBuffer>,
}

impl Wrappable for AuthenticatorResponse {}

impl AuthenticatorResponse {
    pub(crate) fn client_data_json(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.client_data)
    }
}

#[derive(Clone, Copy, Trace)]
#[gc(crate = libjs_rust)]
pub(crate) enum AnyAuthenticatorResponse {
    AuthenticatorAssertionResponse(Ref<AuthenticatorAssertionResponse>),
    AuthenticatorAttestationResponse(Ref<AuthenticatorAttestationResponse>),
}

impl ToJs for AnyAuthenticatorResponse {
    fn to_js(self, cx: &CallContext) -> ThrowCompletionOr<Value> {
        match self {
            Self::AuthenticatorAssertionResponse(response) => response.to_js(cx),
            Self::AuthenticatorAttestationResponse(response) => response.to_js(cx),
        }
    }
}
