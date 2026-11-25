/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use libjs_rust::api::{ArrayBuffer, Gc, Trace};

use super::authenticator_response::AuthenticatorResponse;
use crate::bindings::interface::{Inherits, Wrappable};
use crate::bindings::{CallContext, WebIdlResult};

#[derive(Trace)]
#[gc(crate = libjs_rust)]
pub(crate) struct AuthenticatorAssertionResponse {
    pub(crate) response: AuthenticatorResponse,
    pub(crate) authenticator_data: Gc<ArrayBuffer>,
    pub(crate) signature: Gc<ArrayBuffer>,
    pub(crate) user_handle: Option<Gc<ArrayBuffer>>,
}

impl Wrappable for AuthenticatorAssertionResponse {}

impl Inherits<AuthenticatorResponse> for AuthenticatorAssertionResponse {
    fn parent(&self) -> &AuthenticatorResponse {
        &self.response
    }
}

impl AuthenticatorAssertionResponse {
    pub(crate) fn authenticator_data(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.authenticator_data)
    }

    pub(crate) fn signature(&self, _: &mut CallContext) -> WebIdlResult<Gc<ArrayBuffer>> {
        Ok(self.signature)
    }

    pub(crate) fn user_handle(&self, _: &mut CallContext) -> WebIdlResult<Option<Gc<ArrayBuffer>>> {
        Ok(self.user_handle)
    }
}
