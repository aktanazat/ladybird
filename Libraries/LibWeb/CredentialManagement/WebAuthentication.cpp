/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObject.h>
#include <AK/JsonValue.h>
#include <LibGC/Function.h>
#include <LibJS/HostClassBuilder.h>
#include <LibJS/Runtime/VM.h>
#include <LibWeb/DOM/AbortSignal.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/DOM/DocumentObserver.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/Page/Page.h>
#include <LibWeb/Platform/Timer.h>

namespace Web::CredentialManagement {

using CompletionCallback = void (*)(JSVM*, GC::Cell*, JSValue, ReadonlyBytes);

static JsonObject error_response(StringView name, StringView message)
{
    JsonObject object;
    object.set("error"sv, name);
    object.set("message"sv, message);
    return object;
}

class PendingWebAuthentication final : public GC::Cell {
    GC_CELL(PendingWebAuthentication, GC::Cell);
    GC_DECLARE_ALLOCATOR(PendingWebAuthentication);

public:
    PendingWebAuthentication(DOM::Document& document, GC::Ptr<DOM::AbortSignal> signal, GC::Cell& state, CompletionCallback callback)
        : m_document(document)
        , m_signal(signal)
        , m_state(state)
        , m_callback(callback)
    {
    }

    void start(JsonObject request, u32 timeout)
    {
        if (m_signal && m_signal->aborted()) {
            finish({}, m_signal->reason());
            return;
        }
        if (!m_document->is_fully_active()) {
            finish(error_response("NotAllowedError"sv, "The document is no longer active"sv));
            return;
        }
        m_request_id = m_document->page().request_webauthn(m_document->id(), move(request), GC::create_function(heap(), GC::captures(*this), [](PendingWebAuthentication& self, JsonObject response) {
            self.m_request_id.clear();
            self.finish(move(response));
        }));
        m_observer = DOM::DocumentObserver::create(*m_document);
        m_observer->set_document_became_inactive(GC::create_function(heap(), GC::captures(*this), [](PendingWebAuthentication& self) {
            self.finish(error_response("NotAllowedError"sv, "The document is no longer active"sv));
        }));
        if (m_signal) {
            m_abort_algorithm = m_signal->add_abort_algorithm(GC::create_function(heap(), GC::captures(*this), [](PendingWebAuthentication& self) {
                self.finish({}, self.m_signal->reason());
            }));
        }
        m_timer = Platform::Timer::create_single_shot(heap(), AK::Duration::from_milliseconds(timeout), GC::create_function(heap(), GC::captures(*this), [](PendingWebAuthentication& self) {
            self.finish(error_response("NotAllowedError"sv, "The WebAuthn request timed out"sv));
        }));
        m_timer->start();
    }

private:
    void finish(JsonObject response, JS::Value abort_reason = JS::js_undefined())
    {
        if (m_request_id.has_value())
            m_document->page().cancel_webauthn(m_request_id.release_value());
        if (m_observer)
            m_observer->set_document_became_inactive(nullptr);
        if (m_abort_algorithm.has_value())
            m_signal->remove_abort_algorithm(m_abort_algorithm.release_value());
        if (m_timer)
            m_timer->stop();
        auto serialized = response.serialized();
        m_callback(JS::HostABI::vm_to_abi(JS::VM::the()), m_state.ptr(), JS::HostABI::value_to_abi(abort_reason), serialized.bytes());
    }

    virtual void visit_edges(Visitor& visitor) override
    {
        Base::visit_edges(visitor);
        visitor.visit(m_document);
        visitor.visit(m_signal);
        visitor.visit(m_state);
        visitor.visit(m_observer);
        visitor.visit(m_timer);
    }

    GC::Ref<DOM::Document> m_document;
    GC::Ptr<DOM::AbortSignal> m_signal;
    GC::Ref<GC::Cell> m_state;
    CompletionCallback m_callback;
    GC::Ptr<DOM::DocumentObserver> m_observer;
    GC::Ptr<Platform::Timer> m_timer;
    Optional<u64> m_abort_algorithm;
    Optional<u64> m_request_id;
};

GC_DEFINE_ALLOCATOR(PendingWebAuthentication);

extern "C" void web_webauthn_request(HTML::Window*, DOM::AbortSignal*, u32 timeout, ReadonlyBytes, GC::Cell*, CompletionCallback);

void web_webauthn_request(HTML::Window* window, DOM::AbortSignal* signal, u32 timeout, ReadonlyBytes json, GC::Cell* state, CompletionCallback callback)
{
    auto request = JsonValue::from_string(StringView { json });
    if (request.is_error() || !request.value().is_object()) {
        auto error = error_response("TypeError"sv, "Invalid WebAuthn request"sv).serialized();
        callback(JS::HostABI::vm_to_abi(JS::VM::the()), state, JS::HostABI::value_to_abi(JS::js_undefined()), error.bytes());
        return;
    }
    auto& document = window->associated_document();
    auto pending = document.heap().allocate<PendingWebAuthentication>(document, signal, *state, callback);
    pending->start(move(request.value().as_object()), timeout);
}

}
