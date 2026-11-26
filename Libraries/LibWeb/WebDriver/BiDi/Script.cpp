/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/HashMap.h>
#include <AK/JsonArray.h>
#include <AK/Random.h>
#include <AK/RefCounted.h>
#include <LibGC/Function.h>
#include <LibGC/Heap.h>
#include <LibGC/Root.h>
#include <LibGC/RootVector.h>
#include <LibJS/Runtime/AbstractOperations.h>
#include <LibJS/Runtime/Error.h>
#include <LibJS/Runtime/NativeFunction.h>
#include <LibJS/Runtime/Promise.h>
#include <LibJS/Runtime/VM.h>
#include <LibWeb/Bindings/HostDefined.h>
#include <LibWeb/Bindings/Intrinsics.h>
#include <LibWeb/Bindings/MainThreadVM.h>
#include <LibWeb/Bindings/WrapperWorld.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/HTML/LocalNavigable.h>
#include <LibWeb/HTML/Navigable.h>
#include <LibWeb/HTML/Scripting/ClassicScript.h>
#include <LibWeb/HTML/Scripting/Environments.h>
#include <LibWeb/HTML/Scripting/ExceptionReporter.h>
#include <LibWeb/HTML/Scripting/TemporaryExecutionContext.h>
#include <LibWeb/HTML/Window.h>
#include <LibWeb/HTML/WindowProxy.h>
#include <LibWeb/WebDriver/BiDi/BiDi.h>
#include <LibWeb/WebDriver/BiDi/BindingsGlue.h>
#include <LibWeb/WebDriver/BiDi/RemoteValue.h>
#include <LibWeb/WebDriver/BiDi/Script.h>
#include <LibWeb/WebIDL/Promise.h>

namespace Web::WebDriver::BiDi {

// https://w3c.github.io/webdriver-bidi/#default-user-context
// FIXME: Support user contexts other than the default user context.
static constexpr auto DEFAULT_USER_CONTEXT_ID = "default"sv;

static Error invalid_argument(StringView message)
{
    return Error::from_code(ErrorCode::InvalidArgument, message);
}

static Error no_such_frame()
{
    return Error::from_code(ErrorCode::NoSuchFrame, "Realm not found"sv);
}

static String document_realm_id(DOM::Document const& document)
{
    auto id = document.id();
    return MUST(String::formatted("{}.{}", id.namespace_id, id.local_id));
}

class SandboxSettings final : public HTML::EnvironmentSettingsObject {
    GC_CELL(SandboxSettings, HTML::EnvironmentSettingsObject);
    GC_DECLARE_ALLOCATOR(SandboxSettings);

public:
    SandboxSettings(DOM::Document& document, NonnullOwnPtr<JS::ExecutionContext> execution_context, String name)
        : EnvironmentSettingsObject(move(execution_context))
        , name(move(name))
        , realm_id(MUST(String::formatted("{}.{}", document_realm_id(document), generate_random_uuid())))
        , m_document(document)
    {
        auto& principal = document.relevant_settings_object();
        id = HTML::EnvironmentId::generate();
        creation_url = principal.creation_url;
        top_level_creation_url = principal.top_level_creation_url;
        top_level_origin = principal.top_level_origin;
        execution_ready = true;
    }

    virtual GC::Ptr<DOM::Document> responsible_document() override { return m_document.ptr(); }
    virtual URL::URL api_base_url() const override { return m_document->base_url(); }
    virtual URL::Origin origin() const override { return m_document->origin(); }
    virtual bool has_cross_site_ancestor() const override { return principal_settings().has_cross_site_ancestor(); }
    virtual NonnullRefPtr<HTML::PolicyContainer> policy_container() const override { return m_document->policy_container(); }
    virtual HTML::CanUseCrossOriginIsolatedAPIs cross_origin_isolated_capability() const override { return principal_settings().cross_origin_isolated_capability(); }
    virtual Optional<u64> agent_cluster_id() const override { return principal_settings().agent_cluster_id(); }
    virtual HTML::CrossOriginIsolationMode agent_cluster_cross_origin_isolation_mode() const override { return principal_settings().agent_cluster_cross_origin_isolation_mode(); }
    virtual double time_origin() const override { return principal_settings().time_origin(); }

    String const name;
    String const realm_id;

private:
    HTML::EnvironmentSettingsObject const& principal_settings() const { return m_document->relevant_settings_object(); }

    virtual void visit_edges(Cell::Visitor& visitor) override
    {
        Base::visit_edges(visitor);
        visitor.visit(m_document);
    }

    GC::Ref<DOM::Document> m_document;
};

GC_DEFINE_ALLOCATOR(SandboxSettings);

class SandboxHostDefined final : public Bindings::HostDefined {
    GC_CELL(SandboxHostDefined, Bindings::HostDefined);
    GC_DECLARE_ALLOCATOR(SandboxHostDefined);

public:
    SandboxHostDefined(Bindings::Intrinsics& intrinsics, Bindings::WrapperWorld& wrapper_world, JS::Realm& principal_realm, SandboxSettings& settings)
        : HostDefined(intrinsics, wrapper_world, principal_realm)
        , m_settings(settings)
    {
    }

    virtual HTML::EnvironmentSettingsObject* auxiliary_settings_object() const override { return m_settings.ptr(); }

private:
    virtual void visit_edges(Cell::Visitor& visitor) override
    {
        Base::visit_edges(visitor);
        visitor.visit(m_settings);
    }

    GC::Ref<SandboxSettings> m_settings;
};

GC_DEFINE_ALLOCATOR(SandboxHostDefined);

static SandboxSettings* sandbox_settings(JS::Realm& realm)
{
    auto& host_defined = Bindings::host_defined_of(realm);
    if (host_defined.wrapper_world->type() != Bindings::WrapperWorld::Type::WebDriverSandbox)
        return nullptr;
    return static_cast<SandboxSettings*>(host_defined.auxiliary_settings_object());
}

Optional<String> sandbox_realm_id(HTML::EnvironmentSettingsObject& settings)
{
    if (auto* sandbox = sandbox_settings(settings.realm()))
        return sandbox->realm_id;
    return {};
}

using SandboxRealms = Vector<GC::Root<SandboxSettings>>;
static HashMap<String, SandboxRealms>& sandbox_realms()
{
    static auto& realms = *new HashMap<String, SandboxRealms>;
    return realms;
}

static void for_each_sandbox_realm(DOM::Document& document, auto callback)
{
    auto realms = sandbox_realms().find(document_realm_id(document));
    if (realms == sandbox_realms().end())
        return;
    for (auto const& sandbox : realms->value)
        callback(*sandbox);
}

HTML::EnvironmentSettingsObject* sandbox_settings_with_realm_id(DOM::Document& document, StringView id)
{
    SandboxSettings* found = nullptr;
    for_each_sandbox_realm(document, [&](auto& sandbox) {
        if (sandbox.realm_id == id)
            found = &sandbox;
    });
    return found;
}

static void retire_sandbox(SandboxSettings& sandbox)
{
    sandbox.execution_ready = false;
    Bindings::host_defined_wrapper_world(sandbox.realm()).detach();
}

void unload_sandbox_realms(DOM::Document& document, Function<void(HTML::EnvironmentSettingsObject&)> const& on_destroyed)
{
    if (auto realms = sandbox_realms().take(document_realm_id(document)); realms.has_value()) {
        for (auto const& sandbox : *realms) {
            retire_sandbox(*sandbox);
            on_destroyed(*sandbox);
        }
    }
}

void clear_all_sandbox_realms()
{
    for (auto& entry : sandbox_realms()) {
        for (auto const& sandbox : entry.value)
            retire_sandbox(*sandbox);
    }
    sandbox_realms().clear();
}

// https://w3c.github.io/webdriver-bidi/#get-or-create-a-sandbox-realm
static SandboxSettings& get_or_create_sandbox_realm(DOM::Document& document, String const& name)
{
    auto& principal = document.relevant_settings_object();
    auto document_id = document_realm_id(document);
    auto& realms = sandbox_realms().ensure(document_id);
    for (auto const& sandbox : realms) {
        if (sandbox->name == name)
            return *sandbox;
    }

    auto& window = *document.window();
    GC::Ptr<HTML::WindowProxy> proxy;
    auto execution_context = Bindings::create_a_new_javascript_realm(
        principal.realm().vm(), principal.agent_cluster_cross_origin_isolation_mode(),
        [&](JS::Realm& realm) -> GC::Ref<JS::Object> { return Bindings::create_global_object_wrapper(realm, GC::Ref { window }); },
        [&](JS::Realm& realm) -> GC::Ref<JS::Object> {
            proxy = HTML::WindowProxy::create(realm);
            return proxy->object();
        });

    auto& realm = *execution_context->realm();
    auto wrapper_world = realm.heap().allocate<Bindings::WrapperWorld>(Bindings::WrapperWorld::Type::WebDriverSandbox);
    auto intrinsics = realm.create<Bindings::Intrinsics>(realm);
    auto sandbox = realm.create<SandboxSettings>(document, move(execution_context), name);
    realm.set_host_defined(realm.heap().allocate<SandboxHostDefined>(*intrinsics, *wrapper_world, principal.realm(), *sandbox));
    Bindings::cache_global_object_wrapper(realm);
    proxy->set_window(window);
    MUST(Bindings::initialize_window_web_interfaces(window, realm));

    realms.append(GC::make_root(sandbox));
    emit_realm_created(*sandbox);
    return *sandbox;
}

// NB: A sandbox reaches another frame's window as that frame's sandbox of the same name, as a script there would see
//     it, so it writes to no page's globals and reads no page's objects.
JS::Object* sandbox_global_for_window(JS::Realm& from_realm, HTML::Window& window)
{
    auto* settings = sandbox_settings(from_realm);
    if (!settings)
        return nullptr;
    return &get_or_create_sandbox_realm(window.associated_document(), settings->name).realm().global_object();
}

// https://w3c.github.io/webdriver-bidi/#get-the-realm-info
Optional<JsonObject> get_the_realm_info(HTML::EnvironmentSettingsObject& environment_settings)
{
    // 1. Let realm be environment settings' realm execution context's Realm component.

    // 2. Let realm id be the realm id for realm.
    auto id = realm_id(environment_settings);

    // 3. Let origin be the serialization of an origin given environment settings's origin.
    auto origin = environment_settings.origin().serialize();

    // 4. Let global object be the global object specified by environment settings
    auto& global_object = environment_settings.global_object();

    // 5. Run the steps under the first matching condition:
    // -> global object is a Window object
    if (HTML::window_from_global_object(global_object)) {
        // 1. Let document be environment settings' relevant global object's associated Document.
        auto document = environment_settings.responsible_document();

        // 2. Let navigable be document's node navigable.
        auto navigable = document ? document->navigable() : nullptr;

        // 3. If navigable is null, return null.
        if (!navigable)
            return {};

        // 4. Let navigable id be the navigable id for navigable.
        // 5. Let user context id be the user context id of navigable's associated user context
        // 6. Let realm info be a map matching the script.WindowRealmInfo production, with the realm field set to realm
        //    id, the origin field set to origin, the context field set to navigable id and the userContext field set to
        //    user context id.
        JsonObject realm_info;
        realm_info.set("realm"sv, move(id));
        realm_info.set("origin"sv, move(origin));
        realm_info.set("type"sv, "window"sv);
        realm_info.set("context"sv, navigable_id(*navigable));
        realm_info.set("userContext"sv, DEFAULT_USER_CONTEXT_ID);
        if (auto* sandbox = sandbox_settings(environment_settings.realm()))
            realm_info.set("sandbox"sv, sandbox->name);
        return realm_info;
    }

    // FIXME: -> global object is a WorkerGlobalScope or WorkletGlobalScope object

    // -> Otherwise:
    //    1. Let realm info be null.
    return {};
}

// https://w3c.github.io/webdriver-bidi/#get-the-source
JsonObject get_the_source(HTML::EnvironmentSettingsObject& environment_settings)
{
    // 1. Let realm be the realm id for source realm.
    auto settings = realm_id(environment_settings);

    // 2. Let environment settings be the environment settings object whose realm execution context's Realm component
    //    is source realm.

    // 3. If environment settings has a associated Document:
    //     1. Let document be environment settings’ associated Document.
    //     2. Let navigable be document’s node navigable.
    //     3. Let navigable id be the navigable id for navigable if navigable is not null.
    //     4. Let user context id be the user context id of navigable's associated user context.
    //    Otherwise let navigable be null.
    GC::Ptr<HTML::Navigable> navigable;
    if (HTML::window_from_global_object(environment_settings.global_object())) {
        if (auto document = environment_settings.responsible_document())
            navigable = document->navigable();
    }

    // 4. Let source be a map matching the script.Source production with the realm field set to realm, the context field
    //    set to navigable id if navigable is not null, or unset otherwise, and the userContext field set to user context
    //    id if |navigable is not null, or unset otherwise.
    JsonObject source;
    source.set("realm"sv, move(settings));
    if (navigable) {
        source.set("context"sv, navigable_id(*navigable));
        source.set("userContext"sv, DEFAULT_USER_CONTEXT_ID);
    }

    // 5. Return source.
    return source;
}

// https://w3c.github.io/webdriver-bidi/#create-a-channel
JS::Value create_a_channel(HTML::EnvironmentSettingsObject& settings, JsonObject const& protocol_value)
{
    // 1. Let channel properties be protocol value["value"].
    auto channel_properties = protocol_value.get_object("value"sv).value_or({});

    // 2. Let steps be the following steps given the argument message:
    auto steps = GC::create_function(GC::Heap::the(), GC::captures(move(channel_properties)), [](JsonObject& channel_properties, JS::VM& vm) -> JS::ThrowCompletionOr<JS::Value> {
        auto message = vm.argument(0);

        // 1. Let current realm be the current Realm Record.
        auto* sandbox = sandbox_settings(*vm.current_realm());
        auto& current_settings = sandbox ? *sandbox : HTML::current_settings_object();

        // 2. Emit a script message with session, current realm, channel properties and message.
        // https://w3c.github.io/webdriver-bidi/#emit-a-script-message
        if (!is_active() || (sandbox && !sandbox->execution_ready) || !is_event_enabled("script.message"sv))
            return JS::js_undefined();

        // 1. Let environment settings be the environment settings object whose realm execution context's Realm
        //    component is realm.
        auto& environment_settings = current_settings;

        // 2. Let related navigables be the result of get related navigables given environment settings.
        auto document = environment_settings.responsible_document();
        auto navigable = document ? document->navigable() : nullptr;
        if (!navigable)
            return JS::js_undefined();

        // 3. If event is enabled given session, "script.message" and related navigables:
        // NB: The browser process emits the event if some subscription enables it.

        // 1. If channel properties contains "serializationOptions", let serialization options be the value of the
        //    serializationOptions field of channel properties. Otherwise let serialization options be a map matching
        //    the script.SerializationOptions production with the fields set to their default values.
        SerializationOptions serialization_options;
        if (auto options = channel_properties.get("serializationOptions"sv); options.has_value()) {
            if (auto parsed = parse_serialization_options(*options); !parsed.is_error())
                serialization_options = parsed.release_value();
        }

        // 2. Let if channel properties contains "ownership", let ownership type be channel properties["ownership"].
        //    Otherwise let ownership type be "none".
        auto ownership_type = ResultOwnership::None;
        if (auto ownership = channel_properties.get("ownership"sv); ownership.has_value()) {
            if (auto parsed = parse_result_ownership(*ownership); !parsed.is_error())
                ownership_type = parsed.release_value();
        }

        // 3. Let data be the result of serialize as a remote value given message, serialization options, ownership type,
        //    a new map as serialization internal map and realm.
        auto data = serialize_as_a_remote_value(message, serialization_options, ownership_type, current_settings);

        // 4. Let source be the get the source with realm.
        auto source = get_the_source(current_settings);

        // 5. Let params be a map matching the script.MessageParameters production, with the channel field set to
        //    channel properties["channel"], the data field set to data, and the source field set to source.
        JsonObject params;
        params.set("channel"sv, channel_properties.get_string("channel"sv).value_or({}));
        params.set("data"sv, move(data));
        params.set("source"sv, move(source));

        // 6. Let body be a map matching the script.Message production, with the params field set to params.
        // 7. Emit an event with session and body.
        emit_event(*navigable, "script.message"_string, move(params));
        return JS::js_undefined();
    });

    // 3. Return CreateBuiltinFunction(steps, 1, "", « », realm).
    return BindingsGlue::create_channel_function(settings, steps);
}

// https://w3c.github.io/webdriver-bidi/#get-a-realm-from-a-target
// NB: The browser process routes the command to the process hosting the navigable of the target, which is the given
//     navigable.
static ErrorOr<HTML::EnvironmentSettingsObject*, Error> get_a_realm_from_a_target(HTML::Navigable& navigable, JsonObject const& params)
{
    auto target_value = params.get("target"sv);
    if (!target_value.has_value() || !target_value->is_object())
        return invalid_argument("Parameter 'target' must be an object"sv);
    auto const& target = target_value->as_object();

    // 1. If target matches the script.ContextTarget production:
    if (target.has("context"sv)) {
        // 1. Let sandbox be null.
        // 2. If target contains "sandbox", set sandbox to target["sandbox"].
        Optional<String> sandbox;
        if (auto sandbox_value = target.get("sandbox"sv); sandbox_value.has_value()) {
            if (!sandbox_value->is_string())
                return invalid_argument("Parameter 'sandbox' must be a string"sv);
            sandbox = sandbox_value->as_string();
        }

        // 3. Let realm be get a realm from a navigable with target["context"] and sandbox.
        // https://w3c.github.io/webdriver-bidi/#get-a-realm-from-a-navigable
        // 1. Let navigable be the result of trying to get a navigable with navigable id.
        auto* local_navigable = as_if<HTML::LocalNavigable>(navigable);
        if (!local_navigable || !local_navigable->active_document())
            return Error::from_code(ErrorCode::NoSuchFrame, "Browsing context not found"sv);

        // 2. If sandbox is null or is an empty string:
        if (!sandbox.has_value() || sandbox->is_empty()) {
            // 1. Let document be navigable's active document.
            // 2. Let environment settings be the environment settings object whose relevant global object's associated
            //    Document is document.
            // 3. Let realm be environment settings' realm execution context's Realm component.
            return &local_navigable->active_document()->relevant_settings_object();
        }

        // 3. Otherwise: let realm be result of trying to get or create a sandbox realm given sandbox and navigable.
        return &get_or_create_sandbox_realm(*local_navigable->active_document(), *sandbox);
    }

    // 2. Otherwise:
    if (auto id = target.get_string("realm"sv); id.has_value()) {
        // 1. Assert: target matches the script.RealmTarget production.
        // 2. Let realm id be the value of the realm field of target.
        // 3. Let realm be get a realm given realm id.
        // https://w3c.github.io/webdriver-bidi/#get-a-realm
        // 2. If there is no realm with id realm id return error with error code no such frame
        auto* settings = settings_with_realm_id(navigable, *id);
        if (!settings)
            return no_such_frame();

        // 3. Let realm be the realm with id realm id.
        // 4. Return success with data realm
        return settings;
    }

    return invalid_argument("Parameter 'target' must be a context or realm target"sv);
}

static ErrorOr<bool, Error> get_bool(JsonObject const& params, StringView name)
{
    auto value = params.get(name);
    if (!value.has_value() || !value->is_bool())
        return invalid_argument(MUST(String::formatted("Parameter '{}' must be a boolean", name)));
    return value->as_bool();
}

static ErrorOr<bool, Error> get_optional_bool(JsonObject const& params, StringView name, bool default_value)
{
    if (!params.has(name))
        return default_value;
    return get_bool(params, name);
}

static ErrorOr<String, Error> get_string(JsonObject const& params, StringView name)
{
    auto value = params.get(name);
    if (!value.has_value() || !value->is_string())
        return invalid_argument(MUST(String::formatted("Parameter '{}' must be a string", name)));
    return value->as_string();
}

static ErrorOr<SerializationOptions, Error> get_serialization_options(JsonObject const& params)
{
    // Let serialization options be the value of the serializationOptions field of command parameters, if present, or
    // otherwise a map matching the script.SerializationOptions production with the fields set to their default values.
    if (auto value = params.get("serializationOptions"sv); value.has_value())
        return parse_serialization_options(*value);
    return SerializationOptions {};
}

static ErrorOr<ResultOwnership, Error> get_result_ownership(JsonObject const& params)
{
    // Let result ownership be the value of the resultOwnership field of command parameters, if present, or none
    // otherwise.
    if (auto value = params.get("resultOwnership"sv); value.has_value())
        return parse_result_ownership(*value);
    return ResultOwnership::None;
}

// https://html.spec.whatwg.org/multipage/interaction.html#activation-notification
static void run_activation_notification_steps(HTML::EnvironmentSettingsObject& settings)
{
    // AD-HOC: Notify the window of the realm, the way a user interaction with its document does.
    auto& environment_settings = settings;
    if (auto* window = HTML::window_from_global_object(environment_settings.global_object()))
        window->notify_about_user_activation();
}

static JsonObject evaluation_result_exception(HTML::EnvironmentSettingsObject& settings, JS::Value exception, ResultOwnership result_ownership)
{
    // 1. Let exception details be the result of get exception details given realm, evaluation status, result ownership
    //    and session.
    // 2. Return a new map matching the script.EvaluationResultException production, with the realm field set to realm
    //    id, and the exceptionDetails field set to exception details.
    JsonObject result;
    result.set("type"sv, "exception"sv);
    result.set("exceptionDetails"sv, get_exception_details(settings, exception, result_ownership));
    result.set("realm"sv, realm_id(settings));
    return result;
}

static JsonObject evaluation_result_success(HTML::EnvironmentSettingsObject& settings, JS::Value value, SerializationOptions const& serialization_options, ResultOwnership result_ownership)
{
    // 1. Let result be the result of serialize as a remote value with evaluation status.[[Value]], serialization
    //    options, result ownership, a new map as serialization internal map, realm and session.
    auto result = serialize_as_a_remote_value(value, serialization_options, result_ownership, settings);

    // 2. Return a new map matching the script.EvaluationResultSuccess production, with the realm field set to realm id,
    //    and the result field set to result.
    JsonObject body;
    body.set("type"sv, "success"sv);
    body.set("result"sv, move(result));
    body.set("realm"sv, realm_id(settings));
    return body;
}

namespace {

// NB: The session keeps an awaited promise and its evaluation alive until it settles or its environment is destroyed.
struct PendingEvaluation : RefCounted<PendingEvaluation> {
    GC_HOLDS_NO_CELL_EDGES;

    AK_ALLOC_WITH_KMALLOC;

    String environment_id;
    GC::Root<WebIDL::Promise> promise;
    GC::Root<GC::Function<void(Response)>> on_complete;
    SerializationOptions serialization_options;
    ResultOwnership result_ownership { ResultOwnership::None };

    void complete(Response);

    void fail()
    {
        complete(Error::from_code(ErrorCode::UnknownError, "The realm was destroyed while awaiting the promise"sv));
    }
};

}

static HashMap<String, Vector<NonnullRefPtr<PendingEvaluation>>>& pending_evaluations()
{
    static auto& evaluations = *new HashMap<String, Vector<NonnullRefPtr<PendingEvaluation>>>;
    return evaluations;
}

void PendingEvaluation::complete(Response response)
{
    if (!on_complete)
        return;

    // NB: Completion may run more script or end the session. Remove this evaluation before calling out.
    if (auto evaluations = pending_evaluations().find(environment_id); evaluations != pending_evaluations().end()) {
        evaluations->value.remove_all_matching([this](auto const& evaluation) { return evaluation.ptr() == this; });
        if (evaluations->value.is_empty())
            pending_evaluations().remove(evaluations);
    }
    promise = {};
    auto callback = move(on_complete);
    callback->function()(move(response));
}

void fail_pending_evaluations(HTML::EnvironmentSettingsObject& settings)
{
    auto evaluations = pending_evaluations().take(realm_id(settings));
    if (!evaluations.has_value())
        return;
    for (auto& evaluation : *evaluations)
        evaluation->fail();
}

void fail_all_pending_evaluations()
{
    auto evaluations = move(pending_evaluations());
    pending_evaluations().clear();
    for (auto& entry : evaluations) {
        for (auto& evaluation : entry.value)
            evaluation->complete(Error::from_code(ErrorCode::UnknownError, "The session ended while awaiting the promise"sv));
    }
}

// NB: The steps of evaluate and callFunction once their evaluation status is known: they await a promise if asked to,
//     and complete with the evaluation result.
static void complete_evaluation(HTML::EnvironmentSettingsObject& settings, JS::Completion evaluation_status, bool await_promise, SerializationOptions serialization_options, ResultOwnership result_ownership, OnCommandComplete on_complete)
{
    // If evaluation status.[[Type]] is normal, await promise is true, and IsPromise(evaluation status.[[Value]]):
    if (!evaluation_status.is_abrupt() && await_promise && evaluation_status.value().is_object() && is<JS::Promise>(evaluation_status.value().as_object())) {
        // Set evaluation status to Await(evaluation status.[[Value]]).
        HTML::TemporaryExecutionContext execution_context { settings, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };
        auto promise = WebIDL::create_resolved_promise_for(settings.global_object(), evaluation_status.value());

        auto state = adopt_ref(*new PendingEvaluation);
        state->on_complete = move(on_complete);
        state->serialization_options = serialization_options;
        state->result_ownership = result_ownership;

        state->environment_id = realm_id(settings);
        state->promise = promise;
        pending_evaluations().ensure(state->environment_id).append(state);

        WebIDL::react_to_promise(promise,
            GC::create_function(GC::Heap::the(), GC::captures(GC::Ref { settings }, state), [](auto& settings, auto& state, JS::Value value) -> WebIDL::ExceptionOr<JS::Value> {
                if (!state->on_complete)
                    return JS::js_undefined();
                HTML::TemporaryExecutionContext execution_context { *settings, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };
                state->complete(JsonValue { evaluation_result_success(*settings, value, state->serialization_options, state->result_ownership) });
                return JS::js_undefined();
            }),
            GC::create_function(GC::Heap::the(), GC::captures(GC::Ref { settings }, state), [](auto& settings, auto& state, JS::Value reason) -> WebIDL::ExceptionOr<JS::Value> {
                if (!state->on_complete)
                    return JS::js_undefined();
                HTML::TemporaryExecutionContext execution_context { *settings, HTML::TemporaryExecutionContext::CallbacksEnabled::Yes };
                state->complete(JsonValue { evaluation_result_exception(*settings, reason, state->result_ownership) });
                return JS::js_undefined();
            }));
        return;
    }

    HTML::TemporaryExecutionContext execution_context { settings };

    // If evaluation status.[[Type]] is throw:
    if (evaluation_status.is_abrupt()) {
        on_complete->function()(JsonValue { evaluation_result_exception(settings, evaluation_status.value(), result_ownership) });
        return;
    }

    // Assert: evaluation status.[[Type]] is normal.
    on_complete->function()(JsonValue { evaluation_result_success(settings, evaluation_status.value(), serialization_options, result_ownership) });
}

#define TRY_OR_COMPLETE(expression)                                                                  \
    ({                                                                                               \
        /* Ignore -Wshadow to allow nesting the macro. */                                            \
        AK_IGNORE_DIAGNOSTIC("-Wshadow",                                                             \
            auto&& _temporary_result = (expression));                                                \
        static_assert(!::AK::Detail::IsLvalueReference<decltype(_temporary_result.release_value())>, \
            "Do not return a reference from a fallible expression");                                 \
        if (_temporary_result.is_error()) [[unlikely]] {                                             \
            on_complete->function()(_temporary_result.release_error());                              \
            return;                                                                                  \
        }                                                                                            \
        _temporary_result.release_value();                                                           \
    })

// https://w3c.github.io/webdriver-bidi/#command-script-evaluate
void evaluate(HTML::Navigable& navigable, JsonObject const& params, OnCommandComplete on_complete)
{
    auto source = TRY_OR_COMPLETE(get_string(params, "expression"sv));

    // 1. Let realm be the result of trying to get a realm from a target given the value of the target field of command
    //    parameters.
    auto& settings = *TRY_OR_COMPLETE(get_a_realm_from_a_target(navigable, params));

    // 2. Let realm id be realm's realm id.
    // 3. Let environment settings be the environment settings object whose realm execution context's Realm component is
    //    realm.
    auto& environment_settings = settings;

    // 4. Let source be the value of the expression field of command parameters.
    // 5. Let await promise be the value of the awaitPromise field of command parameters.
    auto await_promise = TRY_OR_COMPLETE(get_bool(params, "awaitPromise"sv));

    // 6. Let serialization options be the value of the serializationOptions field of command parameters, if present, or
    //    otherwise a map matching the script.SerializationOptions production with the fields set to their default
    //    values.
    auto serialization_options = TRY_OR_COMPLETE(get_serialization_options(params));

    // 7. Let result ownership be the value of the resultOwnership field of command parameters, if present, or none
    //    otherwise.
    auto result_ownership = TRY_OR_COMPLETE(get_result_ownership(params));

    auto user_activation = TRY_OR_COMPLETE(get_optional_bool(params, "userActivation"sv, false));

    // 8. Let options be the default script fetch options.
    // 9. Let base URL be the API base URL of environment settings.
    auto base_url = environment_settings.api_base_url();

    // 10. Let bypassDisabledScripting be true.
    // 11. Let script be the result of create a classic script with source, environment settings, base URL, options and
    //     bypassDisabledScripting.
    auto script = HTML::ClassicScript::create({}, Utf16String::from_utf8(source), environment_settings, base_url);

    // 12. If command parameters["userActivation"] is true, run activation notification steps.
    if (user_activation)
        run_activation_notification_steps(settings);

    // 13. Prepare to run script with environment settings.
    // 14. Set evaluation status to ScriptEvaluation(script's record).
    // 16. Clean up after running script with environment settings.
    // NB: Running the script prepares to run it and cleans up after running it.
    auto evaluation_status = script->run(HTML::ClassicScript::RethrowErrors::Yes);

    // 15. If evaluation status.[[Type]] is normal, await promise is true, and IsPromise(evaluation status.[[Value]]):
    //     1. Set evaluation status to Await(evaluation status.[[Value]]).
    // 17. If evaluation status.[[Type]] is throw:
    //     1. Let exception details be the result of get exception details with realm, evaluation status, result
    //        ownership and session.
    //     2. Return a new map matching the script.EvaluationResultException production, with the realm field set to
    //        realm id, and the exceptionDetails field set to exception details.
    // 18. Assert: evaluation status.[[Type]] is normal.
    // 19. Let result be the result of serialize as a remote value with evaluation status.[[Value]], serialization
    //     options, result ownership, a new map as serialization internal map, realm and session.
    // 20. Return a new map matching the script.EvaluationResultSuccess production, with the with the realm field set to
    //     realm id, and the result field set to result.
    complete_evaluation(settings, move(evaluation_status), await_promise, serialization_options, result_ownership, move(on_complete));
}

// https://w3c.github.io/webdriver-bidi/#evaluate-function-body
static JS::Completion evaluate_function_body(StringView function_declaration, HTML::EnvironmentSettingsObject& environment_settings, URL::URL const& base_url)
{
    // NB: the function declaration is parenthesized and evaluated.

    // 1. Let bypassDisabledScripting be true.
    // 2. Let parenthesized function declaration be concatenate «"(", function declaration, ")"»
    auto parenthesized_function_declaration = Utf16String::formatted("({})", function_declaration);

    // 3. Let function script be the result of create a classic script with parenthesized function declaration,
    //    environment settings, base URL, options and bypassDisabledScripting.
    auto function_script = HTML::ClassicScript::create({}, parenthesized_function_declaration, environment_settings, base_url);

    // 4. Prepare to run script with environment settings.
    // 5. Let function body evaluation status be ScriptEvaluation(function script's record).
    // 6. Clean up after running script with environment settings.
    // NB: Running the script prepares to run it and cleans up after running it.
    // 7. Return function body evaluation status.
    return function_script->run(HTML::ClassicScript::RethrowErrors::Yes);
}

// https://w3c.github.io/webdriver-bidi/#command-script-callFunction
void call_function(HTML::Navigable& navigable, JsonObject const& params, OnCommandComplete on_complete)
{
    auto function_declaration = TRY_OR_COMPLETE(get_string(params, "functionDeclaration"sv));
    auto await_promise = TRY_OR_COMPLETE(get_bool(params, "awaitPromise"sv));

    // 1. Let realm be the result of trying to get a realm from a target given the value of the target field of command
    //    parameters.
    auto& settings = *TRY_OR_COMPLETE(get_a_realm_from_a_target(navigable, params));
    auto& vm = settings.global_object().vm();

    // 2. Let realm id be realm's realm id.
    // 3. Let environment settings be the environment settings object whose realm execution context's Realm component is
    //    realm.
    auto& environment_settings = settings;

    HTML::TemporaryExecutionContext execution_context { settings };

    // 4. Let command arguments be the value of the arguments field of command parameters.
    // 5. Let deserialized arguments be an empty list.
    GC::RootVector<JS::Value> deserialized_arguments;

    // 6. If command arguments is not null, set deserialized arguments to the result of trying to deserialize arguments
    //    given realm, command arguments and session.
    if (auto command_arguments = params.get("arguments"sv); command_arguments.has_value()) {
        if (!command_arguments->is_array())
            return on_complete->function()(invalid_argument("Parameter 'arguments' must be a list"sv));

        // https://w3c.github.io/webdriver-bidi/#deserialize-arguments
        for (auto const& serialized_argument : command_arguments->as_array().values())
            deserialized_arguments.append(TRY_OR_COMPLETE(deserialize_local_value(serialized_argument, settings)));
    }

    // 7. Let this parameter be the value of the this field of command parameters.
    // 8. Let this object be null.
    JS::Value this_object = JS::js_null();

    // 9. If this parameter is not null, set this object to the result of trying to deserialize local value given this
    //    parameter, realm and session.
    if (auto this_parameter = params.get("this"sv); this_parameter.has_value())
        this_object = TRY_OR_COMPLETE(deserialize_local_value(*this_parameter, settings));

    // 10. Let function declaration be the value of the functionDeclaration field of command parameters.
    // 11. Let await promise be the value of the awaitPromise field of command parameters.

    // 12. Let serialization options be the value of the serializationOptions field of command parameters, if present, or
    //     otherwise a map matching the script.SerializationOptions production with the fields set to their default
    //     values.
    auto serialization_options = TRY_OR_COMPLETE(get_serialization_options(params));

    // 13. Let result ownership be the value of the resultOwnership field of command parameters, if present, or none
    //     otherwise.
    auto result_ownership = TRY_OR_COMPLETE(get_result_ownership(params));

    auto user_activation = TRY_OR_COMPLETE(get_optional_bool(params, "userActivation"sv, false));

    // 14. Let base URL be the API base URL of environment settings.
    auto base_url = environment_settings.api_base_url();

    // 15. Let options be the default script fetch options.
    // 16. Let function body evaluation status be the result of evaluate function body with function declaration,
    //     environment settings, base URL, and options.
    auto function_body_evaluation_status = evaluate_function_body(function_declaration, environment_settings, base_url);

    // 17. If function body evaluation status.[[Type]] is throw:
    if (function_body_evaluation_status.is_abrupt()) {
        // 1. Let exception details be the result of get exception details given realm, function body evaluation status,
        //    result ownership and session.
        // 2. Return a new map matching the script.EvaluationResultException production, with the exceptionDetails field
        //    set to exception details.
        on_complete->function()(JsonValue { evaluation_result_exception(settings, function_body_evaluation_status.value(), result_ownership) });
        return;
    }

    // 18. Let function object be function body evaluation status.[[Value]].
    auto function_object = function_body_evaluation_status.value();

    // 19. If IsCallable(function object) is false:
    if (!function_object.is_function()) {
        // 1. Return an error with error code invalid argument
        return on_complete->function()(invalid_argument("Function declaration is not a function"sv));
    }

    // 20. If command parameters["userActivation"] is true, run activation notification steps.
    if (user_activation)
        run_activation_notification_steps(settings);

    // 21. Prepare to run script with environment settings.
    HTML::prepare_to_run_script(environment_settings);

    // 22. Set evaluation status to Call(function object, this object, deserialized arguments).
    auto call_result = JS::call(vm, function_object, this_object, deserialized_arguments.span());
    JS::Completion evaluation_status = call_result.is_error() ? JS::Completion { call_result.release_error() } : JS::normal_completion(call_result.release_value());

    // 23. If evaluation status.[[Type]] is normal, and await promise is true, and IsPromise(evaluation
    //     status.[[Value]]):
    //     1. Set evaluation status to Await(evaluation status.[[Value]]).
    // 24. Clean up after running script with environment settings.
    HTML::clean_up_after_running_script(environment_settings);

    // 25. If evaluation status.[[Type]] is throw:
    //     1. Let exception details be the result of get exception details given realm, evaluation status, result
    //        ownership and session.
    //     2. Return a new map matching the script.EvaluationResultException production, with the exceptionDetails field
    //        set to exception details.
    // 26. Assert: evaluation status.[[Type]] is normal.
    // 27. Let result be the result of serialize as a remote value with evaluation status.[[Value]], serialization
    //     options, result ownership, a new map as serialization internal map, realm and session.
    // 28. Return a new map matching the script.EvaluationResultSuccess production, with the realm field set to realm id,
    //     and the result field set to result.
    complete_evaluation(settings, move(evaluation_status), await_promise, serialization_options, result_ownership, move(on_complete));
}

// https://w3c.github.io/webdriver-bidi/#command-script-disown
Response disown(HTML::Navigable& navigable, JsonObject const& params)
{
    auto handles = params.get("handles"sv);
    if (!handles.has_value() || !handles->is_array())
        return invalid_argument("Parameter 'handles' must be a list of strings"sv);
    for (auto const& handle : handles->as_array().values()) {
        if (!handle.is_string())
            return invalid_argument("Parameter 'handles' must be a list of strings"sv);
    }

    // 1. Let realm be the result of trying to get a realm from a target given the value of the target field of command
    //    parameters.
    auto& settings = *TRY(get_a_realm_from_a_target(navigable, params));

    // 2. Let handles the value of the handles field of command parameters.
    // 3. For each handle id of handles:
    for (auto const& handle_id : handles->as_array().values()) {
        // 1. Let handle map be realm's handle object map
        // 2. If handle map contains handle id, remove handle id from the handle map.
        remove_handle(settings, handle_id.as_string());
    }

    // 4. Return success with data null.
    return JsonValue {};
}

// https://w3c.github.io/webdriver-bidi/#command-script-getRealms
Response get_realms(HTML::Navigable& navigable, JsonObject const& params)
{
    auto type = params.get_string("type"sv);

    // 1. Let environment settings be a list of all the environment settings objects that have their execution ready flag
    //    set.
    // 2. If command parameters contains context:
    //     1. Let navigable be the result of trying to get a navigable with command parameters["context"].
    //     2. Let document be navigable's active document.
    //     3. Let navigable environment settings be a list.
    //     4. For each settings of environment settings:
    //         1. If any of the following conditions hold:
    //            - The associated Document of settings' relevant global object is document
    //            - The global object specified by settings is a WorkerGlobalScope with document in its owner set
    //            Append settings to navigable environment settings.
    //     5. Set environment settings to navigable environment settings.
    // NB: The browser process asks the process hosting each navigable's active document for the realms of that
    //     document.
    // FIXME: Include the realms of workers.
    GC::RootVector<HTML::EnvironmentSettingsObject*> environment_settings;
    if (auto* local_navigable = as_if<HTML::LocalNavigable>(navigable)) {
        if (auto document = local_navigable->active_document()) {
            auto& settings = document->relevant_settings_object();
            if (settings.execution_ready)
                environment_settings.append(&settings);
            for_each_sandbox_realm(*document, [&](auto& sandbox) { environment_settings.append(&sandbox); });
        }
    }

    // 3. Let realms be a list.
    JsonArray realms;

    // 4. For each settings of environment settings:
    for (auto* settings : environment_settings) {
        // 1. Let realm info be the result of get the realm info given settings.
        auto realm_info = get_the_realm_info(*settings);

        // 2. If command parameters contains type and realm info["type"] is not equal to command parameters["type"] then
        //    continue.
        if (type.has_value() && realm_info.has_value() && realm_info->get_string("type"sv) != *type)
            continue;

        // 3. If realm info is not null, append realm info to realms.
        if (realm_info.has_value())
            realms.must_append(realm_info.release_value());
    }

    // 5. Let body be a map matching the script.GetRealmsResult production, with the realms field set to realms.
    JsonObject body;
    body.set("realms"sv, move(realms));

    // 6. Return success with data body.
    return JsonValue { move(body) };
}

// https://w3c.github.io/webdriver-bidi/#run-webdriver-bidi-preload-scripts
void run_webdriver_bidi_preload_scripts(HTML::EnvironmentSettingsObject& environment_settings)
{
    // NB: The preload scripts may spin the event loop, which may replace the session state, so they are copied.
    auto preload_scripts = session_state().preload_scripts;
    if (preload_scripts.is_empty())
        return;

    // 1. Let document be environment settings' relevant global object's associated Document.
    auto* window = HTML::window_from_global_object(environment_settings.global_object());
    if (!window)
        return;
    auto& document = window->associated_document();

    // 2. Let navigable be document's navigable.
    auto navigable = document.navigable();
    if (!navigable)
        return;

    // 3. Let user context be navigable's associated user context.
    // 4. Let user context id be user context's user context id.
    auto user_context_id = DEFAULT_USER_CONTEXT_ID;

    // 5. For each session in active BiDi sessions:
    //     1. For each preload script in session's preload script map's values:
    for (auto const& preload_script : preload_scripts) {
        if (!is_active() || navigable->active_document().ptr() != &document)
            return;
        // 1. If preload script's user contexts's size is not zero:
        //     1. If preload script's user contexts does not contain user context id, continue.
        if (!preload_script.user_contexts.is_empty() && !preload_script.user_contexts.contains_slow(user_context_id))
            continue;

        // 2. If preload script's contexts is not null:
        if (preload_script.contexts.has_value()) {
            // 1. Let navigable id be navigable’s top-level traversable's id.
            auto top_level_traversable_id = navigable_id(*navigable->top_level_traversable());

            // 2. If preload script's contexts does not contain navigable id, continue.
            if (!preload_script.contexts->contains_slow(top_level_traversable_id))
                continue;
        }

        // 3. If preload script's sandbox is not null, let realm be get or create a sandbox realm with preload script's
        //    sandbox and navigable. Otherwise let realm be environment settings' realm execution context's Realm
        //    component.
        auto& settings = preload_script.sandbox.has_value()
            ? static_cast<HTML::EnvironmentSettingsObject&>(get_or_create_sandbox_realm(document, *preload_script.sandbox))
            : environment_settings;

        // 4. Let exception reporting global be be environment settings' realm execution context's Realm component's
        //    global object.
        auto& exception_reporting_global = settings.global_object();

        HTML::TemporaryExecutionContext execution_context { settings };

        // 5. Let arguments be preload script's arguments.
        // 6. Let deserialized arguments be an empty list.
        GC::RootVector<JS::Value> deserialized_arguments;

        // 7. For each argument in arguments:
        if (preload_script.arguments.is_array()) {
            for (auto const& argument : preload_script.arguments.as_array().values()) {
                // 1. Let channel be create a channel with session, realm and argument.
                // 2. Append channel to deserialized arguments.
                if (argument.is_object())
                    deserialized_arguments.append(create_a_channel(settings, argument.as_object()));
            }
        }

        // 8. Let base URL be the API base URL of environment settings.
        auto base_url = settings.api_base_url();

        // 9. Let options be the default script fetch options.
        // 10. Let function declaration be preload script's function declaration.
        // 11. Let function body evaluation status be the result of evaluate function body with function declaration,
        //     environment settings, base URL, and options.
        auto function_body_evaluation_status = evaluate_function_body(preload_script.function_declaration, settings, base_url);

        // 12. If function body evaluation status is an abrupt completion, then report an exception given by function
        //     body evaluation status.[[Value]] for exception reporting global.
        if (function_body_evaluation_status.is_abrupt()) {
            HTML::report_an_exception(exception_reporting_global, function_body_evaluation_status.value());
            continue;
        }

        // 13. Let function object be function body evaluation status.[[Value]].
        auto function_object = function_body_evaluation_status.value();

        // 14. If IsCallable(function object) is false:
        if (!function_object.is_function()) {
            // 1. Let error be a new TypeError object in realm.
            auto error = BindingsGlue::create_preload_type_error(settings);

            // 2. Report an exception error for exception reporting global.
            HTML::report_an_exception(exception_reporting_global, error);
            continue;
        }

        // 15. Prepare to run script with environment settings.
        HTML::prepare_to_run_script(settings);

        // 16. Set evaluation status to Call(function object, null, deserialized arguments).
        auto evaluation_status = JS::call(settings.global_object().vm(), function_object, JS::js_null(), deserialized_arguments.span());

        // 17. Clean up after running script with environment settings.
        HTML::clean_up_after_running_script(settings);

        // 18. If evaluation status is an abrupt completion, then report an exception given by evaluation
        //     status.[[Value]] for exception reporting global.
        if (evaluation_status.is_error())
            HTML::report_an_exception(exception_reporting_global, evaluation_status.error_value());
    }
}

}
