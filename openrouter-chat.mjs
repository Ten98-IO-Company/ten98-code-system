const encoder = new TextEncoder();
function invalid() { throw new TypeError('Invalid OpenRouter chat protocol value.'); }
const record = (v) => v !== null && typeof v === 'object' && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null);
function text(v) {
    if (typeof v !== 'string' || v.includes('\0'))
        return false;
    for (let i = 0; i < v.length; i++) {
        const c = v.charCodeAt(i);
        if (c >= 0xd800 && c <= 0xdbff) {
            const next = v.charCodeAt(++i);
            if (!(next >= 0xdc00 && next <= 0xdfff))
                return false;
        }
        else if (c >= 0xdc00 && c <= 0xdfff)
            return false;
    }
    return true;
}
function bytes(v, limit) { if (encoder.encode(v).byteLength > limit)
    invalid(); }
function keys(v, allowed) {
    if (Object.keys(v).some(key => !allowed.includes(key)))
        invalid();
}
function options(input) {
    if (!input || ![input.maxContextBytes, input.maxArgumentBytes, input.maxMessageBytes].every(v => Number.isSafeInteger(v) && v > 0)
        || !Array.isArray(input.allowedToolNames) || input.allowedToolNames.some(v => typeof v !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(v)))
        invalid();
    const names = new Set(input.allowedToolNames);
    if (names.size !== input.allowedToolNames.length)
        invalid();
    return names;
}
/** Validate JSON structure independently of its original or canonical wire encoding. */
function validateJson(value, limit) {
    const queue = [{ value }], active = new Set();
    let nodes = 0;
    while (queue.length) {
        const entry = queue.pop(), item = entry.value;
        if (entry.exit) {
            active.delete(item);
            continue;
        }
        if (++nodes > limit)
            invalid();
        if (typeof item === 'string') {
            if (!text(item))
                invalid();
            bytes(item, limit);
            continue;
        }
        if (item === null || typeof item === 'boolean' || typeof item === 'number' && Number.isFinite(item))
            continue;
        if (!Array.isArray(item) && !record(item))
            invalid();
        if (active.has(item))
            invalid();
        active.add(item);
        queue.push({ value: item, exit: true });
        const descriptors = Object.getOwnPropertyDescriptors(item);
        if (Object.getOwnPropertySymbols(item).length)
            invalid();
        if (Array.isArray(item) && (Object.keys(item).length !== item.length || Object.keys(item).some((key, index) => key !== String(index))))
            invalid();
        for (const [key, descriptor] of Object.entries(descriptors)) {
            if (Array.isArray(item) && key === 'length')
                continue;
            if (!descriptor.enumerable || !('value' in descriptor) || !text(key))
                invalid();
            bytes(key, limit);
            queue.push({ value: descriptor.value });
        }
    }
}
/** Refuse non-JSON objects/accessors before serialization; detach validated output from caller mutations. */
function copyJson(value, limit) {
    validateJson(value, limit);
    try {
        const encoded = JSON.stringify(value);
        bytes(encoded, limit);
        return structuredClone(value);
    }
    catch {
        return invalid();
    }
}
function assistant(value, names, limits) {
    if (!record(value) || value.role !== 'assistant')
        invalid();
    keys(value, ['role', 'content', 'tool_calls', 'refusal', 'reasoning', 'reasoning_content', 'reasoning_details']);
    for (const key of ['content', 'refusal', 'reasoning', 'reasoning_content']) {
        if (Object.hasOwn(value, key) && value[key] !== null && !text(value[key]))
            invalid();
    }
    if (Object.hasOwn(value, 'reasoning_details') && (!Array.isArray(value.reasoning_details) || value.reasoning_details.some(v => !record(v))))
        invalid();
    if (Object.hasOwn(value, 'tool_calls')) {
        if (!Array.isArray(value.tool_calls) || !value.tool_calls.length)
            invalid();
        const ids = new Set();
        for (const call of value.tool_calls) {
            if (!record(call))
                invalid();
            keys(call, ['id', 'type', 'function']);
            if (!text(call.id) || !call.id.length || ids.has(call.id) || call.type !== 'function' || !record(call.function))
                invalid();
            ids.add(call.id);
            keys(call.function, ['name', 'arguments']);
            if (typeof call.function.name !== 'string' || !names.has(call.function.name) || !text(call.function.arguments))
                invalid();
            bytes(call.function.arguments, limits.maxArgumentBytes);
            let args;
            try {
                args = JSON.parse(call.function.arguments);
            }
            catch {
                return invalid();
            }
            if (!record(args))
                invalid();
            validateJson(args, limits.maxArgumentBytes);
        }
        if (value.refusal)
            invalid();
    }
    else if (typeof value.content !== 'string' && !(typeof value.refusal === 'string' && value.refusal.length))
        invalid();
    return value;
}
/** Validate the whole message before returning any call. Identity, HTTP status and usage are app-owned. */
export function readOpenRouterAssistantMessageV1(value, finishReason, limits) {
    const names = options(limits), message = assistant(copyJson(value, limits.maxMessageBytes), names, limits);
    if (finishReason === 'length' || finishReason === 'content_filter' || finishReason === 'error')
        return { kind: 'incomplete', finishReason, message };
    if (finishReason === 'tool_calls') {
        if (!message.tool_calls)
            invalid();
        return { kind: 'tool-calls', message: message };
    }
    if (finishReason !== 'stop' || message.tool_calls)
        invalid();
    return { kind: message.refusal ? 'refusal' : 'text', message };
}
/** Require complete call groups. IDs are scoped to their group and may recur after all results arrive. */
export function validateOpenRouterToolHistoryV1(value, limits) {
    const names = options(limits), history = copyJson(value, limits.maxContextBytes);
    if (!Array.isArray(history) || !history.length)
        invalid();
    const pending = new Map();
    let hasUser = false;
    for (const item of history) {
        if (!record(item))
            invalid();
        if (item.role === 'tool') {
            keys(item, ['role', 'tool_call_id', 'content', 'name']);
            if (!text(item.tool_call_id) || !pending.has(item.tool_call_id) || !text(item.content)
                || Object.hasOwn(item, 'name') && item.name !== pending.get(item.tool_call_id))
                invalid();
            pending.delete(item.tool_call_id);
            continue;
        }
        if (pending.size)
            invalid();
        if (item.role === 'assistant') {
            if (!hasUser)
                invalid();
            bytes(JSON.stringify(item), limits.maxMessageBytes);
            const message = assistant(item, names, limits);
            for (const call of message.tool_calls ?? [])
                pending.set(call.id, call.function.name);
        }
        else {
            keys(item, ['role', 'content']);
            if (!text(item.content) || item.role !== 'user' && item.role !== 'system' || item.role === 'system' && hasUser)
                invalid();
            if (item.role === 'user')
                hasUser = true;
        }
    }
    if (!hasUser || pending.size)
        invalid();
    return history;
}
