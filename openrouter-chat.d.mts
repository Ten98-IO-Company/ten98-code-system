/** Pure Chat Completions validation. Apps retain dispatch, authority, receipts and usage. */
export type OpenRouterJsonV1 = null | boolean | number | string | OpenRouterJsonV1[] | {
    [key: string]: OpenRouterJsonV1;
};
export interface OpenRouterChatOptionsV1 {
    allowedToolNames: readonly string[];
    /** Whole encoded history, e.g. 131072 bytes. */
    maxContextBytes: number;
    /** Original arguments string, e.g. 8192 bytes. */
    maxArgumentBytes: number;
    /** Whole encoded assistant message, e.g. 2097152 bytes. No envelope is parsed. */
    maxMessageBytes: number;
}
export interface OpenRouterFunctionCallV1 {
    id: string;
    type: 'function';
    function: {
        name: string;
        arguments: string;
    };
}
export interface OpenRouterAssistantMessageV1 {
    role: 'assistant';
    content?: string | null;
    tool_calls?: OpenRouterFunctionCallV1[];
    refusal?: string | null;
    reasoning?: string | null;
    reasoning_content?: string | null;
    /** Opaque JSON blocks: order, signatures and unknown block fields are preserved. */
    reasoning_details?: {
        [key: string]: OpenRouterJsonV1;
    }[];
}
export type OpenRouterChatMessageV1 = {
    role: 'system' | 'user';
    content: string;
} | OpenRouterAssistantMessageV1 | {
    role: 'tool';
    tool_call_id: string;
    content: string;
    name?: string;
};
export type OpenRouterAssistantResultV1 = {
    kind: 'text' | 'refusal';
    message: OpenRouterAssistantMessageV1;
} | {
    kind: 'tool-calls';
    message: OpenRouterAssistantMessageV1 & {
        tool_calls: OpenRouterFunctionCallV1[];
    };
} | {
    kind: 'incomplete';
    finishReason: 'length' | 'content_filter' | 'error';
    message: OpenRouterAssistantMessageV1;
};
/** Validate the whole message before returning any call. Identity, HTTP status and usage are app-owned. */
export declare function readOpenRouterAssistantMessageV1(value: unknown, finishReason: unknown, limits: OpenRouterChatOptionsV1): OpenRouterAssistantResultV1;
/** Require complete call groups. IDs are scoped to their group and may recur after all results arrive. */
export declare function validateOpenRouterToolHistoryV1(value: unknown, limits: OpenRouterChatOptionsV1): OpenRouterChatMessageV1[];
