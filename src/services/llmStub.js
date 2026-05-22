/**
 * LLM Stub
 *
 * Drop-in replacement for the third-party LLM module, activated by setting
 * `BIOCBOT_TEST_LLM_STUB=1`. The Playwright web server runs with this flag
 * so the e2e suite can exercise LLM-backed routes without making real
 * ChatGPT calls. Responses are scripted via the small test-only routes in
 * src/routes/testLlmStub.js.
 *
 * Not loaded in production: src/services/llm.js only requires this module
 * when the stub flag is set.
 */

const DEFAULT_RESPONSE_CONTENT = '{}';

class LLMStub {
    constructor() {
        this.queue = [];
        this.rules = [];
        this.defaultContent = DEFAULT_RESPONSE_CONTENT;
        this.callLog = [];
    }

    reset() {
        this.queue = [];
        this.rules = [];
        this.defaultContent = DEFAULT_RESPONSE_CONTENT;
        this.callLog = [];
    }

    enqueueContent(content) {
        this.queue.push(String(content == null ? '' : content));
    }

    enqueueMany(responses) {
        for (const r of responses) {
            if (r == null) continue;
            if (typeof r === 'string') this.enqueueContent(r);
            else if (typeof r === 'object' && 'content' in r) this.enqueueContent(r.content);
            else this.enqueueContent(JSON.stringify(r));
        }
    }

    setDefaultContent(content) {
        this.defaultContent = String(content == null ? '' : content);
    }

    // Register a content-matching rule. Useful when multiple background LLM
    // calls fire in non-deterministic order (e.g. fire-and-forget mental-health
    // analysis vs main chat reply). Rules are tried before the FIFO queue and
    // are NOT consumed by use — the matching rule keeps applying for all
    // subsequent calls until reset(). Supported matchers:
    //   - matchSystemPrompt: substring to find in options.systemPrompt
    //   - matchMessage:      substring to find in the message string
    // A rule needs at least one matcher; calls with no rule match fall through
    // to the FIFO queue, then to defaultContent.
    addRule(rule) {
        if (!rule || (rule.matchSystemPrompt === undefined && rule.matchMessage === undefined)) {
            throw new Error('LLMStub.addRule: rule needs matchSystemPrompt or matchMessage');
        }
        this.rules.push({
            matchSystemPrompt: rule.matchSystemPrompt,
            matchMessage: rule.matchMessage,
            content: String(rule.content == null ? '' : rule.content),
        });
    }

    _ruleMatch(message, options) {
        const sysPrompt = (options && typeof options.systemPrompt === 'string') ? options.systemPrompt : '';
        const msg = typeof message === 'string' ? message : '';
        for (const r of this.rules) {
            const spOk = r.matchSystemPrompt === undefined || sysPrompt.includes(r.matchSystemPrompt);
            const mOk = r.matchMessage === undefined || msg.includes(r.matchMessage);
            if (spOk && mOk) return r.content;
        }
        return null;
    }

    _nextContent(message, options) {
        const ruled = this._ruleMatch(message, options);
        if (ruled !== null) return ruled;
        if (this.queue.length > 0) return this.queue.shift();
        return this.defaultContent;
    }

    // Mirrors ubc-genai-toolkit-llm LLMModule API surface used by LLMService

    async sendMessage(message, options = {}) {
        this.callLog.push({ kind: 'sendMessage', message: String(message).slice(0, 500), options });
        const content = this._nextContent(message, options);
        return { content };
    }

    createConversation() {
        const stub = this;
        const messages = [];
        return {
            messages,
            addMessage(role, content) {
                messages.push({ role, content });
            },
            async send(options = {}) {
                stub.callLog.push({ kind: 'conversation.send', messages: [...messages], options });
                const lastUser = [...messages].reverse().find((m) => m.role === 'user');
                const content = stub._nextContent(lastUser ? lastUser.content : '', options);
                return { content };
            },
        };
    }

    getProviderName() {
        return 'test-stub';
    }

    async getAvailableModels() {
        return ['test-stub-model'];
    }
}

let singleton = null;

function getLLMStub() {
    if (!singleton) singleton = new LLMStub();
    return singleton;
}

module.exports = { LLMStub, getLLMStub };
