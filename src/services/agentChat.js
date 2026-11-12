'use strict';

/**
 * Student chat on the UBC GenAI agents framework (Rung 2a of its PRD, section 7).
 *
 * The old handler in src/routes/chat.js makes one model call that both decides
 * what to say and writes it. Here that splits in two: a "tutor" agent reads the
 * course material and decides, and the framework's summariser writes the one
 * reply the student sees. The struggle check and the summary-attempt check
 * become small JSON agents. Retrieval, the struggle-state update and directive
 * mode reach the agents through tools, so the database and Qdrant stay in
 * BiocBot.
 *
 * This path sits beside the old handler and is off by default. AGENT_CHAT_MODES
 * turns it on per mode (a comma-separated list of tutor, explain, protege).
 * The mental-health check and the chat summary stay on the old code (2b and
 * decision 29).
 */

const prompts = require('./prompts');
const TrackerService = require('./tracker');
const { LANES } = require('./llmLanes');

const CORE_PACKAGE = '@ubc/genai-toolkit-agents-core';
const RUNTIME_PACKAGE = '@ubc/genai-toolkit-agents-runtime';
const AGENT_MODES = Object.freeze(['tutor', 'explain', 'protege']);

/** @type {{ core: any, runtime: any } | null | undefined} */
let framework;

/**
 * The framework is published to GitHub Packages, so, like the encryption
 * toolkit, an install without a registry token cannot fetch it and it is an
 * optional dependency. The agent path is off by default, so a deployment that
 * never turns it on does not need it.
 *
 * @returns {{ core: any, runtime: any } | null}
 */
function loadFramework() {
    if (framework === undefined) {
        try {
            framework = { core: require(CORE_PACKAGE), runtime: require(RUNTIME_PACKAGE) };
        } catch (error) {
            if (error.code !== 'MODULE_NOT_FOUND') throw error;
            framework = null;
        }
    }
    return framework;
}

/**
 * Which mode's prompts a request uses. An explanation request uses the explain
 * prompts even in protégé mode, as the old handler's system prompt does.
 * @param {{ mode?: string, isExplanationRequest?: boolean }} body
 * @returns {'tutor'|'explain'|'protege'}
 */
function resolveAgentMode(body = {}) {
    if (body.isExplanationRequest) return 'explain';
    return body.mode === 'protege' ? 'protege' : 'tutor';
}

/**
 * @param {string} mode
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {boolean} Whether this mode runs on the agent path
 */
function isAgentChatEnabled(mode, env = process.env) {
    const enabled = String(env.AGENT_CHAT_MODES || '')
        .split(',')
        .map(value => value.trim().toLowerCase())
        .filter(Boolean);
    return AGENT_MODES.includes(mode) && enabled.includes(mode) && loadFramework() !== null;
}

// Schemas are constants so that definitions built on every request reuse one
// compiled schema (PRD section 7, "per-request definitions").
const TRACKER_SCHEMA = Object.freeze({
    type: 'object',
    required: ['isStruggling', 'mappedTopic'],
    properties: {
        isStruggling: { type: 'boolean' },
        rawTopic: { type: 'string' },
        mappedTopic: { type: 'string' },
        matchConfidence: { type: 'number' },
        reason: { type: 'string' }
    }
});
const SUMMARY_CHECK_SCHEMA = Object.freeze({
    type: 'object',
    required: ['isSummaryAttempt'],
    properties: { isSummaryAttempt: { type: 'boolean' } }
});
const KEY_POINTS = Object.freeze({
    type: 'array',
    items: {
        type: 'object',
        required: ['point'],
        properties: { point: { type: 'string' }, unit: { type: 'string' } }
    }
});
const PLAN_SCHEMA = Object.freeze({
    type: 'object',
    required: ['approach', 'keyPoints'],
    properties: {
        approach: { type: 'string' },
        keyPoints: KEY_POINTS,
        coverage: { type: 'string' },
        style: { type: 'string' },
        nextQuestion: { type: 'string' }
    }
});
const PROTEGE_PLAN_SCHEMA = Object.freeze({
    type: 'object',
    required: ['verdict', 'nextQuestion'],
    properties: {
        verdict: { type: 'string' },
        whatTheyGotRight: { type: 'string' },
        confusionToVoice: { type: 'string' },
        nextQuestion: { type: 'string' }
    }
});

/**
 * What the student sees while each step runs. The framework carries a label
 * and status on an agent, on the summariser and on a tool, and sends them with
 * its events; BiocBot streams them to the chat page (see handleAgentChat in
 * src/routes/chat.js). In order: the tracker, the course search (the tutor's
 * read tool), the tutor's own model call, then the writer.
 */
const PROGRESS = Object.freeze({
    tracker: Object.freeze({ label: 'Understanding', status: 'BiocBot is understanding your message' }),
    courseSearch: Object.freeze({ label: 'Course materials', status: 'BiocBot is finding relevant course materials' }),
    tutor: Object.freeze({ label: 'Planning', status: 'BiocBot is working out what to say' }),
    writer: Object.freeze({ label: 'Writing', status: 'BiocBot is finalizing its response' })
});

const FALLBACK_REPLY = 'Sorry, I encountered an error processing your message.';
const REPROMPT_TEXT = '\n\n----------------\nHey, I know you asked another question, would you like to summarize our chat again?';

/**
 * PRD section 7.4, second finding, and decision 20: what a model damages in
 * math that still parses as JSON, mended because only BiocBot knows it expects
 * math.
 * - `\?` for `\)?` inside open inline math.
 * - A doubled backslash inside [SMILES], which is one backslash in SMILES, or
 *   anywhere outside math, where chat text never means one.
 * - A LaTeX command that JSON read as a control character (`\frac` as a form
 *   feed and "rac", `\theta` as a tab and "heta"), inside math only, because a
 *   real tab or new line is normal text elsewhere. Form feeds and backspaces
 *   are never real text, so they are mended anywhere.
 * `\\` inside a LaTeX environment is a real line break and is left alone.
 * @param {string} text
 * @returns {string}
 */
function mendMathText(text) {
    if (typeof text !== 'string' || text === '') return text;
    const controls = { '\f': 'f', '\b': 'b', '\t': 't', '\n': 'n', '\r': 'r' };

    let mended = text
        .replace(/\[SMILES\]([\s\S]*?)\[\/SMILES\]/g, (match, smiles) => `[SMILES]${smiles.replace(/\\\\/g, '\\')}[/SMILES]`)
        .replace(/[\f\b](?=[a-zA-Z])/g, char => `\\${controls[char]}`);

    let result = '';
    let inMath = false;
    for (let i = 0; i < mended.length; i += 1) {
        const char = mended[i];
        const next = mended[i + 1];
        // Outside math, a doubled backslash is over-escaping, never meant: the
        // real-model check saw `C=C\\C` in a SMILES string written without
        // tags. Drop one and look at the pair again, so `\\(` opens math.
        if (!inMath && char === '\\' && next === '\\') continue;
        // The same over-escaping on the closing delimiter of inline math.
        if (inMath && char === '\\' && next === '\\' && mended[i + 2] === ')') continue;
        if (char === '\\' && (next === '(' || next === '[')) { inMath = true; result += `\\${next}`; i += 1; continue; }
        if (char === '\\' && (next === ')' || next === ']')) { inMath = false; result += `\\${next}`; i += 1; continue; }
        if (inMath && char === '\\' && next === '?') { inMath = false; result += '\\)?'; i += 1; continue; }
        if (inMath && controls[char] && /[a-zA-Z]/.test(next || '')) { result += `\\${controls[char]}`; continue; }
        result += char;
    }
    return result;
}

/** Applies mendMathText to every string in a JSON value. */
function mendStrings(value) {
    if (typeof value === 'string') return mendMathText(value);
    if (Array.isArray(value)) return value.map(mendStrings);
    if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value).map(([key, inner]) => [key, mendStrings(inner)]));
    }
    return value;
}

/**
 * The prompts for one request, built from the course's editable prompts.
 * @param {Object} options
 * @param {'tutor'|'explain'|'protege'} options.mode
 * @param {{ base: string, tutor: string, protege: string, explain: string }} options.coursePrompts
 *   The course's prompts, with learning objectives already added to `base`
 * @returns {{ planner: string, writer: string }}
 */
function buildModePrompts({ mode, coursePrompts }) {
    const persona = `${coursePrompts.base}${coursePrompts[mode]}`;
    return {
        planner: prompts.appendAgentRules(persona, prompts.AGENT_PLANNER_RULES[mode], prompts.MATH_DELIMITER_RULE),
        writer: prompts.appendAgentRules(persona, prompts.AGENT_WRITER_RULES[mode], prompts.MATH_DELIMITER_RULE)
    };
}

/**
 * Builds the agents and the system for one request. Everything here is plain
 * data, so a definition could later come from a builder or a file.
 * @param {Object} options
 * @param {'tutor'|'explain'|'protege'} options.mode
 * @param {{ planner: string, writer: string }} options.modePrompts
 * @param {string} [options.trackerPrompt] - Set to run the struggle check
 * @param {boolean} [options.checkSummaryAttempt]
 * @returns {{ definitions: Object[], system: Object }}
 */
function buildStudentChatSystem({ mode, modePrompts, trackerPrompt, checkSummaryAttempt }) {
    const definitions = [];
    const add = definition => definitions.push({ version: '1.0.0', ...definition });

    if (trackerPrompt) {
        add({
            id: 'tracker',
            prompt: trackerPrompt,
            outputSchema: TRACKER_SCHEMA,
            llmOptions: { lane: LANES.BACKEND, temperature: 0.1, maxTokens: 220, responseFormat: 'json' },
            progress: PROGRESS.tracker,
            tools: { writes: ['struggle-update'] }
        });
    }
    if (checkSummaryAttempt) {
        add({
            id: 'summary-check',
            prompt: prompts.AGENT_SUMMARY_CHECK_PROMPT,
            outputSchema: SUMMARY_CHECK_SCHEMA,
            llmOptions: { lane: LANES.BACKEND, temperature: 0.1, maxTokens: 50, responseFormat: 'json' }
        });
    }
    add({
        id: 'tutor',
        prompt: modePrompts.planner,
        outputSchema: mode === 'protege' ? PROTEGE_PLAN_SCHEMA : PLAN_SCHEMA,
        // The course's student-facing model decides what to say, as it does today.
        llmOptions: { lane: LANES.FRONTEND, temperature: 0.5, maxTokens: 32768, responseFormat: 'json' },
        timeoutMs: 120000,
        progress: PROGRESS.tutor,
        context: { history: true },
        // The tracker goes first so that directive mode sees this message's update.
        ...(trackerPrompt ? { dependsOn: ['tracker'] } : {}),
        // Directive mode is for the tutor prompt only (old handler: chat.js:1705).
        tools: { reads: ['course-context', ...(mode === 'tutor' ? ['directive-state'] : [])] }
    });

    const system = {
        id: `biocbot-student-chat-${mode}`,
        agents: definitions.map(({ id }) => id),
        visibleAgents: [...definitions.filter(({ progress }) => progress).map(({ id }) => id), 'summariser'],
        summariser: {
            instructions: modePrompts.writer,
            fallbackReply: FALLBACK_REPLY,
            progress: PROGRESS.writer,
            // A failed tutor would leave the writer with no course material (decision 23).
            requires: ['tutor'],
            llmOptions: { lane: LANES.FRONTEND, temperature: 0.5, maxTokens: 32768, responseFormat: 'json' },
            timeoutMs: 120000,
            continuation: {
                maxContinuations: 2,
                instructions: prompts.AGENT_CONTINUATION_INSTRUCTIONS,
                llmOptions: { temperature: mode === 'protege' ? 0.8 : 0.6 }
            }
        },
        errorRecovery: {
            instructions: prompts.AGENT_ERROR_RECOVERY_INSTRUCTIONS,
            maxRetries: 1,
            llmOptions: { lane: LANES.BACKEND, temperature: 0.1, maxTokens: 300, responseFormat: 'json' }
        }
    };

    return { definitions, system };
}

/** A key, configuration or preparing error, which keeps its own response and is never retried. */
function isLlmAccessError(cause) {
    const code = cause && typeof cause.code === 'string' ? cause.code : '';
    return code.startsWith('LLM_KEY_') || code === 'LLM_CONFIGURATION_REQUIRED' || code === 'LLM_PROVIDER_PREPARING'
        || (cause && cause.name === 'LlmKeyError') || (cause && cause.name === 'LlmPreparationError');
}

/**
 * Drops the current message from the end of the history the browser sent, so
 * the model doesn't read it twice.
 * @param {Array<{role: string, content: string}>} messages
 * @param {string} message
 */
function toHistory(messages, message) {
    const history = (Array.isArray(messages) ? messages : [])
        .filter(entry => entry && typeof entry.content === 'string' && (entry.role === 'user' || entry.role === 'assistant'))
        .map(({ role, content }) => ({ role, content }));
    const last = history[history.length - 1];
    if (last && last.role === 'user' && last.content === message) history.pop();
    return history;
}

/**
 * Runs one student message through the agents.
 *
 * @param {Object} options
 * @param {'tutor'|'explain'|'protege'} options.mode
 * @param {string} options.message
 * @param {Array<{role: string, content: string}>} [options.history]
 * @param {{ sendMessage: Function }} options.llm - The course's LLMService
 * @param {{ base: string, tutor: string, protege: string, explain: string, directive: string }} options.coursePrompts
 * @param {boolean} options.runTracker - Whether to ask the model about struggle
 * @param {{ courseId: string, unitName: string, approvedTopics: string[] }} options.trackerContext
 * @param {boolean} [options.checkSummaryAttempt]
 * @param {boolean} [options.preview]
 * @param {() => Promise<{ contextText: string, coverageNote: string }>} options.retrieve
 * @param {(analysis: Object) => Promise<void>} options.recordStruggle - Persists a mapped struggle
 * @param {() => ({ active: boolean, topic?: string })} options.directiveState
 * @param {Object} [options.identifiers]
 * @param {(update: { step: string, label: string, status: string }) => void} [options.onProgress]
 *   Called as each visible step starts. It must not throw, and nothing waits for it.
 * @returns {Promise<{ run: Object, reply: string, replyCall: { model?: string, usage?: any }|null, accessError: any, failureCause: any }>}
 */
async function runStudentChat(options) {
    const loaded = loadFramework();
    if (!loaded) throw new Error(`${RUNTIME_PACKAGE} is not installed`);
    const { core, runtime } = loaded;
    const {
        mode, message, llm, coursePrompts, runTracker, trackerContext, checkSummaryAttempt,
        preview = false, retrieve, recordStruggle, directiveState, identifiers = {}, onProgress
    } = options;

    const modePrompts = buildModePrompts({ mode, coursePrompts });
    const approvedTopics = trackerContext.approvedTopics || [];
    const { definitions, system } = buildStudentChatSystem({
        mode,
        modePrompts,
        trackerPrompt: runTracker
            ? TrackerService.buildAnalysisPrompt(trackerContext.courseId, trackerContext.unitName, approvedTopics)
            : null,
        checkSummaryAttempt
    });

    const agents = core.createAgentRegistry();
    for (const definition of definitions) {
        const result = agents.register(definition);
        if (!result.isValid) throw new TypeError(`Invalid agent ${definition.id}: ${JSON.stringify(result.errors)}`);
    }

    const tools = core.createToolRegistry();
    tools.register({
        id: 'struggle-update',
        sideEffect: true,
        // It writes under a preview user's id, and it's how an instructor sees
        // directive mode in a preview (decision 21).
        allowInPreview: true,
        run: async ({ output }) => {
            const analysis = TrackerService.normalizeAnalysis(output, approvedTopics);
            if (analysis.isStruggling && analysis.isMapped) await recordStruggle(analysis);
        }
    });
    tools.register({
        id: 'directive-state',
        sideEffect: false,
        run: () => {
            const state = directiveState();
            if (!state.active) return { active: false };
            return {
                active: true,
                topic: state.topic,
                instructions: `CRITICAL INSTRUCTION: The student is struggling significantly with the topic "${state.topic}".\nSwitch to DIRECTIVE MODE:\n${coursePrompts.directive}`
            };
        }
    });
    tools.register({
        id: 'course-context',
        sideEffect: false,
        progress: PROGRESS.courseSearch,
        run: () => retrieve()
    });

    const bus = core.createEventBus();
    // For local development only: prints each agent's output, which quotes the
    // student and the course material, so it is off unless asked for.
    if (process.env.AGENT_CHAT_DEBUG === '1') {
        console.log(`🤖 [AGENT_DEBUG] ${mode} mode, student said: ${JSON.stringify(message)}`);
        const started = {};
        bus.subscribe('agent.started', event => { started[event.agentId] = Date.now(); });
        bus.subscribe('agent.completed', event => {
            const seconds = started[event.agentId] ? ((Date.now() - started[event.agentId]) / 1000).toFixed(1) : '?';
            console.log(`🤖 [AGENT_DEBUG] ${event.agentId} finished in ${seconds}s${event.truncated ? ' (cut off)' : ''}:\n${JSON.stringify(event.output, null, 2)}`);
        });
        bus.subscribe('tool.*', event => {
            console.log(`🤖 [AGENT_DEBUG] tool ${event.toolId} for ${event.agentId}: ${event.type.replace('tool.', '')}`);
        });
    }
    if (typeof onProgress === 'function') subscribeProgress(bus, onProgress);
    bus.subscribe('agent.*', event => {
        if (event.type === 'agent.failed' || event.type === 'agent.retrying' || event.type === 'agent.continued' || event.type === 'agent.skipped') {
            const detail = event.failure
                ? `${event.failure.code}: ${event.failure.message}`
                : (event.because ? `because ${event.because.join(', ')} failed` : '');
            console.log(`🤖 [AGENT_CHAT] ${event.type} ${event.agentId} ${detail}`);
        }
    });
    const hooks = core.createHookManager({ bus });
    hooks.addFilter('agent.output', (output, context) =>
        (context && (context.agentId === 'summariser' || context.agentId === 'tutor') ? mendStrings(output) : output));

    const run = await runtime.runSystem(
        system,
        { message, history: toHistory(options.history, message), identifiers },
        {
            llm,
            bus,
            agents,
            tools,
            hooks,
            auditLog: runtime.createAuditLog({
                bus,
                sink: entry => console.log(`🧾 [AGENT_AUDIT] ${entry.agentId}/${entry.toolId} ${entry.status}${entry.code ? ` ${entry.code}` : ''}`)
            }),
            isRetryable: failure => !isLlmAccessError(failure.cause)
        },
        { preview }
    );

    const causes = Object.values(run.failures).map(failure => failure.cause).filter(Boolean);
    const accessError = causes.find(isLlmAccessError) || null;
    const failureCause = run.failures.summariser?.cause || run.failures.tutor?.cause || null;

    const check = run.outputs['summary-check'];
    // A check that failed adds nothing, as today (chat.js:1765).
    const reply = check && check.isSummaryAttempt === false ? `${run.reply}${REPROMPT_TEXT}` : run.reply;

    // The response reports the call that finished the reply, as the old handler
    // reports its last call (a continuation's, if there was one), so nothing is
    // summed across calls.
    const writerCalls = (run.modelCalls && run.modelCalls.summariser) || [];
    const replyCall = writerCalls[writerCalls.length - 1] || null;

    return { run, reply, replyCall, accessError, failureCause };
}

/**
 * Sends the student each visible step's status, from the framework's events.
 * An agent's status shows when it starts, a visible tool's while it runs, and
 * the agent's again once the tool is done, because the agent's model call
 * comes after its read tools. The framework announces an agent and its read
 * tools in one go, so only the last status published together is sent: the
 * agent's own status would otherwise flash before the course search's.
 * @param {Object} bus
 * @param {(update: { step: string, label: string, status: string }) => void} onProgress
 */
function subscribeProgress(bus, onProgress) {
    const agentProgress = new Map();
    let pending = null;
    let lastStatus = null;
    const flush = () => {
        const update = pending;
        pending = null;
        if (!update || update.status === lastStatus) return;
        lastStatus = update.status;
        try {
            onProgress(update);
        } catch (error) {
            console.error('❌ [AGENT_CHAT] Progress listener failed:', error);
        }
    };
    const show = (step, progress) => {
        if (!pending) queueMicrotask(flush);
        pending = { step, label: progress.label, status: progress.status };
    };
    bus.subscribe('agent.started', event => {
        if (!event.visible || !event.progress) return;
        agentProgress.set(event.agentId, event.progress);
        show(event.agentId, event.progress);
    });
    bus.subscribe('tool.*', event => {
        if (!event.visible) return;
        if (event.type === 'tool.started' && event.progress) show(event.agentId, event.progress);
        else if ((event.type === 'tool.completed' || event.type === 'tool.failed') && agentProgress.has(event.agentId)) {
            show(event.agentId, agentProgress.get(event.agentId));
        }
    });
}

module.exports = {
    AGENT_MODES,
    FALLBACK_REPLY,
    REPROMPT_TEXT,
    PROGRESS,
    loadFramework,
    resolveAgentMode,
    isAgentChatEnabled,
    buildModePrompts,
    buildStudentChatSystem,
    mendMathText,
    toHistory,
    isLlmAccessError,
    runStudentChat
};
