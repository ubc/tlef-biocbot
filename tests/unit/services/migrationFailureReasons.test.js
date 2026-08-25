/**
 * Turning provider errors into sentences an instructor can act on.
 *
 * The rule these tests hold to: what a person sees says what happened, what it
 * means for their course, and what to do next — and never quotes the provider's
 * own error text. That text stays on the item for the browser console.
 */
const {
    REASONS,
    classifyFailure,
    describeReason,
    summarizeFailures
} = require('../../../src/services/migrationFailureReasons');

const PROXY = 'ubc-llm-proxy';
const OPENAI = 'openai';

function failedJob(errors, { toProvider = PROXY, fromProvider = OPENAI } = {}) {
    return {
        toProvider,
        fromProvider,
        items: errors.map((error, index) => ({
            status: 'failed',
            title: `file-${index + 1}.docx`,
            error
        }))
    };
}

describe('classifying a provider failure', () => {
    test('an embedding deadline is a timeout, from the code or from the stored string', () => {
        const thrown = Object.assign(new Error('Embedding request for x timed out after 30s'), {
            code: 'EMBEDDING_TIMEOUT'
        });
        expect(classifyFailure(thrown)).toBe(REASONS.PROVIDER_TIMEOUT);

        // A job that failed before this classification existed only has the
        // string, so the string alone has to be enough.
        expect(classifyFailure(
            'Failed to generate embedding for chunk 1: Embedding request for '
            + 'qwen3-embedding-0.6b timed out after 30s'
        )).toBe(REASONS.PROVIDER_TIMEOUT);
    });

    test('a surface with no key names the key, not an unknown error', () => {
        expect(classifyFailure('No stored ubc-llm-sandbox credential for course:C1'))
            .toBe(REASONS.KEY_MISSING);
    });

    test('HTTP status is used when the message is unhelpful', () => {
        expect(classifyFailure(Object.assign(new Error('request failed'), { status: 401 })))
            .toBe(REASONS.KEY_REJECTED);
        expect(classifyFailure(Object.assign(new Error('request failed'), { status: 429 })))
            .toBe(REASONS.RATE_LIMITED);
    });

    test('the platform saying no to a model is not the same as saying no to the key', () => {
        expect(classifyFailure("key not allowed to access model. This key can only access models=['a']"))
            .toBe(REASONS.MODEL_UNAVAILABLE);
        expect(classifyFailure('litellm.AuthenticationError: invalid api key'))
            .toBe(REASONS.KEY_REJECTED);
    });

    test('transport errors are told apart from provider errors', () => {
        expect(classifyFailure('connect ECONNREFUSED 127.0.0.1:4000')).toBe(REASONS.PROVIDER_UNREACHABLE);
        expect(classifyFailure('fetch failed')).toBe(REASONS.PROVIDER_UNREACHABLE);
        expect(classifyFailure('Qdrant collection upsert rejected')).toBe(REASONS.VECTOR_STORE);
    });

    test('anything unrecognised is unknown rather than mis-labelled', () => {
        expect(classifyFailure('something nobody predicted')).toBe(REASONS.UNKNOWN);
        expect(classifyFailure(null)).toBe(REASONS.UNKNOWN);
    });
});

describe('what the instructor is told', () => {
    test('the message says what happened, what survived, and what to do', () => {
        const { headline, detail } = describeReason(REASONS.PROVIDER_TIMEOUT, {
            target: 'UBC LLM Proxy',
            current: 'OpenAI Chat GPT'
        });

        expect(headline).toBe('UBC LLM Proxy did not respond in time.');
        expect(detail).toContain('No course material was changed');
        expect(detail).toContain('OpenAI Chat GPT is still answering');
        expect(detail).toContain('try again');
    });

    test('with no previous platform it does not promise one is still answering', () => {
        const { detail } = describeReason(REASONS.PROVIDER_TIMEOUT, { target: 'UBC LLM Proxy' });
        expect(detail).toContain('No course material was changed.');
        expect(detail).not.toContain('still answering');
    });

    test('every reason produces a complete sentence pair', () => {
        for (const reason of Object.values(REASONS)) {
            const { headline, detail } = describeReason(reason, { target: 'X', current: 'Y' });
            expect(headline).toMatch(/\.$/);
            expect(detail.length).toBeGreaterThan(20);
        }
    });
});

describe('summarising a whole job', () => {
    test('the real proxy outage reads as prose, with no jargon and no repetition', () => {
        const timeout = 'Failed to generate embedding for chunk 1: Embedding request for '
            + 'qwen3-embedding-0.6b timed out after 30s';
        const summary = summarizeFailures(failedJob([timeout, timeout]));

        expect(summary.reason).toBe(REASONS.PROVIDER_TIMEOUT);
        expect(summary.headline).toBe('UBC LLM Proxy did not respond in time.');
        // The cause is stated once, so the files are listed bare.
        expect(summary.affected).toEqual([
            { title: 'file-1.docx', cause: null },
            { title: 'file-2.docx', cause: null }
        ]);

        const shown = `${summary.headline} ${summary.detail} ${summary.affected.map(a => a.title).join(' ')}`;
        for (const jargon of ['embedding', 'chunk', 'timed out after', 'qwen3']) {
            expect(shown.toLowerCase()).not.toContain(jargon.toLowerCase());
        }
    });

    test('a job that failed several ways labels each file with its own cause', () => {
        const summary = summarizeFailures(failedJob([
            'Embedding request for m timed out after 30s',
            'No stored ubc-llm-proxy credential for course:C1'
        ]));

        expect(summary.reason).toBeNull();
        expect(summary.affected).toEqual([
            { title: 'file-1.docx', cause: 'No response in time' },
            { title: 'file-2.docx', cause: 'No key available' }
        ]);
    });

    test('a reason recorded at failure time beats re-reading the string', () => {
        const summary = summarizeFailures({
            toProvider: PROXY,
            fromProvider: OPENAI,
            items: [{ status: 'failed', title: 'a.docx', error: 'opaque', failureReason: REASONS.RATE_LIMITED }]
        });
        expect(summary.reason).toBe(REASONS.RATE_LIMITED);
    });

    test('a job with nothing failed has nothing to say', () => {
        expect(summarizeFailures({ items: [{ status: 'done' }] })).toBeNull();
        expect(summarizeFailures({})).toBeNull();
        expect(summarizeFailures(null)).toBeNull();
    });

    test('switching within one platform does not claim another is still answering', () => {
        const summary = summarizeFailures(failedJob(['timed out'], { fromProvider: PROXY }));
        expect(summary.detail).not.toContain('still answering');
    });
});
