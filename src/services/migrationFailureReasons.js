/**
 * Human-readable causes for migration item failures.
 *
 * The runner records whatever the provider or vector store threw, which is the
 * right thing to keep for debugging and the wrong thing to show an instructor.
 * This module maps those errors onto a small set of causes and writes the
 * sentence a person actually needs: what happened, what it means for their
 * course, and what to do next. The raw error travels alongside it for the
 * browser console.
 */

const { providerLabel } = require('./llmProviders');

const REASONS = {
    PROVIDER_TIMEOUT: 'provider_timeout',
    PROVIDER_UNREACHABLE: 'provider_unreachable',
    KEY_REJECTED: 'key_rejected',
    KEY_MISSING: 'key_missing',
    MODEL_UNAVAILABLE: 'model_unavailable',
    RATE_LIMITED: 'rate_limited',
    VECTOR_STORE: 'vector_store',
    UNKNOWN: 'unknown'
};

/**
 * Short cause shown next to a file name when one job failed several ways.
 */
const SHORT_CAUSE = {
    [REASONS.PROVIDER_TIMEOUT]: 'No response in time',
    [REASONS.PROVIDER_UNREACHABLE]: 'Could not reach the platform',
    [REASONS.KEY_REJECTED]: 'The key was rejected',
    [REASONS.KEY_MISSING]: 'No key available',
    [REASONS.MODEL_UNAVAILABLE]: 'Model not available',
    [REASONS.RATE_LIMITED]: 'Too many requests',
    [REASONS.VECTOR_STORE]: 'Could not save the results',
    [REASONS.UNKNOWN]: 'Unexpected error'
};

function statusCodeOf(error) {
    if (!error || typeof error !== 'object') return null;
    const code = error.status || error.statusCode || error.response?.status;
    return Number.isInteger(code) ? code : null;
}

function textOf(error) {
    if (!error) return '';
    if (typeof error === 'string') return error;
    return String(error.message || error);
}

/**
 * Which cause an item failure belongs to.
 *
 * Accepts an Error (precise: its `code` and HTTP status are used) or the error
 * string a finished job already stored, so jobs that failed before this
 * classification existed still get a readable message.
 *
 * @param {Error|string|null} error
 * @returns {string} one of REASONS
 */
function classifyFailure(error) {
    const code = error && typeof error === 'object' ? error.code : null;
    const status = statusCodeOf(error);
    const text = textOf(error).toLowerCase();

    if (code === 'EMBEDDING_TIMEOUT' || /timed out|timeout|etimedout|aborted/.test(text)) {
        return REASONS.PROVIDER_TIMEOUT;
    }
    if (code === 'LLM_KEY_MISSING' || /no stored credential|no .* key|missing encrypted api key/.test(text)) {
        return REASONS.KEY_MISSING;
    }
    if (status === 429 || /rate limit|too many requests|quota/.test(text)) {
        return REASONS.RATE_LIMITED;
    }
    if (/not allowed to access model|model .*not found|no healthy deployments|unknown model/.test(text)) {
        return REASONS.MODEL_UNAVAILABLE;
    }
    if (status === 401 || status === 403
        || code === 'LLM_KEY_INVALID'
        || /unauthorized|forbidden|invalid api key|authentication|auth_error/.test(text)) {
        return REASONS.KEY_REJECTED;
    }
    if (/econnrefused|enotfound|econnreset|eai_again|fetch failed|network|socket hang up|unreachable/.test(text)) {
        return REASONS.PROVIDER_UNREACHABLE;
    }
    if (/qdrant|collection|vector/.test(text)) {
        return REASONS.VECTOR_STORE;
    }
    return REASONS.UNKNOWN;
}

/**
 * The sentence pair shown to an instructor for a cause.
 *
 * @param {string} reason - one of REASONS
 * @param {Object} context
 * @param {string} context.target - platform being prepared, e.g. 'UBC LLM Proxy'
 * @param {string|null} context.current - platform still answering questions
 * @returns {{headline: string, detail: string}}
 */
function describeReason(reason, { target, current = null }) {
    // Every one of these ends in the same reassurance, so say it once here.
    const untouched = current
        ? `No course material was changed, and ${current} is still answering questions.`
        : 'No course material was changed.';

    switch (reason) {
        case REASONS.PROVIDER_TIMEOUT:
            return {
                headline: `${target} did not respond in time.`,
                detail: `${untouched} The platform may be temporarily unavailable or under maintenance — `
                    + 'wait a few minutes and try again.'
            };
        case REASONS.PROVIDER_UNREACHABLE:
            return {
                headline: `${target} could not be reached.`,
                detail: `${untouched} Check that the platform is online, then try again.`
            };
        case REASONS.KEY_REJECTED:
            return {
                headline: `The saved ${target} key was rejected.`,
                detail: `${untouched} Replace it with a valid key, then try again.`
            };
        case REASONS.KEY_MISSING:
            return {
                headline: `Some material has no ${target} key to prepare it with.`,
                detail: `${untouched} Save a ${target} key on the course or bucket that owns this material, `
                    + 'then try again.'
            };
        case REASONS.MODEL_UNAVAILABLE:
            return {
                headline: `The selected ${target} model is not available for this key.`,
                detail: `${untouched} Choose a different model in the model settings, then try again.`
            };
        case REASONS.RATE_LIMITED:
            return {
                headline: `${target} is refusing further requests right now.`,
                detail: `${untouched} This usually clears on its own — wait a few minutes and try again.`
            };
        case REASONS.VECTOR_STORE:
            return {
                headline: 'The prepared material could not be saved.',
                detail: `${untouched} This is a problem with the vector database rather than ${target}. `
                    + 'Try again, and contact an administrator if it keeps happening.'
            };
        default:
            return {
                headline: `${target} could not prepare some course material.`,
                detail: `${untouched} Try again, and contact an administrator if it keeps happening. `
                    + 'The technical details are in the browser console.'
            };
    }
}

/**
 * A whole job's failure, described for a person.
 *
 * When every item failed the same way — the usual case, because the cause is
 * normally the platform rather than the file — the cause is stated once and the
 * files are simply listed. A mixed job labels each file with its own cause.
 *
 * @param {Object} job - stored migration document
 * @returns {Object|null} null when nothing failed
 */
function summarizeFailures(job) {
    const failed = (job?.items || []).filter(item => item.status === 'failed');
    if (failed.length === 0) return null;

    const target = providerLabel(job.toProvider || job.targetProfile?.provider);
    const current = job.fromProvider && job.fromProvider !== job.toProvider
        ? providerLabel(job.fromProvider)
        : null;

    const reasons = failed.map(item => item.failureReason || classifyFailure(item.error));
    const distinct = [...new Set(reasons)];
    const shared = distinct.length === 1 ? distinct[0] : null;
    const { headline, detail } = shared
        ? describeReason(shared, { target, current })
        : describeReason(REASONS.UNKNOWN, { target, current });

    return {
        reason: shared,
        headline,
        detail,
        // One entry per affected item, already in the order the job queued them.
        affected: failed.map((item, index) => ({
            title: item.title || item.itemId,
            // Only worth showing per item when the job failed more than one way.
            cause: shared ? null : SHORT_CAUSE[reasons[index]]
        }))
    };
}

module.exports = {
    REASONS,
    SHORT_CAUSE,
    classifyFailure,
    describeReason,
    summarizeFailures
};
