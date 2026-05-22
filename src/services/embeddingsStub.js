/**
 * Embeddings Stub
 *
 * Drop-in replacement for ubc-genai-toolkit-embeddings' EmbeddingsModule when
 * BIOCBOT_TEST_LLM_STUB=1. Produces deterministic bag-of-words hash vectors
 * so RAG search still returns sensible nearest neighbours in tests without
 * any OpenAI traffic.
 *
 * Vector contract:
 *  - `embed(text)` returns `[ [v1, v2, ..., vN] ]` (matches the toolkit's
 *    "nested array" return shape that src/services/qdrantService.js expects).
 *  - Vectors are L2-normalised so cosine similarity is well-behaved.
 *  - Shared vocabulary → positive dot product, so a query that mentions a
 *    sentinel token in a seeded document will retrieve that chunk.
 */

const crypto = require('crypto');

function tokenize(text) {
    return String(text || '').toLowerCase().match(/[a-z0-9]+/g) || [];
}

function tokenBucket(token, dim) {
    // Stable hash → bucket index. SHA-256 first 4 bytes is plenty.
    const h = crypto.createHash('sha256').update(token).digest();
    return h.readUInt32BE(0) % dim;
}

function bagOfWordsEmbedding(text, dim) {
    const v = new Array(dim).fill(0);
    for (const tok of tokenize(text)) {
        v[tokenBucket(tok, dim)] += 1;
    }
    let sumSq = 0;
    for (let i = 0; i < dim; i++) sumSq += v[i] * v[i];
    const norm = Math.sqrt(sumSq);
    if (norm === 0) {
        // Empty / no-token text: use a stable non-zero seed so Qdrant doesn't
        // reject a zero vector.
        v[0] = 1;
        return v;
    }
    for (let i = 0; i < dim; i++) v[i] = v[i] / norm;
    return v;
}

class EmbeddingsStub {
    constructor({ vectorSize } = {}) {
        // Default to text-embedding-3-small's 1536 dims so existing Qdrant
        // collections seeded in real envs stay compatible.
        this.vectorSize = Number(vectorSize) || 1536;
    }

    async embed(input) {
        if (Array.isArray(input)) {
            return input.map((t) => bagOfWordsEmbedding(t, this.vectorSize));
        }
        // Match the toolkit's nested-array return shape for single strings.
        return [bagOfWordsEmbedding(input, this.vectorSize)];
    }
}

module.exports = { EmbeddingsStub, bagOfWordsEmbedding };
