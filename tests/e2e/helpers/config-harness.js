// @ts-nocheck
/**
 * Coverage harness for src/services/config.js.
 *
 * The config service is a singleton; once validated it caches `isValidated`.
 * To exercise every provider/env-var branch we delete its entry from
 * `require.cache` between cases and re-require it with a fresh `process.env`.
 *
 * Runs as a child Node process under NODE_V8_COVERAGE so its coverage gets
 * merged into the monocart report by global-teardown.js.
 */

const assert = require('assert/strict');
const path = require('path');
const v8 = require('v8');

const configPath = path.resolve(__dirname, '../../../src/services/config');
const OPENAI_VALID_ENV = {
    LLM_PROVIDER: 'openai',
    OPENAI_API_KEY: 'k',
    OPENAI_MODEL: 'm',
    LLM_EMBEDDING_MODEL: 'embed',
};

function loadFresh(envOverrides) {
    delete require.cache[require.resolve(configPath)];
    const previous = {};
    const touchedKeys = [];
    // Strip provider envs that might leak from the parent process so each case
    // exercises exactly the path it intends.
    const KNOWN_KEYS = [
        'LLM_PROVIDER',
        'OLLAMA_ENDPOINT', 'OLLAMA_MODEL',
        'OPENAI_API_KEY', 'OPENAI_MODEL',
        'LLM_API_KEY', 'LLM_ENDPOINT', 'LLM_DEFAULT_MODEL', 'LLM_EMBEDDING_MODEL',
        'TLEF_BIOCBOT_PORT', 'NODE_ENV',
        'MONGODB_URI', 'QDRANT_URL', 'QDRANT_HOST', 'QDRANT_PORT',
    ];
    for (const key of KNOWN_KEYS) {
        previous[key] = process.env[key];
        delete process.env[key];
        touchedKeys.push(key);
    }
    for (const [key, value] of Object.entries(envOverrides || {})) {
        previous[key] = previous[key] !== undefined ? previous[key] : process.env[key];
        process.env[key] = value;
        if (!touchedKeys.includes(key)) touchedKeys.push(key);
    }
    const config = require(configPath);
    return {
        config,
        restore() {
            for (const key of touchedKeys) {
                if (previous[key] === undefined) delete process.env[key];
                else process.env[key] = previous[key];
            }
        },
    };
}

function withFreshConfig(envOverrides, fn) {
    const { config, restore } = loadFresh(envOverrides);
    try {
        return fn(config);
    } finally {
        restore();
    }
}

async function run() {
    // ---- getLLMConfig: ollama ----
    withFreshConfig(
        { LLM_PROVIDER: 'ollama', OLLAMA_ENDPOINT: 'http://localhost:11434', OLLAMA_MODEL: 'llama3' },
        (config) => {
            const llm = config.getLLMConfig();
            assert.deepEqual(llm, { provider: 'ollama', endpoint: 'http://localhost:11434', defaultModel: 'llama3' });
        }
    );

    // ---- getLLMConfig: openai ----
    withFreshConfig(
        {
            LLM_PROVIDER: 'openai',
            OPENAI_API_KEY: 'sk-test',
            OPENAI_MODEL: 'gpt-4.1-mini',
            LLM_EMBEDDING_MODEL: 'text-embedding-3-small',
        },
        (config) => {
            const llm = config.getLLMConfig();
            assert.equal(llm.provider, 'openai');
            assert.equal(llm.apiKey, 'sk-test');
            assert.equal(llm.defaultModel, 'gpt-4.1-mini');
        }
    );

    // ---- getLLMConfig: ubc-llm-sandbox ----
    withFreshConfig(
        {
            LLM_PROVIDER: 'ubc-llm-sandbox',
            LLM_API_KEY: 'ubc-key',
            LLM_ENDPOINT: 'https://ubc.example/api',
            LLM_DEFAULT_MODEL: 'ubc-model',
            LLM_EMBEDDING_MODEL: 'ubc-embed',
        },
        (config) => {
            const llm = config.getLLMConfig();
            assert.equal(llm.provider, 'ubc-llm-sandbox');
            assert.equal(llm.endpoint, 'https://ubc.example/api');
            assert.equal(llm.defaultModel, 'ubc-model');
        }
    );

    // ---- getLLMConfig: unsupported provider throws ----
    withFreshConfig(
        { LLM_PROVIDER: 'mystery', OPENAI_API_KEY: 'k', OPENAI_MODEL: 'm' },
        (config) => {
            // The validate step runs first; 'mystery' is not validated, so it
            // passes validation, and then the switch hits the default case.
            assert.throws(() => config.getLLMConfig(), /Unsupported LLM provider/);
        }
    );

    // ---- validateConfig: ollama missing endpoint ----
    withFreshConfig({ LLM_PROVIDER: 'ollama' }, (config) => {
        assert.throws(() => config.validateConfig(), /OLLAMA_ENDPOINT is required/);
    });

    // ---- validateConfig: ollama missing model ----
    withFreshConfig({ LLM_PROVIDER: 'ollama', OLLAMA_ENDPOINT: 'http://x' }, (config) => {
        assert.throws(() => config.validateConfig(), /OLLAMA_MODEL is required/);
    });

    // ---- validateConfig: openai missing model ----
    withFreshConfig({ LLM_PROVIDER: 'openai' }, (config) => {
        assert.throws(() => config.validateConfig(), /OPENAI_MODEL is required/);
    });

    // ---- validateConfig: openai missing embedding model ----
    withFreshConfig({ LLM_PROVIDER: 'openai', OPENAI_MODEL: 'm' }, (config) => {
        assert.throws(() => config.validateConfig(), /LLM_EMBEDDING_MODEL is required/);
    });

    // ---- validateConfig: ubc-llm-sandbox missing api key ----
    withFreshConfig({ LLM_PROVIDER: 'ubc-llm-sandbox' }, (config) => {
        assert.throws(() => config.validateConfig(), /LLM_API_KEY is required/);
    });

    // ---- validateConfig: ubc-llm-sandbox missing endpoint ----
    withFreshConfig({ LLM_PROVIDER: 'ubc-llm-sandbox', LLM_API_KEY: 'k' }, (config) => {
        assert.throws(() => config.validateConfig(), /LLM_ENDPOINT is required/);
    });

    // ---- validateConfig: ubc-llm-sandbox missing embedding model ----
    withFreshConfig(
        { LLM_PROVIDER: 'ubc-llm-sandbox', LLM_API_KEY: 'k', LLM_ENDPOINT: 'http://x' },
        (config) => {
            assert.throws(() => config.validateConfig(), /LLM_EMBEDDING_MODEL is required/);
        }
    );

    // ---- validateConfig: unknown provider passes through (no validations) ----
    withFreshConfig({ LLM_PROVIDER: 'mystery' }, (config) => {
        // No throw — none of the conditional branches match.
        config.validateConfig();
    });

    // ---- getServerConfig: defaults ----
    withFreshConfig(OPENAI_VALID_ENV, (config) => {
        const s = config.getServerConfig();
        assert.equal(s.port, 8080);
        assert.equal(s.nodeEnv, 'development');
    });

    // ---- getServerConfig: explicit values ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, TLEF_BIOCBOT_PORT: '9999', NODE_ENV: 'production' },
        (config) => {
            const s = config.getServerConfig();
            assert.equal(s.port, '9999');
            assert.equal(s.nodeEnv, 'production');
        }
    );

    // ---- getDatabaseConfig: default ----
    withFreshConfig(OPENAI_VALID_ENV, (config) => {
        const d = config.getDatabaseConfig();
        assert.equal(d.mongoUri, 'mongodb://localhost:27017/biocbot');
    });

    // ---- getDatabaseConfig: explicit ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, MONGODB_URI: 'mongodb://db/host' },
        (config) => {
            const d = config.getDatabaseConfig();
            assert.equal(d.mongoUri, 'mongodb://db/host');
        }
    );

    // ---- getVectorDBConfig: QDRANT_URL parsed correctly ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, QDRANT_URL: 'http://qdrant.example:6333' },
        (config) => {
            const v = config.getVectorDBConfig();
            assert.equal(v.host, 'qdrant.example');
            assert.equal(v.port, 6333);
        }
    );

    // ---- getVectorDBConfig: QDRANT_URL without explicit port → defaults to 6333 ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, QDRANT_URL: 'http://qdrant.example' },
        (config) => {
            const v = config.getVectorDBConfig();
            assert.equal(v.host, 'qdrant.example');
            assert.equal(v.port, 6333);
        }
    );

    // ---- getVectorDBConfig: invalid QDRANT_URL falls back to defaults ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, QDRANT_URL: 'not-a-url' },
        (config) => {
            const v = config.getVectorDBConfig();
            assert.equal(v.host, 'localhost');
            assert.equal(v.port, 6333);
        }
    );

    // ---- getVectorDBConfig: no QDRANT_URL, individual envs ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, QDRANT_HOST: 'h1', QDRANT_PORT: '7000' },
        (config) => {
            const v = config.getVectorDBConfig();
            assert.equal(v.host, 'h1');
            assert.equal(v.port, 7000);
        }
    );

    // ---- getVectorDBConfig: no env at all → defaults ----
    withFreshConfig(OPENAI_VALID_ENV, (config) => {
        const v = config.getVectorDBConfig();
        assert.equal(v.host, 'localhost');
        assert.equal(v.port, 6333);
    });

    // ---- getEnvironment / isDevelopment / isProduction ----
    withFreshConfig(
        { ...OPENAI_VALID_ENV, NODE_ENV: 'development' },
        (config) => {
            assert.equal(config.getEnvironment(), 'development');
            assert.equal(config.isDevelopment(), true);
            assert.equal(config.isProduction(), false);
        }
    );
    withFreshConfig(
        { ...OPENAI_VALID_ENV, NODE_ENV: 'production' },
        (config) => {
            assert.equal(config.getEnvironment(), 'production');
            assert.equal(config.isProduction(), true);
            assert.equal(config.isDevelopment(), false);
        }
    );
    withFreshConfig(OPENAI_VALID_ENV, (config) => {
        // No NODE_ENV → defaults to development
        assert.equal(config.getEnvironment(), 'development');
    });

    // ---- ensureValidated caches isValidated after first use ----
    withFreshConfig(OPENAI_VALID_ENV, (config) => {
        config.getServerConfig();
        // second call hits the `if (!this.isValidated)` false branch
        config.getServerConfig();
    });
}

run()
    .then(() => {
        try { v8.takeCoverage(); } catch { /* coverage disabled */ }
    })
    .catch((err) => {
        console.error(err);
        try { v8.takeCoverage(); } catch { /* coverage disabled */ }
        process.exitCode = 1;
    });
