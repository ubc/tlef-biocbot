/**
 * Unit tests for src/services/config.js — the env-driven ConfigService singleton.
 *
 * Two gotchas this file handles:
 *  - It's a SINGLETON (`module.exports = new ConfigService()`), and it caches
 *    validation in `isValidated`. We reset that flag before each test so
 *    provider-specific validation re-runs against this test's env.
 *  - Everything reads process.env at call time, so we snapshot/scrub env per test.
 */
const config = require('../../../src/services/config');

const OLD_ENV = process.env;
const TOUCHED = [
    'LLM_PROVIDER', 'OPENAI_API_KEY', 'OPENAI_MODEL', 'LLM_EMBEDDING_MODEL',
    'OLLAMA_ENDPOINT', 'OLLAMA_MODEL', 'LLM_API_KEY', 'LLM_ENDPOINT', 'LLM_DEFAULT_MODEL',
    'TLEF_BIOCBOT_PORT', 'MONGODB_URI', 'QDRANT_URL', 'QDRANT_HOST', 'QDRANT_PORT', 'NODE_ENV',
];

beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
});
afterAll(() => {
    process.env = OLD_ENV;
    jest.restoreAllMocks();
});
beforeEach(() => {
    process.env = { ...OLD_ENV };
    for (const key of TOUCHED) delete process.env[key];
    config.isValidated = false; // force re-validation for this test's env
});

describe('config.getLLMConfig', () => {
    test('openai: returns provider/apiKey/defaultModel from env', () => {
        Object.assign(process.env, {
            LLM_PROVIDER: 'openai', OPENAI_MODEL: 'gpt-4.1-mini',
            LLM_EMBEDDING_MODEL: 'text-embedding-3-small', OPENAI_API_KEY: 'sk-test',
        });
        expect(config.getLLMConfig()).toEqual({
            provider: 'openai', apiKey: 'sk-test', defaultModel: 'gpt-4.1-mini',
        });
    });

    test('openai: apiKey is undefined when OPENAI_API_KEY is unset', () => {
        Object.assign(process.env, {
            LLM_PROVIDER: 'openai', OPENAI_MODEL: 'gpt-4.1-mini', LLM_EMBEDDING_MODEL: 'emb',
        });
        expect(config.getLLMConfig().apiKey).toBeUndefined();
    });

    test('ollama: returns endpoint and defaultModel', () => {
        Object.assign(process.env, {
            LLM_PROVIDER: 'ollama', OLLAMA_ENDPOINT: 'http://localhost:11434', OLLAMA_MODEL: 'llama3',
        });
        expect(config.getLLMConfig()).toEqual({
            provider: 'ollama', endpoint: 'http://localhost:11434', defaultModel: 'llama3',
        });
    });

    test('ubc-llm-sandbox: returns apiKey/endpoint/defaultModel', () => {
        Object.assign(process.env, {
            LLM_PROVIDER: 'ubc-llm-sandbox', LLM_API_KEY: 'k', LLM_ENDPOINT: 'http://ubc',
            LLM_EMBEDDING_MODEL: 'emb', LLM_DEFAULT_MODEL: 'sandbox-model',
        });
        expect(config.getLLMConfig()).toEqual({
            provider: 'ubc-llm-sandbox', apiKey: 'k', endpoint: 'http://ubc', defaultModel: 'sandbox-model',
        });
    });

    test('throws for an unsupported provider (passes validation, fails the switch)', () => {
        process.env.LLM_PROVIDER = 'gemini';
        expect(() => config.getLLMConfig()).toThrow('Unsupported LLM provider: gemini');
    });
});

describe('config.validateConfig', () => {
    test('openai requires OPENAI_MODEL and LLM_EMBEDDING_MODEL', () => {
        process.env.LLM_PROVIDER = 'openai';
        process.env.LLM_EMBEDDING_MODEL = 'emb';
        expect(() => config.validateConfig()).toThrow('OPENAI_MODEL is required for OpenAI provider');
    });

    test('ollama requires OLLAMA_ENDPOINT', () => {
        process.env.LLM_PROVIDER = 'ollama';
        expect(() => config.validateConfig()).toThrow('OLLAMA_ENDPOINT is required for Ollama provider');
    });

    test('ubc-llm-sandbox requires LLM_API_KEY', () => {
        process.env.LLM_PROVIDER = 'ubc-llm-sandbox';
        expect(() => config.validateConfig()).toThrow('LLM_API_KEY is required for UBC LLM Sandbox provider');
    });

    test('an unknown provider passes validation (no required fields enforced)', () => {
        process.env.LLM_PROVIDER = 'something-else';
        expect(() => config.validateConfig()).not.toThrow();
    });
});

describe('config.getServerConfig', () => {
    test('defaults port to 8080 and nodeEnv to development', () => {
        expect(config.getServerConfig()).toEqual({ port: 8080, nodeEnv: 'development' });
    });

    test('uses env overrides when present', () => {
        process.env.TLEF_BIOCBOT_PORT = '3000';
        process.env.NODE_ENV = 'production';
        expect(config.getServerConfig()).toEqual({ port: '3000', nodeEnv: 'production' });
    });
});

describe('config.getDatabaseConfig', () => {
    test('defaults to the local mongo uri', () => {
        expect(config.getDatabaseConfig()).toEqual({ mongoUri: 'mongodb://localhost:27017/biocbot' });
    });

    test('uses MONGODB_URI when set', () => {
        process.env.MONGODB_URI = 'mongodb://host:1234/db';
        expect(config.getDatabaseConfig()).toEqual({ mongoUri: 'mongodb://host:1234/db' });
    });
});

describe('config.getVectorDBConfig', () => {
    test('parses host/port out of QDRANT_URL', () => {
        process.env.QDRANT_URL = 'http://qhost:7000';
        expect(config.getVectorDBConfig()).toEqual({ host: 'qhost', port: 7000 });
    });

    test('defaults the port to 6333 when QDRANT_URL has none', () => {
        process.env.QDRANT_URL = 'http://qhost';
        expect(config.getVectorDBConfig()).toEqual({ host: 'qhost', port: 6333 });
    });

    test('falls back to QDRANT_HOST/PORT when QDRANT_URL is malformed', () => {
        process.env.QDRANT_URL = 'not a url';
        process.env.QDRANT_HOST = 'h2';
        process.env.QDRANT_PORT = '6334';
        expect(config.getVectorDBConfig()).toEqual({ host: 'h2', port: 6334 });
    });

    test('defaults to localhost:6333 when nothing is set', () => {
        expect(config.getVectorDBConfig()).toEqual({ host: 'localhost', port: 6333 });
    });
});

describe('config environment helpers', () => {
    test('getEnvironment defaults to development', () => {
        expect(config.getEnvironment()).toBe('development');
    });

    test('isDevelopment / isProduction track NODE_ENV', () => {
        process.env.NODE_ENV = 'development';
        expect(config.isDevelopment()).toBe(true);
        expect(config.isProduction()).toBe(false);

        process.env.NODE_ENV = 'production';
        expect(config.isDevelopment()).toBe(false);
        expect(config.isProduction()).toBe(true);
    });
});
