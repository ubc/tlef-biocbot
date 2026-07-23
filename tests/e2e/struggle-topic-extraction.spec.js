// @ts-check
/**
 * HTTP integration coverage for large struggle-topic extraction. The real
 * courses router is mounted while the expensive LLM and database boundaries
 * are deterministic in-memory substitutes.
 */

const { test, expect, request } = require('./fixtures/monocart');
// @ts-ignore -- this repository does not install @types/express
const express = require('express');
const coursesRouter = require('../../src/routes/courses');

/** @type {import('http').Server|null} */
let server = null;
/** @type {import('@playwright/test').APIRequestContext|null} */
let api = null;
let llmCallCount = 0;

const course = {
    courseId: 'BIOC-TOPIC-BATCHING',
    courseName: 'Topic Batching Test',
    instructorId: 'topic-instructor',
    instructors: ['topic-instructor'],
    tas: [],
    additionalMaterialSecondarySearch: false,
    status: 'active',
};

/** @param {any} query */
function matchesCourseQuery(query) {
    if (!query || query.courseId !== course.courseId) return false;
    return !(query.status && query.status.$ne === 'deleted' && course.status === 'deleted');
}

const db = {
    /** @param {string} name */
    collection(name) {
        if (name === 'courses') {
            return {
                /** @param {any} query */
                findOne: async (query) => matchesCourseQuery(query) ? course : null,
            };
        }
        if (name === 'documents') {
            return { findOne: async () => null };
        }
        throw new Error(`Unexpected collection: ${name}`);
    },
};

const llm = {
    /**
     * @param {string} prompt
     * @param {{ systemPrompt?: string }} options
     */
    async sendMessage(prompt, options = {}) {
        llmCallCount += 1;
        if (String(options.systemPrompt || '').includes('consolidate')) {
            return {
                content: '{"topics":["Stoichiometry","Acid-Base Chemistry","Chemical Equilibrium","Thermochemistry","Atomic Structure","Chemical Bonding","Solutions","Electrochemistry"]}',
            };
        }
        if (String(prompt).includes('Slide 1')) {
            return {
                content: '{"topics":["Stoichiometry","Acid-Base Chemistry","Chemical Equilibrium","Thermochemistry"]}',
            };
        }
        return {
            content: '{"topics":["Atomic Structure","Chemical Bonding","Solutions","Electrochemistry"]}',
        };
    },
};

test.beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.locals.db = db;
    app.locals.llmRegistry = {
        forCourse: async () => ({ llm }),
    };
    app.use((
        /** @type {any} */ req,
        /** @type {any} */ _res,
        /** @type {any} */ next
    ) => {
        req.user = { userId: 'topic-instructor', role: 'instructor' };
        next();
    });
    app.use('/api/courses', coursesRouter);

    const startedServer = await /** @type {Promise<import('http').Server>} */ (new Promise((resolve, reject) => {
        const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
        listener.on('error', reject);
    }));
    server = startedServer;
    const address = startedServer.address();
    if (!address || typeof address === 'string') {
        throw new Error('Topic extraction test server did not bind to a TCP port');
    }
    api = await request.newContext({ baseURL: `http://127.0.0.1:${address.port}` });
});

test.afterAll(async () => {
    if (api) await api.dispose();
    const runningServer = server;
    if (runningServer) {
        await new Promise((resolve, reject) => {
            runningServer.close(error => error ? reject(error) : resolve(undefined));
        });
    }
});

test.beforeEach(() => {
    llmCallCount = 0;
});

test('retains general chemistry topics when batching and consolidating large content', async () => {
    if (!api) throw new Error('Topic extraction API context is not initialized');
    const content = [
        `Slide 1\n${'Stoichiometry, acid-base chemistry, chemical equilibrium, and thermochemistry. '.repeat(120)}`,
        `Slide 2\n${'Atomic structure, chemical bonding, solutions, and electrochemistry. '.repeat(130)}`,
    ].join('\n\n');

    const res = await api.post('/api/courses/BIOC-TOPIC-BATCHING/extract-topics', {
        data: { content, maxTopics: 8 },
        failOnStatusCode: false,
    });

    expect(res.ok()).toBeTruthy();
    expect(await res.json()).toMatchObject({
        success: true,
        data: {
            courseId: 'BIOC-TOPIC-BATCHING',
            topics: [
                'Stoichiometry',
                'Acid-Base Chemistry',
                'Chemical Equilibrium',
                'Thermochemistry',
                'Atomic Structure',
                'Chemical Bonding',
                'Solutions',
                'Electrochemistry',
            ],
        },
    });
    expect(llmCallCount).toBe(3);
});
