/**
 * Mount a route module on a bare Express app for fast, in-process route tests
 * (supertest — no real server, no real Mongo, no browser).
 *
 * Routes in this codebase read two things off the request: the DB via
 * `req.app.locals.db`, and the authenticated user via `req.user` (Passport).
 * This helper injects both, plus any extra app.locals (e.g. `llmRegistry`).
 *
 * IMPORTANT: the heavy modules a router require()s at load time (qdrantService,
 * llm, llmKeyStore, superCourseService) must be `jest.mock()`ed by the TEST FILE
 * before it require()s the router — this helper only wires per-request state.
 *
 * Usage:
 *   jest.mock('../../../src/services/llmKeyStore', () => ({ ... }));
 *   const router = require('../../../src/routes/superchats');
 *   const app = makeRouteApp(router, { db: memoryDb({...}), user: instructor });
 *   const res = await request(app).get('/');
 */
const express = require('express');
const request = require('supertest');

function makeRouteApp(router, { db = null, user = null, session = null, locals = {}, mountPath = '/' } = {}) {
    const app = express();
    app.use(express.json());
    app.locals.db = db;
    Object.assign(app.locals, locals);
    // Fake auth: stand in for Passport by attaching the provided user (if any).
    // Some routers (e.g. auth.js) also read req.session directly for the legacy
    // session-based path; inject it when the caller supplies one.
    app.use((req, res, next) => {
        if (user) req.user = user;
        if (session) req.session = session;
        next();
    });
    app.use(mountPath, router);
    return app;
}

module.exports = { makeRouteApp, request };
