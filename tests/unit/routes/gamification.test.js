/**
 * /api/gamification (src/routes/gamification.js): the gamification toolkit's
 * router with BiocBot's answers to "who is asking?". Each test mounts it as
 * server.js does, on the in-memory database, behind a stand-in for Passport,
 * with BiocBot's real catalog and the toolkit's in-memory store.
 */
const express = require('express');
const request = require('supertest');
const { memoryDb } = require('../helpers/memory-db');
const eventsService = require('../../../src/services/events');
const gamificationService = require('../../../src/services/gamification');
const { buildPreviewUserId } = require('../../../src/services/previewSession');
const { createGamificationRoutes, loadRouterPackage } = require('../../../src/routes/gamification');

const installed = eventsService.loadToolkit() !== null
    && gamificationService.loadGamificationToolkit() !== null
    && loadRouterPackage() !== null;
const describeWithToolkit = installed ? describe : describe.skip;

const student = { userId: 'user_5f1c', role: 'student' };
const otherStudent = { userId: 'user_9a2b', role: 'student' };
const instructor = { userId: 'user_17d0', role: 'instructor' };
const otherInstructor = { userId: 'user_33aa', role: 'instructor' };
const ta = { userId: 'user_7e7e', role: 'ta' };
const admin = { userId: 'user_ad01', role: 'instructor', permissions: { systemAdmin: true } };
const preview = { userId: buildPreviewUserId(instructor.userId, 'C1'), role: 'student', isPreview: true };

function courses() {
    return [
        {
            courseId: 'C1',
            status: 'active',
            instructorId: instructor.userId,
            instructors: [instructor.userId],
            tas: [ta.userId],
            studentEnrollment: { [student.userId]: { enrolled: true } }
        },
        {
            courseId: 'C2',
            status: 'active',
            instructorId: otherInstructor.userId,
            instructors: [otherInstructor.userId],
            studentEnrollment: { [otherStudent.userId]: { enrolled: true } }
        },
        {
            courseId: 'C3',
            status: 'inactive',
            instructorId: instructor.userId,
            instructors: [instructor.userId],
            studentEnrollment: { [student.userId]: { enrolled: true } }
        }
    ];
}

const FIRST_CHAT = Object.freeze({
    rule: {
        id: 'first-chat',
        kind: 'badge',
        badge: { id: 'first-chat', name: 'First chat', icon: 'star' },
        when: { event: 'chat.session.started' },
        count: { atLeast: 1 }
    }
});

describeWithToolkit('/api/gamification', () => {
    let gamification;
    let logger;

    beforeEach(() => {
        const { core } = gamificationService.loadGamificationToolkit();
        const toolkit = eventsService.loadToolkit();
        const dictionary = eventsService.buildDictionary(toolkit);
        gamification = core.createGamification({
            catalog: gamificationService.buildCatalog(dictionary),
            store: core.createMemoryStore(),
            logger: { error: jest.fn() }
        });
        logger = { error: jest.fn() };
    });

    /** The routes as server.js mounts them, with `user` signed in. */
    function app(user) {
        const routes = createGamificationRoutes({ gamification, logger });
        const server = express();
        server.locals.db = memoryDb({ courses: courses() });
        server.use((req, res, next) => {
            if (user) req.user = { ...user };
            next();
        });
        server.use('/api/gamification', routes);
        return server;
    }

    const chat = (learner, course = 'C1', id = `${learner}-chat`) => gamification.record({
        id,
        learner,
        course,
        event: 'chat.session.started',
        props: { unit: 'Unit 1' }
    });

    describe('a student', () => {
        test('reads their own awards in a course they are enrolled in', async () => {
            await gamification.publish('C1', FIRST_CHAT);
            await chat(student.userId);
            await chat(otherStudent.userId);

            const res = await request(app(student)).get('/api/gamification/courses/C1/me');
            expect(res.status).toBe(200);
            expect(res.headers['cache-control']).toBe('no-store');
            expect(res.body.badges.map(badge => badge.id)).toEqual(['first-chat']);
            expect(JSON.stringify(res.body)).not.toContain(otherStudent.userId);
        });

        test('is refused in a course they are not enrolled in, or one that is switched off', async () => {
            expect((await request(app(student)).get('/api/gamification/courses/C2/me')).status).toBe(403);
            expect((await request(app(student)).get('/api/gamification/courses/C3/me')).status).toBe(403);
            expect((await request(app(student)).get('/api/gamification/courses/NOPE/me')).status).toBe(403);
        });

        test('hides gamification for themselves', async () => {
            const res = await request(app(student))
                .put('/api/gamification/courses/C1/me/opt-out')
                .send({ optedOut: true });
            expect(res.status).toBe(200);
            expect(res.body.optedOut).toBe(true);
            expect((await gamification.status('C1', student.userId)).optedOut).toBe(true);
        });

        test("can't see or change the course's rules", async () => {
            expect((await request(app(student)).get('/api/gamification/courses/C1/rules')).status).toBe(403);
            expect((await request(app(student)).post('/api/gamification/courses/C1/rules').send(FIRST_CHAT)).status).toBe(403);
            expect(await gamification.rules('C1')).toEqual([]);
        });
    });

    describe('"View as Student"', () => {
        test('sees the student view of its own course, but opting out is not saved', async () => {
            await gamification.publish('C1', FIRST_CHAT);
            const status = await request(app(preview)).get('/api/gamification/courses/C1/me');
            expect(status.status).toBe(200);
            expect(status.body.toEarn.map(badge => badge.ruleId)).toEqual(['first-chat']);

            const off = await request(app(preview)).put('/api/gamification/courses/C1/me/opt-out').send({ optedOut: true });
            expect(off.body.optedOut).toBe(true);
            expect((await gamification.status('C1', preview.userId)).optedOut).toBe(false);
        });

        test('is refused in any other course, and never edits rules', async () => {
            expect((await request(app(preview)).get('/api/gamification/courses/C2/me')).status).toBe(403);
            expect((await request(app(preview)).post('/api/gamification/courses/C1/rules').send(FIRST_CHAT)).status).toBe(403);
        });
    });

    describe('an instructor', () => {
        test("publishes, lists and removes their course's rules", async () => {
            const published = await request(app(instructor)).post('/api/gamification/courses/C1/rules').send(FIRST_CHAT);
            expect(published.status).toBe(201);
            const listed = await request(app(instructor)).get('/api/gamification/courses/C1/rules');
            expect(listed.body.rules.map(rule => rule.id)).toEqual(['first-chat']);
            expect((await request(app(instructor)).delete('/api/gamification/courses/C1/rules/first-chat')).status).toBe(200);
        });

        test("gets the builder from BiocBot's catalog, without struggle", async () => {
            const res = await request(app(instructor)).get('/api/gamification/courses/C1/config');
            expect(res.status).toBe(200);
            expect(res.body.metrics.map(metric => metric.event)).toEqual(gamificationService.METRICS);
            expect(JSON.stringify(res.body.metrics)).not.toContain('struggle');
        });

        test("can't touch another instructor's course", async () => {
            expect((await request(app(instructor)).get('/api/gamification/courses/C2/rules')).status).toBe(403);
            expect((await request(app(instructor)).post('/api/gamification/courses/C2/rules').send(FIRST_CHAT)).status).toBe(403);
            expect(await gamification.rules('C2')).toEqual([]);
        });

        test('has no awards of their own', async () => {
            expect((await request(app(instructor)).get('/api/gamification/courses/C1/me')).status).toBe(403);
        });
    });

    test("a TA sees their course's rules but can't change them", async () => {
        await gamification.publish('C1', FIRST_CHAT);
        expect((await request(app(ta)).get('/api/gamification/courses/C1/rules')).status).toBe(200);
        expect((await request(app(ta)).get('/api/gamification/courses/C1/config')).status).toBe(200);
        expect((await request(app(ta)).delete('/api/gamification/courses/C1/rules/first-chat')).status).toBe(403);
        expect((await request(app(ta)).get('/api/gamification/courses/C2/rules')).status).toBe(403);
        expect((await gamification.rules('C1')).length).toBe(1);
    });

    test('a system admin can change any course\'s rules', async () => {
        expect((await request(app(admin)).post('/api/gamification/courses/C2/rules').send(FIRST_CHAT)).status).toBe(201);
    });

    test('no route takes a student id', async () => {
        expect((await request(app(instructor)).get(`/api/gamification/courses/C1/students/${student.userId}`)).status).toBe(404);
    });
});

describe('createGamificationRoutes', () => {
    test('makes nothing without gamification, or without the server package', () => {
        expect(createGamificationRoutes({ gamification: null, toolkit: {} })).toBeNull();
        expect(createGamificationRoutes({ gamification: {}, toolkit: null })).toBeNull();
    });
});
