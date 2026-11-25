/**
 * src/services/gamification.js: BiocBot on the gamification toolkit. Each test
 * makes a fresh publisher with BiocBot's real dictionary, starts gamification
 * on it with the toolkit's in-memory store (so no MongoDB), publishes the way
 * BiocBot's routes do, and checks what was counted and announced.
 */
const eventsService = require('../../../src/services/events');
const gamificationService = require('../../../src/services/gamification');

const installed = eventsService.loadToolkit() !== null && gamificationService.loadGamificationToolkit() !== null;
const describeWithToolkit = installed ? describe : describe.skip;

const COURSE = 'C1';
const STUDENT = 'user_5f1c';

const FIRST_CHAT = Object.freeze({
    rule: {
        id: 'first-chat',
        kind: 'badge',
        badge: { id: 'first-chat', name: 'First chat', icon: 'star' },
        when: { event: 'chat.session.started' },
        count: { atLeast: 1 }
    }
});

/** Lets the listener, which records asynchronously, finish. */
const settled = () => new Promise(resolve => setTimeout(resolve, 10));

describeWithToolkit('startGamification', () => {
    let events;
    let started;
    let announced;
    let logger;

    beforeEach(async () => {
        const toolkit = eventsService.loadToolkit();
        events = toolkit.events.createEvents({
            bus: toolkit.core.createEventBus(),
            dictionary: eventsService.buildDictionary(toolkit),
            server: 'test'
        });
        logger = { log: jest.fn(), error: jest.fn() };
        const store = gamificationService.loadGamificationToolkit().core.createMemoryStore();
        started = gamificationService.startGamification({ events, store, logger });
        await started.gamification.publish(COURSE, FIRST_CHAT);
        announced = [];
        events.subscribe('gamification.*', event => {
            announced.push(event);
        });
    });

    afterEach(() => started.stop());

    function startChat(extra = {}) {
        const result = events.publish('chat.session.started', {
            user: STUDENT,
            course: COURSE,
            session: 'chat-1',
            data: { unit: 'Unit 1' },
            ...extra
        });
        expect(result.ok).toBe(true);
        return result.event;
    }

    test('a chat about a unit earns the badge, which is announced on the bus', async () => {
        const chat = startChat();
        await settled();

        expect(announced).toHaveLength(1);
        expect(announced[0]).toMatchObject({
            type: 'gamification.badge.earned',
            user: STUDENT,
            course: COURSE,
            data: { rule: 'first-chat', cause: chat.id, badge: 'first-chat', name: 'First chat' }
        });
        const status = await started.gamification.status(COURSE, STUDENT);
        expect(status.badges.map(badge => badge.id)).toEqual(['first-chat']);
        expect(logger.error).not.toHaveBeenCalled();
    });

    test('a "View as Student" preview earns nothing', async () => {
        startChat({ preview: true });
        await settled();

        expect(announced).toEqual([]);
        const status = await started.gamification.status(COURSE, STUDENT);
        expect(status.badges).toEqual([]);
    });

    test('a student who hid gamification still has it counted, but nothing is announced', async () => {
        await started.gamification.setOptOut(COURSE, STUDENT, true);
        startChat();
        await settled();

        expect(announced).toEqual([]);
        const status = await started.gamification.status(COURSE, STUDENT);
        expect(status.badges.map(badge => badge.id)).toEqual(['first-chat']);
    });

    test('struggle is never counted, and no rule can use it', async () => {
        const recorded = jest.spyOn(started.gamification, 'record');
        events.publish('struggle.topic.activated', { user: STUDENT, data: { topic: 'Glycolysis' } });
        await settled();
        expect(recorded).not.toHaveBeenCalled();

        const refused = await started.gamification.publish(COURSE, {
            rule: { ...FIRST_CHAT.rule, id: 'struggle', when: { event: 'struggle.topic.activated' } }
        });
        expect(refused.ok).toBe(false);
    });

    test('is what getGamification returns until it stops', () => {
        expect(gamificationService.getGamification()).toBe(started.gamification);
        started.stop();
        expect(gamificationService.getGamification()).toBeNull();
    });
});

describeWithToolkit('BiocBot\'s catalog', () => {
    test('lists its four metrics, a chat about a unit first, and never struggle', () => {
        const toolkit = eventsService.loadToolkit();
        const catalog = gamificationService.buildCatalog(eventsService.buildDictionary(toolkit));

        expect(catalog.app).toBe('BiocBot');
        expect(catalog.metrics.map(metric => metric.event)).toEqual([
            'chat.session.started',
            'chat.mode.changed',
            'quiz.question.answered',
            'chat.message.sent'
        ]);
        const volume = catalog.metrics.filter(metric => metric.volume).map(metric => metric.event);
        expect(volume).toEqual(['quiz.question.answered', 'chat.message.sent']);
    });

    test('BiocBot\'s dictionary has gamification\'s award events, so its bus accepts them', () => {
        const dictionary = eventsService.buildDictionary(eventsService.loadToolkit());
        const types = dictionary.events.map(event => event.type);
        expect(types).toEqual(expect.arrayContaining([
            'gamification.badge.earned',
            'gamification.points.earned',
            'gamification.streak.extended',
            'gamification.progress.advanced'
        ]));
    });
});

describeWithToolkit('each course\'s switch', () => {
    const { memoryDb } = require('../helpers/memory-db');

    function setup(courseOn) {
        const toolkit = eventsService.loadToolkit();
        const events = toolkit.events.createEvents({
            bus: toolkit.core.createEventBus(),
            dictionary: eventsService.buildDictionary(toolkit),
            server: 'test'
        });
        const logger = { log: jest.fn(), error: jest.fn() };
        const store = gamificationService.loadGamificationToolkit().core.createMemoryStore();
        const started = gamificationService.startGamification({ events, store, logger, courseOn });
        return { events, started, logger };
    }

    const chatIn = (events, course) => events.publish('chat.session.started', {
        user: STUDENT, course, session: `chat-${course}`, data: { unit: 'Unit 1' }
    });

    test('counts only the courses that have gamification on', async () => {
        const { events, started } = setup(async course => course === 'ON');
        await started.gamification.publish('ON', FIRST_CHAT);
        await started.gamification.publish('OFF', FIRST_CHAT);

        chatIn(events, 'ON');
        chatIn(events, 'OFF');
        await settled();

        expect((await started.gamification.status('ON', STUDENT)).badges).toHaveLength(1);
        expect((await started.gamification.status('OFF', STUDENT)).badges).toHaveLength(0);
        started.stop();
    });

    test('counts nothing for a course whose switch cannot be read, and says so', async () => {
        const { events, started, logger } = setup(async () => { throw new Error('database down'); });
        await started.gamification.publish(COURSE, FIRST_CHAT);
        chatIn(events, COURSE);
        await settled();
        expect((await started.gamification.status(COURSE, STUDENT)).badges).toHaveLength(0);
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('Could not read whether a course counts'), 'database down');
        started.stop();
    });

    test('is off until set, and set for every reader on this server at once', async () => {
        gamificationService.forgetCourseSwitches();
        const db = memoryDb({ courses: [{ courseId: 'C9' }] });
        expect(await gamificationService.isCourseOn(db, 'C9')).toBe(false);
        expect(await gamificationService.setCourseOn(db, 'C9', true, 'user_17d0')).toBe(true);
        expect(await gamificationService.isCourseOn(db, 'C9')).toBe(true);
        expect(await gamificationService.setCourseOn(db, 'NOPE', true)).toBe(false);
        gamificationService.forgetCourseSwitches();
    });
});
