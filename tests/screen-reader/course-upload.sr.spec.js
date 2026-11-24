// @ts-check
/**
 * What VoiceOver actually says on the instructor Course Upload page, checked
 * against the findings in ubc/tlef-biocbot#724.
 *
 * tests/a11y/issue-724-course-upload.a11y.spec.js checks each finding against
 * the accessibility tree Chromium computes. These tests listen to a real screen
 * reader instead: VoiceOver moves through the page the way a user would (Tab,
 * the heading key, Space) and each check asserts on what it said.
 *
 * 56 of the 64 findings can be checked this way. The other 8 (6, 8, 9, 10, 11,
 * 25, 27 and 29) are about contrast, target size and visible labels, which a
 * screen reader cannot perceive; the Chromium spec covers those.
 *
 * Each test restarts VoiceOver, so checks are grouped by part of the page and
 * a test's title lists the findings it covers. Checks are soft: one test
 * reports every finding it covers, not just the first that fails. Each test
 * writes what VoiceOver said, and the result of every check, to
 * a11y-results/screen-reader/<project>/<test>.json.
 */
const fs = require('fs');
const path = require('path');
const { voiceOverTest: test } = require('@guidepup/playwright');
const { expect } = require('@playwright/test');
const { storageStatePath } = require('../e2e/helpers/users');
const { cleanupCourses } = require('../e2e/helpers/courses-test');
const fixture = require('../a11y/helpers/course-upload-fixture');

const COURSE_ID = 'BIOC-SR-724';
// Two units share a title with numbers hidden, and file names and objectives repeat.
const DUPLICATES_COURSE_ID = 'BIOC-SR-724-DUPLICATES';
const UNITS = ['1. Cell Structure', '2. Enzymes', '3. Metabolism'];
const LOG_ROOT = path.resolve(__dirname, '../../a11y-results/screen-reader');
// An icon that should have been hidden, as VoiceOver gives it: the glyph itself or its spoken name.
const SPOKEN_SYMBOL = /[×✕▼▶▲◀←→↑↓+]|triangle|multiplication|\btimes\b|\bplus\b|\barrow\b/i;

/** @typedef {import('@guidepup/playwright').VoiceOverPlaywright} VoiceOver */
/** @typedef {import('@playwright/test').Page} Page */
/** @typedef {import('@playwright/test').Locator} Locator */

test.use({ storageState: storageStatePath('instructor') });

// Re-seeded before every test: some tests reorder, publish or remove things.
test.beforeEach(async () => {
    await fixture.seedCourseUploadCourse(COURSE_ID, { courseName: 'Screen Reader 724 Course', docPrefix: 'a11ysr' });
});

test.beforeAll(async () => {
    await fixture.seedDuplicateTitlesCourse(DUPLICATES_COURSE_ID, { docPrefix: 'a11ysrdup' });
});

test.afterAll(async () => {
    await cleanupCourses([COURSE_ID, DUPLICATES_COURSE_ID]);
});

// ------------------------------------------------------------------ helpers

/** Lowercase words only, so punctuation and spacing differences do not matter. */
const norm = (text) => String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
/** Whether VoiceOver's phrase contains all of `text`. */
const says = (phrase, text) => !!norm(text) && norm(phrase).includes(norm(text));
/** "list 3 items", as VoiceOver says it on entering a list. */
const listOf = (count) => new RegExp(`\\blist,? ${count} items?\\b`, 'i');

/**
 * The name a control should be read out with, worked out the way the browser
 * does for these controls: the text inside it (or inside its <label>),
 * including visually hidden text, leaving out anything marked aria-hidden.
 * @param {Locator} locator
 */
const nameOf = (locator) => locator.evaluate((el) => {
    const text = (node) => {
        if (node.nodeType === Node.TEXT_NODE) return node.textContent;
        if (node.nodeType !== Node.ELEMENT_NODE) return '';
        if (node.getAttribute('aria-hidden') === 'true' || /^(SCRIPT|STYLE)$/.test(node.tagName)) return '';
        return [...node.childNodes].map(text).join('');
    };
    const field = /^(INPUT|SELECT|TEXTAREA)$/.test(el.tagName);
    const source = field && el.labels && el.labels.length ? el.labels[0] : el;
    return text(source).replace(/\s+/g, ' ').trim();
});

/** @param {Locator} locator */
const isFocused = (locator) => locator.evaluate((el) => document.activeElement === el).catch(() => false);

/**
 * Per-test record of what was heard and what each check concluded.
 * @param {number[]} findings
 */
function createRecord(findings) {
    /** @type {{ findings: number[], checks: any[], heard: Record<string, any>, warnings: string[], error?: string }} */
    const record = { findings, checks: [], heard: {}, warnings: [] };
    return {
        record,
        heard: record.heard,
        warn: (message) => record.warnings.push(message),
        /** One check of one finding. Soft: a failure is reported at the end of the test. */
        check(finding, what, pass, detail = {}) {
            record.checks.push({ finding, what, pass: !!pass, detail });
            expect.soft(!!pass, `#${finding} ${what}\n${JSON.stringify(detail, null, 2)}`).toBe(true);
        },
    };
}

/**
 * Move keyboard focus onto `target` with a real Tab key press, so VoiceOver
 * announces it the way it does for a keyboard user, and return what it said.
 * Focus is first put on the target by script and moved back one stop, because
 * tabbing to it from the top of the page would take dozens of presses.
 *
 * Links are reached with Option+Tab: Safari and WebKit leave them out of the
 * plain Tab order by default. VoiceOver's last phrase sometimes reads back
 * empty (the control already had focus, or earlier speech was still going),
 * so an empty phrase is tried again rather than taken as silence.
 * @param {VoiceOver} voiceOver @param {Locator} target @param {ReturnType<typeof createRecord>} rec
 */
async function tabTo(voiceOver, target, rec) {
    const isLink = await target.evaluate((el) => el.tagName === 'A');
    const [back, forward] = isLink ? ['Option+Shift+Tab', 'Option+Tab'] : ['Shift+Tab', 'Tab'];
    await target.scrollIntoViewIfNeeded().catch(() => {});
    for (let attempt = 1; attempt <= 3; attempt += 1) {
        await target.focus();
        await new Promise((resolve) => setTimeout(resolve, 250));
        await voiceOver.press(back, { capture: false });
        await voiceOver.press(forward);
        const phrase = await voiceOver.lastSpokenPhrase();
        if (!(await isFocused(target))) rec.warn(`${forward} did not land back on ${await nameOf(target)} (attempt ${attempt})`);
        if (phrase) return phrase;
        rec.warn(`VoiceOver's phrase read back empty on ${await nameOf(target)} (attempt ${attempt})`);
    }
    return '';
}

/**
 * Collect every distinct phrase VoiceOver speaks during the next `ms`. Speech
 * that follows an action (a live region message, focus moving after a
 * re-render) arrives after the key press itself has been captured.
 * @param {VoiceOver} voiceOver @param {number} ms
 */
async function listen(voiceOver, ms) {
    const heard = [];
    const end = Date.now() + ms;
    while (Date.now() < end) {
        const phrase = await voiceOver.lastSpokenPhrase();
        if (phrase && phrase !== heard[heard.length - 1]) heard.push(phrase);
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    return heard;
}

/** Press a key and return everything VoiceOver said because of it. @param {VoiceOver} voiceOver */
async function pressAndListen(voiceOver, key, ms = 2500) {
    await voiceOver.clearSpokenPhraseLog();
    await voiceOver.press(key, { capture: true });
    const heard = [...(await voiceOver.spokenPhraseLog()), ...(await listen(voiceOver, ms))];
    return heard.filter((phrase, i) => phrase && heard.indexOf(phrase) === i);
}

/**
 * Tab to every control in `locator` and check that VoiceOver reads each one's
 * full name, that the names tell the copies apart, and that no hidden icon is
 * read out.
 * @param {VoiceOver} voiceOver @param {ReturnType<typeof createRecord>} rec
 * @param {number} finding @param {string} what @param {Locator} locator
 * @param {{ mustSay?: RegExp, min?: number }} [options]
 */
async function checkRepeated(voiceOver, rec, finding, what, locator, { mustSay, min = 2 } = {}) {
    const items = [];
    for (const control of await locator.all()) {
        const name = await nameOf(control);
        items.push({ name, spoken: await tabTo(voiceOver, control, rec) });
    }
    const problems = [];
    if (items.length < min) problems.push(`expected at least ${min} controls, found ${items.length}`);
    for (const item of items) {
        if (!says(item.spoken, item.name)) problems.push(`"${item.name}" was not read in full`);
        if (mustSay && !mustSay.test(item.spoken)) problems.push(`"${item.spoken}" does not match ${mustSay}`);
        if (SPOKEN_SYMBOL.test(item.spoken)) problems.push(`an icon was read out in "${item.spoken}"`);
    }
    if (new Set(items.map((i) => norm(i.name))).size !== items.length) problems.push('two or more controls share a name');
    rec.heard[`#${finding} ${what}`] = items;
    rec.check(finding, what, problems.length === 0, { problems, items });
    return items;
}

/** Press VoiceOver's next-heading key from the top until it stops moving. @param {VoiceOver} voiceOver */
async function walkHeadings(voiceOver, max = 90) {
    const headings = [];
    for (let i = 0; i < max; i += 1) {
        await voiceOver.nextHeading();
        const phrase = await voiceOver.lastSpokenPhrase();
        if (headings.length && phrase === headings[headings.length - 1]) break; // reached the last heading
        headings.push(phrase);
    }
    return headings;
}

/** The headings VoiceOver read between one unit's heading and the next unit's. */
function unitSegment(headings, unitIndex) {
    const at = (u) => headings.findIndex((h) => /heading level 2/i.test(h) && h.includes(UNITS[u]));
    const start = at(unitIndex);
    if (start < 0) return [];
    const next = unitIndex + 1 < UNITS.length ? at(unitIndex + 1) : -1;
    return headings.slice(start + 1, next > start ? next : undefined);
}

/**
 * The first control a Tab press reaches inside a list, so entering the list
 * from outside makes VoiceOver say "list, N items".
 * @param {Locator} list
 */
async function firstControlIn(list) {
    const index = await list.evaluate((ul) => {
        const all = [...ul.querySelectorAll('button, a[href], input, select, textarea')];
        return all.findIndex((el) => !el.disabled && el.offsetParent !== null);
    });
    return list.locator('button, a[href], input, select, textarea').nth(Math.max(index, 0));
}

/**
 * Put VoiceOver at the start of the page, trying once more if VoiceOver's Item
 * Chooser did not offer "web content" the first time.
 * @param {VoiceOver} voiceOver
 */
async function enterWebContent(voiceOver) {
    try {
        await voiceOver.navigateToWebContent();
    } catch (error) {
        await voiceOver.press('Escape', { capture: false });
        await new Promise((resolve) => setTimeout(resolve, 1000));
        await voiceOver.navigateToWebContent();
    }
}

/** @param {VoiceOver} voiceOver @param {ReturnType<typeof createRecord>} rec */
async function saveTranscript(voiceOver, rec) {
    const info = test.info();
    const transcript = {
        test: info.title, project: info.project.name, ...rec.record,
        spokenPhraseLog: await voiceOver.spokenPhraseLog().catch(() => []),
    };
    const dir = path.join(LOG_ROOT, info.project.name);
    fs.mkdirSync(dir, { recursive: true });
    const slug = info.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 80);
    fs.writeFileSync(path.join(dir, `${slug}.json`), JSON.stringify(transcript, null, 2));
    await info.attach('voiceover-transcript', { body: JSON.stringify(transcript, null, 2), contentType: 'application/json' });
}

/**
 * One VoiceOver test: open the page, put VoiceOver at the start of the web
 * content, run the checks, and save the transcript whatever happens.
 * @param {number[]} findings
 * @param {string} title
 * @param {(ctx: { page: Page, voiceOver: VoiceOver, rec: ReturnType<typeof createRecord> }) => Promise<void>} body
 * @param {{ expandAll?: boolean, courseId?: string }} [options]
 */
function srTest(findings, title, body, { expandAll = true, courseId = COURSE_ID } = {}) {
    const label = findings.length ? `${findings.map((n) => `#${n}`).join(' ')} ${title}` : title;
    test(label, async ({ page, voiceOver }) => {
        const rec = createRecord(findings);
        try {
            await fixture.openCourseUpload(page, courseId, { expandAll: false });
            if (expandAll) {
                // Opened by script rather than by clicking, so keyboard focus (and
                // with it VoiceOver) stays outside the page: Guidepup finds the page
                // through VoiceOver's Item Chooser, which cannot see "web content"
                // while VoiceOver is already inside it.
                await page.evaluate(() => document.querySelectorAll('.accordion-content.collapsed').forEach((content) => {
                    const toggle = content.closest('.accordion-item').querySelector('[aria-expanded]');
                    if (toggle instanceof HTMLElement) toggle.click();
                }));
                await expect(page.locator('.accordion-content.collapsed')).toHaveCount(0);
            }
            await page.evaluate(() => {
                if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
                window.scrollTo(0, 0);
            });
            await enterWebContent(voiceOver);
            await body({ page, voiceOver, rec });
        } catch (error) {
            rec.record.error = String((error && error.message) || error).split('\n').slice(0, 4).join(' ');
            throw error;
        } finally {
            await saveTranscript(voiceOver, rec);
        }
    });
}

const unit = (page, n) => page.locator('.accordion-item').nth(n);

// -------------------------------------------------------------------- tests

srTest([3, 4, 5, 12, 18], 'unit controls: names, nothing nested, no caret, a list', async ({ page, voiceOver, rec }) => {
    const triggers = [];
    for (let n = 0; n < UNITS.length; n += 1) triggers.push(await tabTo(voiceOver, unit(page, n).locator('.accordion-trigger'), rec));
    rec.heard.triggers = triggers;
    rec.check(3, 'each unit expand/collapse control is read with its unit name',
        triggers.every((spoken, n) => says(spoken, UNITS[n]) && /\bbutton\b/i.test(spoken)), { triggers });
    rec.check(4, 'the expand/collapse control is read without the controls beside it',
        triggers.every((spoken) => !/rename|move|published|delete/i.test(spoken)), { triggers });
    rec.check(18, 'the caret is not read out', triggers.every((spoken) => !SPOKEN_SYMBOL.test(spoken)), { triggers });
    rec.check(5, 'entering the units says "list, 3 items"', listOf(3).test(triggers[0]), { first: triggers[0] });
    await checkRepeated(voiceOver, rec, 12, '"Rename unit" controls', page.locator('.unit-rename-btn'), { mustSay: /rename unit/i, min: 3 });
});

srTest([13, 30, 51, 52, 59], 'headings: units, course materials, study deck, card names', async ({ voiceOver, rec }) => {
    const headings = await walkHeadings(voiceOver);
    rec.heard.headings = headings;
    for (const name of UNITS) {
        const spoken = headings.find((h) => h.includes(name) && /heading level 2/i.test(h));
        rec.check(13, `"${name}" is read as a level 2 heading`, !!spoken, { spoken: spoken || null });
    }
    const first = unitSegment(headings, 0);
    const materialsAt = first.findIndex((h) => /heading level 3/i.test(h) && /course materials/i.test(h));
    const materials = [];
    for (let i = materialsAt + 1; materialsAt >= 0 && i < first.length && !/heading level [123]\b/i.test(first[i]); i += 1) materials.push(first[i]);
    rec.check(30, 'headings inside Course Materials are read as level 4, under the level 3 section heading',
        materialsAt >= 0 && materials.length > 0 && materials.every((h) => /heading level 4/i.test(h)), { section: first[materialsAt] || null, materials });
    const deck = headings.filter((h) => /instructor-curated study deck/i.test(h));
    rec.check(51, '"Instructor-curated study deck" is read as a heading', deck.length > 0 && deck.every((h) => /heading level 4/i.test(h)), { deck });
    const draftCards = first.filter((h) => /heading level 6/i.test(h) && /\bcard [1-3]\b/i.test(h));
    rec.check(52, 'draft card names in unit 1 are read as headings', draftCards.length === 3, { draftCards });
    const publishedCards = unitSegment(headings, 2).filter((h) => /heading level 6/i.test(h) && /\bcard [12]\b/i.test(h));
    rec.check(59, 'published card names in unit 3 are read as headings', publishedCards.length === 2, { publishedCards });
});

// Not in #724: found by the first VoiceOver run. Units 2 and 3 start collapsed,
// so the heading key should go from one unit name straight to the next. The
// fast version of this check is tests/a11y/course-upload-collapsed-units.a11y.spec.js.
srTest([], 'the heading key skips the content of a collapsed unit (not in #724)', async ({ page, voiceOver, rec }) => {
    await expect(unit(page, 1).locator('.accordion-trigger')).toHaveAttribute('aria-expanded', 'false');
    const headings = await walkHeadings(voiceOver);
    rec.heard.headings = headings;
    const at = headings.findIndex((h) => h.includes(UNITS[1]) && /heading level 2/i.test(h));
    const next = at >= 0 ? headings[at + 1] : null;
    rec.check(0, 'the next heading after collapsed unit 2 is unit 3', at >= 0 && says(next, UNITS[2]), { unit2: headings[at] || null, next });
}, { expandAll: false });

srTest([19, 20, 21], 'section and unit show/hide controls: names and state', async ({ page, voiceOver, rec }) => {
    await checkRepeated(voiceOver, rec, 19, 'section show/hide controls in unit 1', unit(page, 0).locator('.unit-section .toggle-section'), { min: 4 });
    const spoken = rec.heard['#19 section show/hide controls in unit 1'].map((i) => i.spoken);
    rec.check(20, 'the section carets are not read out', spoken.every((s) => !SPOKEN_SYMBOL.test(s)), { spoken });

    const section = unit(page, 0).locator('.unit-section .toggle-section').first();
    const before = await tabTo(voiceOver, section, rec);
    const onToggle = await pressAndListen(voiceOver, 'Space', 1200);
    const after = await tabTo(voiceOver, section, rec);
    rec.check(21, 'a section control says "expanded", then "collapsed" once used',
        /\bexpanded\b/i.test(before) && [...onToggle, after].some((h) => /\bcollapsed\b/i.test(h)), { before, onToggle, after });

    // The unit's own control (finding 3 covers its name; this is its state).
    const trigger = unit(page, 0).locator('.accordion-trigger');
    const unitBefore = await tabTo(voiceOver, trigger, rec);
    const unitOnToggle = await pressAndListen(voiceOver, 'Space', 1200);
    const unitAfter = await tabTo(voiceOver, trigger, rec);
    rec.heard.unitState = { unitBefore, unitOnToggle, unitAfter };
    rec.check(21, 'the unit control says "expanded", then "collapsed" once used',
        /\bexpanded\b/i.test(unitBefore) && [...unitOnToggle, unitAfter].some((h) => /\bcollapsed\b/i.test(h)), { unitBefore, unitOnToggle, unitAfter });
});

srTest([22, 23, 24, 26, 28], 'learning objectives', async ({ page, voiceOver, rec }) => {
    const firstRemove = await tabTo(voiceOver, unit(page, 0).locator('.objectives-list .remove-objective').first(), rec);
    rec.check(22, 'entering unit 1\'s objectives says "list, 3 items"', listOf(3).test(firstRemove), { firstRemove });
    const removes = await checkRepeated(voiceOver, rec, 23, '"remove objective" controls', page.locator('.objectives-list .remove-objective'), { mustSay: /remove/i, min: 3 });
    rec.check(24, 'the remove icon is not read out', removes.every((i) => !SPOKEN_SYMBOL.test(i.spoken)), { spoken: removes.map((i) => i.spoken) });
    await checkRepeated(voiceOver, rec, 26, 'new learning objective fields', page.locator('.objective-input'), { min: 3 });
    await checkRepeated(voiceOver, rec, 28, '"add objective" controls', page.locator('.add-objective-btn-inline'), { mustSay: /add objective/i, min: 3 });
});

srTest([31, 32, 33, 34, 35, 36], 'course materials', async ({ page, voiceOver, rec }) => {
    const list = unit(page, 0).locator('.course-materials-section .materials-list').first();
    const items = await list.locator(':scope > li').count();
    const entering = await tabTo(voiceOver, await firstControlIn(list), rec);
    rec.check(31, `entering unit 1's materials says "list, ${items} items"`, items > 0 && listOf(items).test(entering), { items, entering });
    await checkRepeated(voiceOver, rec, 32, '"View" controls', page.locator('.action-button.view'), { mustSay: /\bview\b/i, min: 4 });
    await checkRepeated(voiceOver, rec, 33, '"Delete" controls', page.locator('.action-button.delete'), { mustSay: /\bdelete\b/i, min: 4 });
    await checkRepeated(voiceOver, rec, 34, '"Add Lecture Notes" controls', page.locator('.add-content-btn.lecture-notes'), { mustSay: /add lecture notes/i, min: 3 });
    await checkRepeated(voiceOver, rec, 35, '"Add Practice Questions/Tutorial" controls', page.locator('.add-content-btn.practice-quiz'), { mustSay: /add practice questions/i, min: 3 });
    await checkRepeated(voiceOver, rec, 36, '"Add Additional Material" controls', page.locator('.add-content-btn.additional-material'), { mustSay: /add additional material/i, min: 3 });
});

srTest([37, 38, 39, 40, 41, 42, 43, 44], 'upload dialogs: focus after choosing a method, Back controls', async ({ page, voiceOver, rec }) => {
    const dialogs = /** @type {const} */ ([
        { opener: 'lecture-notes', title: 'Upload Lecture Notes', file: 37, paste: 38, backName: 41, backIcon: 42 },
        { opener: 'practice-quiz', title: 'Upload Practice Questions/Tutorial', file: 39, paste: 40, backName: 43, backIcon: 44 },
    ]);
    for (const d of dialogs) {
        await tabTo(voiceOver, unit(page, 0).locator(`.add-content-btn.${d.opener}`), rec);
        rec.heard[`${d.title}: opening`] = await pressAndListen(voiceOver, 'Space', 1500);
        await expect(page.locator('#upload-modal')).toBeVisible();
        await expect(page.locator('#modal-title')).toHaveText(d.title);
        const methods = page.locator('#upload-method-selection .method-btn');
        const backs = [];

        for (const [method, target, finding, label] of /** @type {const} */ ([
            [0, '#file-upload-section .upload-file-btn', d.file, 'Upload a file'],
            [1, '#material-name', d.paste, 'Paste content directly'],
        ])) {
            await tabTo(voiceOver, methods.nth(method), rec);
            const heard = await pressAndListen(voiceOver, 'Space', 1500);
            const next = page.locator(target);
            const expected = await nameOf(next);
            const focused = await isFocused(next);
            rec.check(finding, `"${label}" in "${d.title}" moves focus on, and VoiceOver reads where it went`,
                focused && heard.some((h) => says(h, expected)), { expected, focused, heard });

            const back = page.locator(method === 0 ? '#file-upload-section .btn-text-only' : '#text-input-section .btn-text-only');
            const spoken = await tabTo(voiceOver, back, rec);
            backs.push({ name: await nameOf(back), spoken });
            // Back returns to the method chooser, ready for the next one.
            rec.heard[`${d.title}: after Back from "${label}"`] = await pressAndListen(voiceOver, 'Space', 1200);
        }
        rec.check(d.backName, `the Back controls in "${d.title}" are read as just "Back"`,
            backs.every((b) => norm(b.name) === 'back' && /\bback\b/i.test(b.spoken)), { backs });
        rec.check(d.backIcon, `the Back arrows in "${d.title}" are not read out`, backs.every((b) => !SPOKEN_SYMBOL.test(b.spoken)), { backs });

        await voiceOver.press('Escape', { capture: false });
        if (await page.locator('#upload-modal').isVisible()) await page.locator('#upload-modal .modal-close').first().click();
        await expect(page.locator('#upload-modal')).toBeHidden();
    }
});

srTest([1, 2, 7], 'Canvas and Moodle launchers, and the links in "Import from Moodle"', async ({ page, voiceOver, rec }) => {
    for (const [finding, provider, label] of /** @type {const} */ ([[1, 'canvas', 'Canvas'], [2, 'moodle', 'Moodle']])) {
        const chip = page.locator(`.lms-import-chip[data-lms-provider="${provider}"]`);
        const spoken = await tabTo(voiceOver, chip, rec);
        rec.check(finding, `the ${label} launcher says what it does, which LMS, and that it is not connected`,
            /import/i.test(spoken) && new RegExp(label, 'i').test(spoken) && /not connected/i.test(spoken), { name: await nameOf(chip), spoken });
    }
    // The Moodle launcher is focused now: open its dialog from the keyboard.
    rec.heard.openingMoodle = await pressAndListen(voiceOver, 'Space', 1500);
    await expect(page.locator('#lms-import-modal')).toHaveClass(/show/);
    await expect(page.locator('#lms-token-url')).toBeVisible();
    await checkRepeated(voiceOver, rec, 7, 'links in "Import from Moodle"', page.locator('#lms-import-modal a.lms-token-link'), { mustSay: /\blink\b/i, min: 2 });
    await voiceOver.press('Escape', { capture: false });
});

srTest([45, 46, 47, 53, 54, 55, 57, 58, 60, 61, 62], 'flashcards: controls repeated per unit and per card, card lists', async ({ page, voiceOver, rec }) => {
    await checkRepeated(voiceOver, rec, 45, '"Cards" fields', page.locator('select[id^="flashcard-count-"]'), { mustSay: /\bcards\b/i, min: 3 });
    await checkRepeated(voiceOver, rec, 46, '"Chemistry notation" checkboxes', page.locator('input[id^="flashcard-chemistry-"]'), { mustSay: /chemistry notation/i, min: 3 });
    await checkRepeated(voiceOver, rec, 47, '"Generate Draft" controls', page.locator('.flashcard-generate-btn'), { mustSay: /generate draft/i, min: 3 });

    const draft = unit(page, 0).locator('.flashcard-editor-list');
    const enteringDraft = await tabTo(voiceOver, await firstControlIn(draft), rec);
    rec.check(57, 'entering unit 1\'s draft cards says "list, 3 items"', listOf(3).test(enteringDraft), { enteringDraft });
    const published = unit(page, 2).locator('.flashcard-editor-list');
    const enteringPublished = await tabTo(voiceOver, await firstControlIn(published), rec);
    rec.check(58, 'entering unit 3\'s published cards says "list, 2 items"', listOf(2).test(enteringPublished), { enteringPublished });

    await checkRepeated(voiceOver, rec, 53, 'flashcard "Remove" controls', page.locator('.flashcard-remove-btn'), { mustSay: /remove card/i, min: 6 });
    await checkRepeated(voiceOver, rec, 54, '"Front" fields', page.locator('.flashcard-front-input'), { mustSay: /\bfront\b/i, min: 8 });
    await checkRepeated(voiceOver, rec, 55, '"Back" fields', page.locator('.flashcard-back-input'), { mustSay: /\bback\b/i, min: 8 });
    await checkRepeated(voiceOver, rec, 60, '"Add Card" controls', page.locator('.flashcard-add-btn'), { mustSay: /add card/i, min: 2 });
    await checkRepeated(voiceOver, rec, 61, '"Save Draft" controls', page.locator('.flashcard-save-btn'), { mustSay: /save draft/i, min: 2 });
    await checkRepeated(voiceOver, rec, 62, '"Publish to Students" controls', page.locator('.flashcard-publish-btn'), { mustSay: /publish to students/i, min: 2 });
});

srTest([63, 64], 'assessment questions', async ({ page, voiceOver, rec }) => {
    await checkRepeated(voiceOver, rec, 63, 'protégé threshold fields', page.locator('input[id^="pass-threshold-"]'), { mustSay: /correct answers/i, min: 3 });
    await checkRepeated(voiceOver, rec, 64, '"Add Question" controls', page.locator('.add-question-btn'), { mustSay: /add question/i, min: 3 });
});

srTest([14, 56], 'focus after removing a card and reordering a unit', async ({ page, voiceOver, rec }) => {
    const active = () => page.evaluate(() => {
        const el = document.activeElement;
        return { className: el ? String(el.className) : null, name: el ? (el.textContent || '').replace(/\s+/g, ' ').trim() : null };
    });

    // Remove first: unit numbers are positional, so the move below renumbers the units.
    await tabTo(voiceOver, unit(page, 0).locator('.flashcard-remove-btn').first(), rec);
    const afterRemove = await pressAndListen(voiceOver, 'Space', 3000);
    const removeActive = await active();
    rec.check(56, 'after removing a card, focus moves to the next Remove control and VoiceOver reads it',
        /flashcard-remove-btn/.test(removeActive.className || '') && afterRemove.some((h) => /remove card/i.test(h)), { removeActive, afterRemove });

    await tabTo(voiceOver, unit(page, 0).locator('.unit-move-btn').nth(1), rec);
    const afterMove = await pressAndListen(voiceOver, 'Space', 3000);
    const moveActive = await active();
    // After the move, unit 1 is shown as "2. Cell Structure".
    rec.check(14, 'after "Move down", focus stays on a move control and VoiceOver reads it',
        /unit-move-btn/.test(moveActive.className || '') && afterMove.some((h) => /\bmove\b/i.test(h) && says(h, 'Cell Structure')), { moveActive, afterMove });
});

srTest([15, 16, 17, 48, 49, 50], 'status messages: what is read, and their Dismiss controls', async ({ page, voiceOver, rec }) => {
    /**
     * A message's Dismiss control, if it has one, must be reachable with Tab
     * and still be there after 7 seconds. A message without one passes both.
     */
    async function messageControls(reachFinding, timerFinding, label, toast) {
        const close = toast.locator('.notification-close');
        if ((await close.count()) === 0) {
            rec.check(reachFinding, `${label}: has no control, so there is nothing to reach`, true, {});
            rec.check(timerFinding, `${label}: has no control, so none is taken away`, true, {});
            return;
        }
        const first = await tabTo(voiceOver, close.first(), rec);
        rec.check(reachFinding, `${label}: its Dismiss control can be reached with Tab and is read out`, /dismiss/i.test(first), { first });
        await page.waitForTimeout(7000);
        const still = await close.first().isVisible().catch(() => false);
        const later = still ? await tabTo(voiceOver, close.first(), rec) : null;
        rec.check(timerFinding, `${label}: its Dismiss control is still there after 7 seconds`, still && /dismiss/i.test(later || ''), { still, later });
    }

    // Publish switch (finding 15, and 16/17 for its message).
    const toggle = page.locator('.publish-toggle input').nth(1);
    const before = await tabTo(voiceOver, toggle, rec);
    const published = await pressAndListen(voiceOver, 'Space', 6000);
    const message = published.find((h) => /enzymes is now published/i.test(h));
    rec.heard.publish = { before, published };
    rec.check(15, 'the publish message is read on its own, naming the unit, without "Dismiss"',
        !!message && !/dismiss/i.test(message), { before, published });
    await messageControls(16, 17, 'publish message', page.locator('.notification').filter({ hasText: /published/i }).last());

    // An error message always carries a Dismiss control (findings 16 and 17).
    const error = await (async () => {
        await voiceOver.clearSpokenPhraseLog();
        await page.evaluate(() => /** @type {any} */ (window).showNotification('Could not save the unit.', 'error'));
        return listen(voiceOver, 5000);
    })();
    rec.heard.errorMessage = error;
    await messageControls(16, 17, 'error message', page.locator('.notification.error').last());

    // Generate Draft (findings 48 to 50).
    await tabTo(voiceOver, unit(page, 0).locator('.flashcard-generate-btn'), rec);
    const generated = await pressAndListen(voiceOver, 'Space', 6000);
    const draftMessage = generated.find((h) => /generated/i.test(h));
    rec.heard.generate = generated;
    rec.check(48, 'the "Generate Draft" message is read on its own, naming the unit, without "Dismiss"',
        !!draftMessage && says(draftMessage, 'Cell Structure') && !/dismiss/i.test(draftMessage), { generated });
    await messageControls(49, 50, '"Generate Draft" message', page.locator('.notification').filter({ hasText: /generated/i }).last());
});

// Ivan's re-test of 724: titles do not have to be unique. Units 1 and 2 are
// both "Cell Structure" with their numbers hidden, "lecture.pdf" is uploaded
// twice to unit 1 and once to unit 2, and "Explain osmosis" repeats. Each copy
// of a repeated control must still sound different.
srTest([3, 12, 23, 32, 54, 64], 'repeated titles: each copy of a control still sounds different', async ({ page, voiceOver, rec }) => {
    await checkRepeated(voiceOver, rec, 3, 'unit expand/collapse controls when two units share a title', page.locator('.accordion-trigger'), { min: 3 });
    await checkRepeated(voiceOver, rec, 12, '"Rename unit" controls when two units share a title', page.locator('.unit-rename-btn'), { mustSay: /rename unit/i, min: 3 });
    await checkRepeated(voiceOver, rec, 23, '"remove objective" controls when an objective repeats', page.locator('.objectives-list .remove-objective'), { mustSay: /remove objective/i, min: 5 });
    await checkRepeated(voiceOver, rec, 32, '"View" controls when a file name repeats', page.locator('.action-button.view'), { mustSay: /\bview\b/i, min: 3 });
    await checkRepeated(voiceOver, rec, 54, '"Front" fields when two units share a title', page.locator('.flashcard-front-input'), { mustSay: /\bfront\b/i, min: 8 });
    await checkRepeated(voiceOver, rec, 64, '"Add Question" controls when two units share a title', page.locator('.add-question-btn'), { mustSay: /add question/i, min: 3 });
}, { courseId: DUPLICATES_COURSE_ID });
