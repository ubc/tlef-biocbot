// @ts-check

const { test, expect } = require('./fixtures/monocart');
const { storageStatePath } = require('./helpers/users');
const { gotoOnboarding, branchCourse, INSTRUCTOR_ID } = require('./helpers/onboarding-branches');

test.use({ storageState: storageStatePath('instructor_fresh') });

test.describe('onboarding Unit 1 persistence and notification branches', () => {
    test('omits upload title when no title is passed', async ({ page }) => {
        const captures = await gotoOnboarding(page);

        const result = await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            const file = new File(['branch file'], 'branch.txt', { type: 'text/plain' });
            return testWindow.saveUnit1Document('COURSE-A', 'Unit 1', 'additional', file, instructorId);
        }, { instructorId: INSTRUCTOR_ID });

        expect(result.success).toBe(true);
        expect(captures.fileUploads).toBe(1);
    });

    test('surfaces text upload failures for long direct text content', async ({ page }) => {
        await gotoOnboarding(page, { textUploadStatus: 500 });

        await expect(page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.saveUnit1Text(
                'COURSE-A',
                'Unit 1',
                'additional',
                'x'.repeat(140),
                'Long Text',
                instructorId
            );
        }, { instructorId: INSTRUCTOR_ID })).rejects.toThrow(/Failed to save text content/);
    });

    test('returns false when document type lookup has no matching course data', async ({ page }) => {
        await gotoOnboarding(page, {
            course: branchCourse({ lectures: [] }),
        });

        const exists = await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            testWindow.getCurrentInstructorId = () => instructorId;
            return testWindow.checkDocumentTypeExists('COURSE-A', 'Unit 1', 'lecture-notes');
        }, { instructorId: INSTRUCTOR_ID });

        expect(exists).toBe(false);
    });

    test('returns true when document type exists for Unit 1', async ({ page }) => {
        await gotoOnboarding(page, {
            course: branchCourse({
                lectures: [{
                    name: 'Unit 1',
                    learningObjectives: [],
                    documents: [{ documentId: 'doc-1', documentType: 'lecture-notes' }],
                }],
            }),
        });

        const exists = await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            testWindow.getCurrentInstructorId = () => instructorId;
            return testWindow.checkDocumentTypeExists('COURSE-A', 'Unit 1', 'lecture-notes');
        }, { instructorId: INSTRUCTOR_ID });

        expect(exists).toBe(true);
    });

    test('removes prior field error before rendering a new one', async ({ page }) => {
        await gotoOnboarding(page);

        await page.evaluate(() => {
            const testWindow = /** @type {any} */ (window);
            const field = document.getElementById('custom-course-name');
            testWindow.showFieldError(field, 'First error');
            testWindow.showFieldError(field, 'Second error');
        });

        await expect(page.locator('#custom-course-section .error-message')).toHaveCount(1);
        await expect(page.locator('#custom-course-section .error-message')).toHaveText('Second error');
    });

    test('removes existing documents and lecture document references', async ({ page }) => {
        const captures = await gotoOnboarding(page, {
            course: branchCourse({
                lectures: [{
                    name: 'Unit 1',
                    documents: [
                        { documentId: 'old-a', documentType: 'lecture-notes' },
                        { documentId: 'old-b', documentType: 'lecture-notes' },
                    ],
                }],
            }),
        });

        const removed = await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.removeExistingDocumentType('COURSE-A', 'Unit 1', 'lecture-notes', instructorId);
        }, { instructorId: INSTRUCTOR_ID });

        expect(removed).toBe(true);
        expect(captures.deletedDocuments).toEqual(['old-a', 'old-b']);
        expect(captures.removedDocumentTypes[0]).toEqual(expect.objectContaining({
            documentTypes: ['lecture-notes'],
        }));
    });

    test('converts string probing question to fallback multiple-choice payload', async ({ page }) => {
        const captures = await gotoOnboarding(page);

        await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.saveUnit1AssessmentQuestion('COURSE-A', 'Unit 1', 'Why ATP?', instructorId);
        }, { instructorId: INSTRUCTOR_ID });

        expect(captures.questionSaves[0]).toEqual(expect.objectContaining({
            questionType: 'multiple-choice',
            question: 'Why ATP?',
            options: ['Option A', 'Option B', 'Option C', 'Option D'],
            correctAnswer: 0,
        }));
    });

    test('serializes multiple-choice array options and numeric correct answer', async ({ page }) => {
        const captures = await gotoOnboarding(page);

        await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.saveUnit1AssessmentQuestion('COURSE-A', 'Unit 1', {
                type: 'multiple-choice',
                question: 'Pick B',
                options: ['Alpha', 'Beta', '', 'Delta'],
                correctAnswer: 1,
            }, instructorId);
        }, { instructorId: INSTRUCTOR_ID });

        expect(captures.questionSaves[0]).toEqual(expect.objectContaining({
            options: ['Alpha', 'Beta', 'Delta'],
            correctAnswer: 1,
        }));
    });

    test('serializes true-false boolean answers and short-answer text answers', async ({ page }) => {
        const captures = await gotoOnboarding(page);

        await page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            await testWindow.saveUnit1AssessmentQuestion('COURSE-A', 'Unit 1', {
                type: 'true-false',
                question: 'ATP stores energy.',
                correctAnswer: true,
            }, instructorId);
            await testWindow.saveUnit1AssessmentQuestion('COURSE-A', 'Unit 1', {
                type: 'short-answer',
                questionText: 'Explain ATP.',
                correctAnswer: 'Energy currency.',
            }, instructorId);
        }, { instructorId: INSTRUCTOR_ID });

        expect(captures.questionSaves[0]).toEqual(expect.objectContaining({
            questionType: 'true-false',
            correctAnswer: true,
        }));
        expect(captures.questionSaves[1]).toEqual(expect.objectContaining({
            questionType: 'short-answer',
            question: 'Explain ATP.',
            correctAnswer: 'Energy currency.',
        }));
    });

    test('surfaces pass-threshold save failures', async ({ page }) => {
        await gotoOnboarding(page, { thresholdStatus: 500 });

        await expect(page.evaluate(async ({ instructorId }) => {
            const testWindow = /** @type {any} */ (window);
            return testWindow.saveUnit1PassThreshold('COURSE-A', 'Unit 1', 3, instructorId);
        }, { instructorId: INSTRUCTOR_ID })).rejects.toThrow(/Failed to save pass threshold/);
    });
});
