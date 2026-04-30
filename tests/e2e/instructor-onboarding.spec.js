// @ts-check
require('dotenv').config();
const path = require('path');
const { MongoClient } = require('mongodb');
const { test, expect, request } = require('@playwright/test');
const { TEST_USERS, loadCredentials } = require('./helpers/users');

const user = TEST_USERS.instructor_fresh;

const LECTURE_FIXTURE = path.join(__dirname, 'fixtures', 'sample-lecture.txt');
const PRACTICE_FIXTURE = path.join(__dirname, 'fixtures', 'sample-practice-quiz.txt');
const COURSE_NAME = 'BIOC E2E - Onboarding Test';
const LEARNING_OBJECTIVE = 'Identify the four main classes of biomolecules.';
const QUESTIONS = {
    trueFalse: {
        type: 'true-false',
        text: 'Water is the universal solvent in biological systems.',
        answer: 'true',
    },
    multipleChoice: {
        type: 'multiple-choice',
        text: 'Which of the following is NOT one of the four main classes of biomolecules?',
        options: { A: 'Carbohydrates', B: 'Lipids', C: 'Minerals', D: 'Nucleic acids' },
        correct: 'C',
    },
    shortAnswer: {
        type: 'short-answer',
        text: 'Name the chemical bond that links two amino acids together.',
        expected: 'Peptide bond, formed via a condensation (dehydration) reaction.',
    },
};

let password;

test.beforeAll(() => {
    password = loadCredentials().instructor_fresh;
    if (!password) {
        throw new Error(
            'No credentials.instructor_fresh found. Global-setup should have generated it.'
        );
    }
});

async function hardDeleteCoursesFor(username) {
    if (!process.env.MONGO_URI) {
        throw new Error('MONGO_URI not set; cannot clean up courses for onboarding test.');
    }
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    try {
        const db = client.db();
        const userDoc = await db.collection('users').findOne({ username });
        if (!userDoc) return;
        await db.collection('courses').deleteMany({ instructorId: userDoc.userId });
    } finally {
        await client.close();
    }
}

async function loginViaUI(page) {
    await page.goto('/');
    await page.locator('#auth-form input#username').fill(user.username);
    await page.locator('#auth-form input#password').fill(password);
    await page.locator('#auth-form button#login-btn').click();
    await page.waitForURL((url) => url.pathname !== '/' && url.pathname !== '/login', {
        timeout: 10_000,
    });
}

function findSavedQuestion(questions, questionText) {
    const question = questions.find(savedQuestion => savedQuestion.question === questionText);
    expect(question, `Expected saved question: "${questionText}"`).toBeTruthy();
    return question;
}

test.describe('instructor onboarding', () => {
    test.describe.configure({ mode: 'serial' });

    test.beforeEach(async () => {
        await hardDeleteCoursesFor(user.username);
    });

    test('completes the full onboarding flow end-to-end', async ({ page }) => {
        test.setTimeout(180_000);

        // Auto-accept any "replace existing content" confirms triggered by re-uploads.
        page.on('dialog', dialog => dialog.accept());

        await loginViaUI(page);
        await page.goto('/instructor/onboarding');

        // Step 1 — Welcome
        await expect(page.locator('#step-1.onboarding-step.active')).toBeVisible();
        await page.locator('#step-1 button.btn-primary', { hasText: 'Get Started' }).click();

        // Step 2 — Course Setup (custom course, 1 week, 1 lecture/week)
        await expect(page.locator('#step-2.onboarding-step.active')).toBeVisible();
        await page.locator('#course-select').selectOption('custom');
        await page.locator('#custom-course-name').fill(COURSE_NAME);
        await page.locator('#weeks-count').fill('1');
        await page.locator('#lectures-per-week').fill('1');
        await page.locator('#continue-btn').click();

        // Step 3 — Unit 1 Setup
        await expect(page.locator('#step-3.onboarding-step.active')).toBeVisible();

        // 3a — Learning Objectives
        await expect(page.locator('#substep-objectives.guided-substep.active')).toBeVisible();
        await page.locator('#objective-input').fill(LEARNING_OBJECTIVE);
        await page.locator('.add-objective-btn').click();
        await expect(page.locator('#objectives-list .objective-display-item')).toHaveCount(1);
        await page.locator('#substep-objectives button.btn-primary', { hasText: 'Continue to Course Materials' }).click();

        // 3b — Course Materials: upload BOTH lecture notes and practice questions
        // (the finalize step validates that both required materials have been uploaded)
        await expect(page.locator('#substep-materials.guided-substep.active')).toBeVisible();

        async function uploadRequiredMaterial(buttonIndex, statusLocator, fixturePath) {
            await page.locator('.material-item.required button.upload-btn').nth(buttonIndex).click();
            await expect(page.locator('#upload-modal')).toBeVisible();
            await page.locator('#file-input').setInputFiles(fixturePath);
            await page.locator('#upload-btn').click();

            // AI processing → topic review section appears
            await expect(page.locator('#topic-review-section')).toBeVisible({ timeout: 120_000 });
            await page.locator('#save-topics-btn').click();

            await expect(page.locator('#upload-modal')).toBeHidden({ timeout: 10_000 });
            await expect(statusLocator).not.toHaveText(/Not Uploaded/i);
        }

        await uploadRequiredMaterial(0, page.locator('#lecture-status'), LECTURE_FIXTURE);
        await uploadRequiredMaterial(1, page.locator('#practice-status'), PRACTICE_FIXTURE);

        await page.locator('#substep-materials button.btn-primary', { hasText: 'Continue to Probing Questions' }).click();

        // 3c — Assessment Questions: one of each supported type
        await expect(page.locator('#substep-questions.guided-substep.active')).toBeVisible();

        async function addQuestion(spec) {
            await page.locator('.add-question-btn').click();
            await expect(page.locator('#question-modal')).toBeVisible();

            await page.locator('#question-type').selectOption(spec.type);
            await page.locator('#question-text').fill(spec.text);

            if (spec.type === 'true-false') {
                await page.locator(`input[name="tf-answer"][value="${spec.answer}"]`).check();
            } else if (spec.type === 'multiple-choice') {
                for (const [letter, value] of Object.entries(spec.options)) {
                    await page.locator(`.mcq-input[data-option="${letter}"]`).fill(value);
                }
                await page.locator(`input[name="mcq-correct"][value="${spec.correct}"]`).check();
            } else if (spec.type === 'short-answer') {
                await page.locator('#sa-answer').fill(spec.expected);
            }

            await page.locator('#question-modal button.btn-primary', { hasText: 'Save Question' }).click();
            await expect(page.locator('#question-modal')).toBeHidden({ timeout: 10_000 });
        }

        await addQuestion(QUESTIONS.trueFalse);
        await addQuestion(QUESTIONS.multipleChoice);
        await addQuestion(QUESTIONS.shortAnswer);

        // Finalize — completeUnit1Setup() saves data then redirects to the course
        // upload page after a short notification delay, so we wait for the URL change.
        await page.locator('#substep-questions button.btn-primary', { hasText: 'Complete Unit 1 & Continue' }).click();
        await page.waitForURL(url => !url.pathname.includes('/onboarding'), { timeout: 30_000 });

        // API truth — the instructor now has exactly one course, and it's marked complete
        const apiCtx = await request.newContext({ baseURL: page.url().split('/instructor')[0] });
        await apiCtx.post('/api/auth/login', {
            data: { username: user.username, password },
        });
        const coursesRes = await apiCtx.get('/api/courses');
        expect(coursesRes.ok()).toBeTruthy();
        const { data: courses } = await coursesRes.json();
        expect(courses).toHaveLength(1);
        expect(courses[0].name).toBe(COURSE_NAME);

        const courseDetailRes = await apiCtx.get(`/api/onboarding/${courses[0].id}`);
        expect(courseDetailRes.ok()).toBeTruthy();
        const detail = await courseDetailRes.json();
        expect(detail.success).toBeTruthy();
        const course = detail.data;
        expect(course && course.isOnboardingComplete).toBe(true);
        expect(course.courseName).toBe(COURSE_NAME);
        expect(course.courseStructure).toMatchObject({
            weeks: 1,
            lecturesPerWeek: 1,
            totalUnits: 1,
        });
        expect(course.lectures).toHaveLength(1);

        const unit1 = course.lectures[0];
        expect(unit1.name).toBe('Unit 1');
        expect(unit1.learningObjectives).toContain(LEARNING_OBJECTIVE);

        expect(unit1.documents).toHaveLength(2);
        const documentTypes = unit1.documents.map(document => document.documentType).sort();
        expect(documentTypes).toEqual(['lecture-notes', 'practice-quiz']);

        expect(unit1.assessmentQuestions).toHaveLength(3);
        const savedTrueFalse = findSavedQuestion(unit1.assessmentQuestions, QUESTIONS.trueFalse.text);
        expect(savedTrueFalse.questionType).toBe('true-false');
        expect(savedTrueFalse.correctAnswer).toBe('true');

        const savedMultipleChoice = findSavedQuestion(unit1.assessmentQuestions, QUESTIONS.multipleChoice.text);
        expect(savedMultipleChoice.questionType).toBe('multiple-choice');
        expect(savedMultipleChoice.options).toEqual(QUESTIONS.multipleChoice.options);
        expect(savedMultipleChoice.correctAnswer).toBe(QUESTIONS.multipleChoice.correct);

        const savedShortAnswer = findSavedQuestion(unit1.assessmentQuestions, QUESTIONS.shortAnswer.text);
        expect(savedShortAnswer.questionType).toBe('short-answer');
        expect(savedShortAnswer.correctAnswer).toBe(QUESTIONS.shortAnswer.expected);

        const approvedTopicsRes = await apiCtx.get(`/api/courses/${courses[0].id}/approved-topics`);
        expect(approvedTopicsRes.ok()).toBeTruthy();
        const approvedTopics = await approvedTopicsRes.json();
        expect(approvedTopics.success).toBeTruthy();
        expect(approvedTopics.data.topics.length).toBeGreaterThan(0);
        expect(approvedTopics.data.topicLabels.length).toBeGreaterThan(0);
        expect(approvedTopics.data.topicLabels.every(topic => topic.trim().length > 0)).toBe(true);

        await apiCtx.dispose();
    });
});
