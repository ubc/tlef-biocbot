// @ts-check

const { expect } = require('../fixtures/monocart');

const INSTRUCTOR_ID = 'e2e_onboarding_branch_instructor';
const COURSE_ID = 'ONBOARDING-BRANCH-COURSE';

function branchCourse(overrides = {}) {
    return {
        courseId: COURSE_ID,
        courseName: 'Onboarding Branch Biology',
        courseCode: 'BRSTU',
        instructorCourseCode: 'BRINST',
        instructorId: INSTRUCTOR_ID,
        instructors: [INSTRUCTOR_ID],
        status: 'active',
        isOnboardingComplete: false,
        approvedStruggleTopics: [],
        lectures: [{
            name: 'Unit 1',
            learningObjectives: [],
            documents: [],
            assessmentQuestions: [],
            isPublished: false,
            passThreshold: 2,
        }],
        courseStructure: { weeks: 1, lecturesPerWeek: 1, totalUnits: 1 },
        ...overrides,
    };
}

/**
 * @param {import('@playwright/test').Page} page
 * @param {{
 *   admin?: boolean,
 *   adminCheckFails?: boolean,
 *   course?: Record<string, any>,
 *   courseGetStatus?: number,
 *   createStatus?: number,
 *   documentUploadStatus?: number,
 *   textUploadStatus?: number,
 *   approvedTopicsStatus?: number,
 *   extractTopicsStatus?: number,
 *   extractTopicsSkippedAdditional?: boolean,
 *   learningObjectivesStatus?: number,
 *   questionsStatus?: number,
 *   thresholdStatus?: number,
 *   autoLinkStatus?: number,
 *   aiStatus?: number,
 *   aiSuccess?: boolean,
 *   joinableStatus?: number,
 *   joinableSuccess?: boolean,
 *   joinableCourses?: Record<string, any>[],
 *   instructorCourses?: Record<string, any>[],
 *   instructorCoursesSequence?: Record<string, any>[][],
 *   noAuthUser?: boolean,
 * }} [options]
 */
async function installOnboardingRoutes(page, options = {}) {
    const course = options.course || branchCourse();
    const captures = {
        creates: [],
        updates: [],
        completions: [],
        textUploads: [],
        fileUploads: 0,
        approvedTopicSaves: [],
        learningObjectiveSaves: [],
        questionSaves: [],
        thresholdSaves: [],
        autoLinkRequests: [],
        aiRequests: [],
        deletedDocuments: [],
        removedDocumentTypes: [],
    };
    let instructorLookupCount = 0;
    let aiCallCount = 0;

    await page.route('**/api/**', async (route) => {
        const request = route.request();
        const url = new URL(request.url());
        const pathname = url.pathname;
        const method = request.method();
        const body = () => {
            try {
                return request.postDataJSON();
            } catch {
                return {};
            }
        };

        if (pathname === '/api/settings/llm-tag') {
            await route.fulfill({ json: { success: true, llmIndex: 1, reasoningIndex: 1 } });
            return;
        }

        if (pathname === '/api/auth/me') {
            if (options.noAuthUser) {
                await route.fulfill({ json: { success: false, user: null } });
                return;
            }
            await route.fulfill({
                json: {
                    success: true,
                    user: {
                        userId: INSTRUCTOR_ID,
                        username: 'e2e_onboarding_branch',
                        role: 'instructor',
                        displayName: 'Onboarding Branch Instructor',
                        permissions: { systemAdmin: !!options.admin },
                    },
                },
            });
            return;
        }

        if (pathname === '/api/settings/can-delete-all') {
            if (options.adminCheckFails) {
                await route.abort();
                return;
            }
            await route.fulfill({ json: { success: true, canDeleteAll: !!options.admin } });
            return;
        }

        if (pathname === `/api/onboarding/instructor/${INSTRUCTOR_ID}` && method === 'GET') {
            const sequenceCourses = options.instructorCoursesSequence
                ? options.instructorCoursesSequence[Math.min(instructorLookupCount, options.instructorCoursesSequence.length - 1)]
                : undefined;
            instructorLookupCount += 1;
            await route.fulfill({
                json: {
                    success: true,
                    data: { courses: sequenceCourses || options.instructorCourses || [] },
                },
            });
            return;
        }

        if (pathname === '/api/courses/available/joinable') {
            if (options.joinableStatus) {
                await route.fulfill({ status: options.joinableStatus, json: { success: false, message: 'forced joinable failure' } });
                return;
            }
            if (options.joinableSuccess === false) {
                await route.fulfill({ json: { success: false, message: 'joinable unsuccessful' } });
                return;
            }
            await route.fulfill({
                json: {
                    success: true,
                    data: options.joinableCourses || [
                        branchCourse({ courseId: 'JOIN-BRANCH', courseName: 'Join Branch Biology' }),
                    ],
                },
            });
            return;
        }

        if (pathname === '/api/onboarding' && method === 'POST') {
            const payload = body();
            captures.creates.push(payload);
            if (options.createStatus) {
                await route.fulfill({ status: options.createStatus, body: 'forced create failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: { courseId: payload.courseId || course.courseId } } });
            return;
        }

        if (/^\/api\/onboarding\/[^/]+$/.test(pathname) && method === 'GET') {
            await route.fulfill({ json: { success: true, data: course } });
            return;
        }

        if (/^\/api\/onboarding\/[^/]+$/.test(pathname) && method === 'PUT') {
            captures.updates.push(body());
            await route.fulfill({ json: { success: true, data: course } });
            return;
        }

        if (pathname === '/api/onboarding/complete' && method === 'POST') {
            captures.completions.push(body());
            await route.fulfill({ json: { success: true } });
            return;
        }

        if (/^\/api\/courses\/[^/]+$/.test(pathname) && method === 'GET') {
            if (options.courseGetStatus) {
                await route.fulfill({ status: options.courseGetStatus, json: { success: false } });
                return;
            }
            await route.fulfill({ json: { success: true, data: course } });
            return;
        }

        if (pathname.endsWith('/instructors') && method === 'POST') {
            await route.fulfill({ json: { success: true, data: course } });
            return;
        }

        if (pathname === '/api/documents/upload' && method === 'POST') {
            captures.fileUploads += 1;
            if (options.documentUploadStatus) {
                await route.fulfill({ status: options.documentUploadStatus, body: 'forced upload failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: { documentId: `file-doc-${captures.fileUploads}` } } });
            return;
        }

        if (pathname === '/api/documents/text' && method === 'POST') {
            captures.textUploads.push(body());
            if (options.textUploadStatus) {
                await route.fulfill({ status: options.textUploadStatus, body: 'forced text failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: { documentId: `text-doc-${captures.textUploads.length}` } } });
            return;
        }

        if (pathname.startsWith('/api/documents/') && method === 'DELETE') {
            captures.deletedDocuments.push(pathname.split('/').pop() || '');
            await route.fulfill({ json: { success: true } });
            return;
        }

        if (pathname.includes('/lectures/') && pathname.endsWith('/documents') && method === 'DELETE') {
            captures.removedDocumentTypes.push(body());
            await route.fulfill({ json: { success: true } });
            return;
        }

        if (pathname.endsWith('/approved-topics') && method === 'GET') {
            if (options.approvedTopicsStatus) {
                await route.fulfill({ status: options.approvedTopicsStatus, json: { success: false } });
                return;
            }
            await route.fulfill({
                json: {
                    success: true,
                    data: {
                        topics: course.approvedStruggleTopics || [],
                        topicLabels: (course.approvedStruggleTopics || []).map(topic => topic.topic || topic),
                    },
                },
            });
            return;
        }

        if (pathname.endsWith('/approved-topics') && method === 'PUT') {
            captures.approvedTopicSaves.push(body());
            if (options.approvedTopicsStatus) {
                await route.fulfill({ status: options.approvedTopicsStatus, json: { success: false } });
                return;
            }
            await route.fulfill({ json: { success: true, data: { topics: body().topics || [] } } });
            return;
        }

        if (pathname.endsWith('/extract-topics') && method === 'POST') {
            if (options.extractTopicsStatus) {
                await route.fulfill({ status: options.extractTopicsStatus, json: { success: false } });
                return;
            }
            if (options.extractTopicsSkippedAdditional) {
                await route.fulfill({ json: { success: true, data: { topics: [], skippedAdditionalMaterial: true } } });
                return;
            }
            await route.fulfill({ json: { success: true, data: { topics: ['Branch Topic'] } } });
            return;
        }

        if (pathname === '/api/learning-objectives' && method === 'POST') {
            captures.learningObjectiveSaves.push(body());
            if (options.learningObjectivesStatus) {
                await route.fulfill({ status: options.learningObjectivesStatus, body: 'forced objectives failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: body() } });
            return;
        }

        if (pathname === '/api/questions' && method === 'POST') {
            captures.questionSaves.push(body());
            if (options.questionsStatus) {
                await route.fulfill({ status: options.questionsStatus, body: 'forced question failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: { questionId: `q-${captures.questionSaves.length}` } } });
            return;
        }

        if (pathname === '/api/lectures/pass-threshold' && method === 'POST') {
            captures.thresholdSaves.push(body());
            if (options.thresholdStatus) {
                await route.fulfill({ status: options.thresholdStatus, body: 'forced threshold failure' });
                return;
            }
            await route.fulfill({ json: { success: true, data: body() } });
            return;
        }

        if (pathname === '/api/questions/auto-link-learning-objectives' && method === 'POST') {
            captures.autoLinkRequests.push(body());
            if (options.autoLinkStatus) {
                await route.fulfill({ status: options.autoLinkStatus, json: { success: false, message: 'forced auto-link failure' } });
                return;
            }
            await route.fulfill({
                json: {
                    success: true,
                    message: '',
                    data: {
                        linkedCount: 0,
                        unassignedCount: 1,
                        matchedQuestions: [],
                    },
                },
            });
            return;
        }

        if (pathname === '/api/questions/generate-ai' && method === 'POST') {
            const payload = body();
            captures.aiRequests.push(payload);
            if (options.aiStatus) {
                await route.fulfill({ status: options.aiStatus, json: { success: false, message: 'forced AI failure' } });
                return;
            }
            if (options.aiSuccess === false) {
                await route.fulfill({ json: { success: false, message: 'AI reported unsuccessful' } });
                return;
            }
            aiCallCount += 1;
            await route.fulfill({
                json: {
                    success: true,
                    data: {
                        question: aiCallCount === 1 ? 'Generated branch question?' : 'Regenerated branch question?',
                        options: {
                            choices: ['Alpha', 'Beta', 'Gamma', 'Delta'],
                            correctAnswer: 'A',
                        },
                        answer: 'A',
                        selectedLearningObjective: payload.regenerate ? '' : 'Explain branch biology.',
                        wasRegenerated: !!payload.regenerate,
                    },
                },
            });
            return;
        }

        await route.fulfill({ json: { success: true, data: {} } });
    });

    return captures;
}

async function gotoOnboarding(page, options = {}) {
    const captures = await installOnboardingRoutes(page, options);
    await page.goto('/instructor/onboarding.html');
    await expect(page.locator('#course-select option[value="custom"]')).toHaveCount(1);
    return captures;
}

async function startCustomCourse(page, name = 'Onboarding Branch Custom Course') {
    await page.locator('#step-1 button.btn-primary', { hasText: 'Get Started' }).click();
    await expect(page.locator('#step-2.onboarding-step.active')).toBeVisible();
    await page.locator('#course-select').selectOption('custom');
    await page.locator('#custom-course-name').fill(name);
    await page.locator('#weeks-count').fill('1');
    await page.locator('#lectures-per-week').fill('1');
    await page.locator('#continue-btn').click();
    await expect(page.locator('#step-3.onboarding-step.active')).toBeVisible();
}

async function addObjective(page, text = 'Explain branch biology.') {
    await page.locator('#objective-input').fill(text);
    await page.locator('.add-objective-btn').click();
    await expect(page.locator('#objectives-list')).toContainText(text);
}

async function addTrueFalseQuestion(page, text = 'Enzymes lower activation energy.') {
    await page.locator('.add-question-btn').click();
    await page.locator('#question-type').selectOption('true-false');
    await page.locator('#question-text').fill(text);
    await page.locator('input[name="tf-answer"][value="true"]').check();
    await page.locator('#question-modal button.btn-primary', { hasText: 'Save Question' }).click();
    await expect(page.locator('#assessment-questions-onboarding .question-item')).toHaveCount(1);
}

module.exports = {
    INSTRUCTOR_ID,
    COURSE_ID,
    branchCourse,
    installOnboardingRoutes,
    gotoOnboarding,
    startCustomCourse,
    addObjective,
    addTrueFalseQuestion,
};
