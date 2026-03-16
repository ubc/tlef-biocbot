// @ts-check
require('dotenv').config();
const { expect } = require('@playwright/test');

/**
 * @typedef {{ id?: string, courseId?: string, courseName?: string, isEnrolled?: boolean }} CourseSummary
 * @typedef {(course: CourseSummary) => boolean | Promise<boolean>} CourseMatcher
 * @typedef {{ username: string, password: string }} Credentials
 */

/** @type {CourseMatcher} */
const allowAnyCourse = (_course) => true;

function getRoleCredentials(role, overrides = {}) {
  const roleCredentials = {
    student: {
      username: process.env.student_username,
      password: process.env.student_password,
    },
    instructor: {
      username: process.env.inst_username,
      password: process.env.inst_password,
    },
    ta: {
      username: process.env.ta_username,
      password: process.env.ta_password,
    },
  };

  const credentials = {
    ...(role ? roleCredentials[role] : {}),
    ...overrides,
  };

  if (!credentials.username || !credentials.password) {
    throw new Error(`Missing credentials for role "${role || 'custom'}"`);
  }

  return credentials;
}

async function loginAs(page, role, overrides = {}) {
  const credentials = getRoleCredentials(role, overrides);
  let lastError = null;

  for (let attempt = 0; attempt < 2; attempt += 1) {
    await page.goto('/login');
    await page.fill('#username', credentials.username);
    await page.fill('#password', credentials.password);

    const loginResponsePromise = page.waitForResponse((response) => {
      return response.url().includes('/api/auth/login') && response.request().method() === 'POST';
    });

    await page.click('#login-btn');

    const loginResponse = await loginResponsePromise;
    const responseBody = await loginResponse.json().catch(() => null);

    if (loginResponse.ok() && responseBody && responseBody.success) {
      return credentials;
    }

    lastError = new Error(
      `Login failed for "${credentials.username}": ${responseBody && responseBody.error ? responseBody.error : loginResponse.status()}`
    );
    await page.waitForTimeout(500);
  }

  throw lastError || new Error(`Login failed for "${credentials.username}"`);
}

async function loginViaApi(request, role, overrides = {}) {
  const credentials = getRoleCredentials(role, overrides);
  const response = await request.post('/api/auth/login', {
    data: credentials,
  });

  expect(response.ok()).toBeTruthy();

  return { response, credentials };
}

async function getCurrentUser(request) {
  const response = await request.get('/api/auth/me');
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.user;
}

async function getInstructorCourses(request) {
  const response = await request.get('/api/courses');
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data || [];
}

async function getPrimaryInstructorCourse(request) {
  const courses = await getInstructorCourses(request);
  return courses[0] || null;
}

async function getTACourses(request, taId) {
  const resolvedTaId = taId || (await getCurrentUser(request)).userId;
  const response = await request.get(`/api/courses/ta/${encodeURIComponent(resolvedTaId)}`);
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data || [];
}

async function getAssignedTACourse(request) {
  const courses = await getTACourses(request);
  return courses[0] || null;
}

async function getTAPermissions(request, courseId, taId) {
  const resolvedTaId = taId || (await getCurrentUser(request)).userId;
  const response = await request.get(
    `/api/courses/${encodeURIComponent(courseId)}/ta-permissions/${encodeURIComponent(resolvedTaId)}`
  );
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.permissions;
}

async function getStudentAvailableCourses(request) {
  const response = await request.get('/api/courses/available/all');
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data || [];
}

async function getCourseDetails(request, courseId) {
  const response = await request.get(`/api/courses/${courseId}`);
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data;
}

/**
 * @param {import('@playwright/test').APIRequestContext} request
 * @param {CourseMatcher} [matcher]
 */
async function getEnrolledStudentCourse(request, matcher = allowAnyCourse) {
  const courses = await getStudentAvailableCourses(request);

  for (const course of courses) {
    if (!course.isEnrolled) {
      continue;
    }

    if (await matcher(course)) {
      return course;
    }
  }

  return null;
}

/**
 * @param {import('@playwright/test').APIRequestContext} request
 * @param {CourseMatcher} [matcher]
 */
async function getNonEnrolledStudentCourse(request, matcher = allowAnyCourse) {
  const courses = await getStudentAvailableCourses(request);

  for (const course of courses) {
    if (course.isEnrolled) {
      continue;
    }

    if (await matcher(course)) {
      return course;
    }
  }

  return null;
}

async function getQuizStatus(request, courseId) {
  const response = await request.get(`/api/quiz/status?courseId=${encodeURIComponent(courseId)}`);
  expect(response.ok()).toBeTruthy();

  return response.json();
}

async function getQuizReadyCourse(request) {
  const enrolledCourses = (await getStudentAvailableCourses(request)).filter((course) => course.isEnrolled);

  for (const course of enrolledCourses) {
    const status = await getQuizStatus(request, course.courseId);
    if (!status.success || !status.enabled) {
      continue;
    }

    const questionsResponse = await request.get(`/api/quiz/questions?courseId=${encodeURIComponent(course.courseId)}`);
    if (!questionsResponse.ok()) {
      continue;
    }

    const questionsBody = await questionsResponse.json();
    if (questionsBody.success && Array.isArray(questionsBody.questions) && questionsBody.questions.length > 0) {
      return {
        course,
        questionsBody,
      };
    }
  }

  return null;
}

async function getDisabledQuizCourse(request) {
  const enrolledCourses = (await getStudentAvailableCourses(request)).filter((course) => course.isEnrolled);

  for (const course of enrolledCourses) {
    const status = await getQuizStatus(request, course.courseId);
    if (status.success && status.enabled === false) {
      return course;
    }
  }

  return null;
}

async function getAssessmentUnitCourse(request) {
  const enrolledCourses = (await getStudentAvailableCourses(request)).filter((course) => course.isEnrolled);

  for (const course of enrolledCourses) {
    const details = await getCourseDetails(request, course.courseId);
    const assessmentUnit = (details.lectures || []).find((lecture) => {
      return lecture.isPublished && Array.isArray(lecture.assessmentQuestions) && lecture.assessmentQuestions.length > 0;
    });

    if (assessmentUnit) {
      return {
        course,
        unitName: assessmentUnit.name,
      };
    }
  }

  return null;
}

async function getChatReadyCourse(request) {
  const enrolledCourses = (await getStudentAvailableCourses(request)).filter((course) => course.isEnrolled);
  let assessmentFallback = null;

  for (const course of enrolledCourses) {
    const details = await getCourseDetails(request, course.courseId);
    const publishedLectures = (details.lectures || []).filter((lecture) => lecture.isPublished);

    const chatReadyUnit = publishedLectures.find((lecture) => {
      return !Array.isArray(lecture.assessmentQuestions) || lecture.assessmentQuestions.length === 0;
    });

    if (chatReadyUnit) {
      return {
        course,
        unitName: chatReadyUnit.name,
      };
    }

    if (!assessmentFallback) {
      const assessmentUnit = publishedLectures.find((lecture) => {
        return Array.isArray(lecture.assessmentQuestions) && lecture.assessmentQuestions.length > 0;
      });

      if (assessmentUnit) {
        assessmentFallback = {
          course,
          unitName: assessmentUnit.name,
        };
      }
    }
  }

  return assessmentFallback;
}

async function clearBrowserState(page) {
  await page.evaluate(() => {
    localStorage.clear();
    sessionStorage.clear();
  });
}

async function setSelectedCourse(page, course) {
  await page.evaluate(({ courseId, courseName }) => {
    localStorage.setItem('selectedCourseId', courseId);
    localStorage.setItem('selectedCourseName', courseName || courseId);
  }, course);
}

async function selectUnit(page, unitName) {
  const unitSelect = page.locator('#unit-select');
  await expect(unitSelect).toBeVisible({ timeout: 10000 });
  await unitSelect.selectOption(unitName);
}

async function prepareStudentCourse(page, course) {
  const courseId = course.courseId || course.id;

  await clearBrowserState(page);
  await page.goto('/student');
  await page.waitForLoadState('networkidle');
  await selectStudentCourse(page, courseId);
  await expect(page.locator('.course-name')).not.toHaveText('Select Course', { timeout: 15000 });
  await expect(page.locator('#unit-selection-container')).toBeVisible({ timeout: 15000 });
}

async function selectStudentCourse(page, courseId) {
  const courseSelect = page.locator('#course-select');
  await expect(courseSelect).toBeVisible({ timeout: 10000 });
  await courseSelect.selectOption(courseId);

  await expect.poll(async () => {
    return page.evaluate(() => localStorage.getItem('selectedCourseId'));
  }).toBe(courseId);
  await expect(page.locator('#course-selection-wrapper')).toBeHidden({ timeout: 15000 });
}

function buildUniqueUsername(prefix = 'e2e_user') {
  return `${prefix}_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

async function registerUser(request, userData) {
  const response = await request.post('/api/auth/register', {
    data: userData,
  });

  const body = await response.json();

  return {
    response,
    body,
  };
}

async function findPrivilegedInstructorCredentials(request) {
  const password = process.env.inst_password;
  const candidates = [
    process.env.privileged_inst_username,
  ].filter(Boolean);

  for (const username of Array.from(new Set(candidates))) {
    const response = await request.post('/api/auth/login', {
      data: {
        username,
        password,
      },
    });

    if (!response.ok()) {
      continue;
    }

    const permissionResponse = await request.get('/api/settings/can-delete-all');
    if (!permissionResponse.ok()) {
      continue;
    }

    const permissionBody = await permissionResponse.json();
    if (permissionBody.success && permissionBody.canDeleteAll) {
      return {
        username,
        password,
      };
    }
  }

  return null;
}

module.exports = {
  buildUniqueUsername,
  clearBrowserState,
  findPrivilegedInstructorCredentials,
  getAssessmentUnitCourse,
  getChatReadyCourse,
  getCourseDetails,
  getCurrentUser,
  getDisabledQuizCourse,
  getEnrolledStudentCourse,
  getAssignedTACourse,
  getInstructorCourses,
  getNonEnrolledStudentCourse,
  getPrimaryInstructorCourse,
  getQuizReadyCourse,
  getQuizStatus,
  getStudentAvailableCourses,
  getTACourses,
  getTAPermissions,
  loginAs,
  loginViaApi,
  prepareStudentCourse,
  registerUser,
  selectStudentCourse,
  selectUnit,
  setSelectedCourse,
};
