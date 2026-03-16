// @ts-check
require('dotenv').config();
const { test, expect } = require('@playwright/test');
const {
  getCourseDetails,
  getCurrentUser,
  getPrimaryInstructorCourse,
  loginViaApi,
} = require('./helpers/e2e');

/**
 * Course management API tests for unit lifecycle and content/vector ingestion.
 * Expects the app to be running on localhost:8085 (npm run dev).
 */

async function getInstructorCourseContext(request) {
  await loginViaApi(request, 'instructor');

  const user = await getCurrentUser(request);
  const primaryCourse = await getPrimaryInstructorCourse(request);

  if (!primaryCourse) {
    return null;
  }

  const courseId = primaryCourse.id || primaryCourse.courseId;
  const course = await getCourseDetails(request, courseId);

  return {
    instructorId: user.userId,
    courseId,
    course,
  };
}

async function createUnit(request, courseId, instructorId) {
  const response = await request.post(`/api/courses/${encodeURIComponent(courseId)}/units`, {
    data: { instructorId },
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.unit.name;
}

async function renameUnit(request, courseId, unitName, displayName, instructorId) {
  const response = await request.put(
    `/api/courses/${encodeURIComponent(courseId)}/units/${encodeURIComponent(unitName)}/rename`,
    {
      data: { displayName, instructorId },
    }
  );
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function deleteUnit(request, courseId, unitName, instructorId) {
  const response = await request.delete(
    `/api/courses/${encodeURIComponent(courseId)}/units/${encodeURIComponent(unitName)}`,
    {
      data: { instructorId },
    }
  );
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function safeDeleteUnit(request, courseId, unitName, instructorId) {
  try {
    await request.delete(
      `/api/courses/${encodeURIComponent(courseId)}/units/${encodeURIComponent(unitName)}`,
      {
        data: { instructorId },
      }
    );
  } catch (error) {
    // Best-effort cleanup only.
  }
}

async function deleteDocument(request, documentId, instructorId) {
  const response = await request.delete(`/api/documents/${encodeURIComponent(documentId)}`, {
    data: { instructorId },
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function safeDeleteDocument(request, documentId, instructorId) {
  try {
    await request.delete(`/api/documents/${encodeURIComponent(documentId)}`, {
      data: { instructorId },
    });
  } catch (error) {
    // Best-effort cleanup only.
  }
}

async function uploadTextDocument(request, courseId, lectureName, instructorId, marker) {
  const response = await request.post('/api/documents/text', {
    data: {
      courseId,
      lectureName,
      documentType: 'lecture-notes',
      instructorId,
      title: `E2E Content ${marker}`,
      description: 'Temporary E2E text content upload',
      content: `Biochemistry course management verification content for ${marker}. This unit discusses phosphofructokinase regulation and citrate inhibition. Unique marker: ${marker}.`,
    },
    timeout: 60000,
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function uploadFileDocument(request, courseId, lectureName, instructorId, marker) {
  const title = `E2E File Content ${marker}`;
  const originalName = `e2e-${marker}.txt`;
  const content = `Biochemistry file upload verification content for ${marker}. This file covers pyruvate dehydrogenase regulation and acetyl-CoA feedback. Unique marker: ${marker}.`;

  const response = await request.post('/api/documents/upload', {
    multipart: {
      courseId,
      lectureName,
      documentType: 'lecture-notes',
      instructorId,
      title,
      description: 'Temporary E2E file content upload',
      file: {
        name: originalName,
        mimeType: 'text/plain',
        buffer: Buffer.from(content, 'utf8'),
      },
    },
    timeout: 60000,
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return {
    body,
    title,
    originalName,
    content,
  };
}

async function searchVectors(request, marker, courseId, lectureName) {
  const response = await request.post('/api/qdrant/search', {
    data: {
      query: `phosphofructokinase regulation ${marker}`,
      courseId,
      lectureName,
      limit: 5,
    },
    timeout: 60000,
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.results || [];
}

async function getDocumentStats(request, courseId) {
  const response = await request.get(`/api/documents/stats?courseId=${encodeURIComponent(courseId)}`);
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.stats;
}

async function setLecturePublishStatus(request, courseId, lectureName, isPublished) {
  const response = await request.post('/api/lectures/publish', {
    data: {
      courseId,
      lectureName,
      isPublished,
    },
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function getLecturePublishStatus(request, courseId, instructorId) {
  const response = await request.get(
    `/api/lectures/publish-status?courseId=${encodeURIComponent(courseId)}&instructorId=${encodeURIComponent(instructorId)}`
  );
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.publishStatus;
}

async function getStudentVisibleLectures(request, courseId) {
  const response = await request.get(`/api/lectures/student-visible?courseId=${encodeURIComponent(courseId)}`);
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.publishedLectures || [];
}

async function setPassThreshold(request, courseId, lectureName, passThreshold, instructorId) {
  const response = await request.post('/api/lectures/pass-threshold', {
    data: {
      courseId,
      lectureName,
      passThreshold,
      instructorId,
    },
  });
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body;
}

async function getPassThreshold(request, courseId, lectureName) {
  const response = await request.get(
    `/api/lectures/pass-threshold?courseId=${encodeURIComponent(courseId)}&lectureName=${encodeURIComponent(lectureName)}`
  );
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.passThreshold;
}

async function getPublishedLecturesWithQuestions(request, courseId) {
  const response = await request.get(`/api/lectures/published-with-questions?courseId=${encodeURIComponent(courseId)}`);
  expect(response.ok()).toBeTruthy();

  const body = await response.json();
  expect(body.success).toBeTruthy();

  return body.data.publishedLectures || [];
}

test.describe.serial('Course unit management', () => {
  test('instructor can add a new unit to a course', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for unit tests.');

    const initialUnitCount = (context.course.lectures || []).length;
    let unitName = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const updatedCourse = await getCourseDetails(request, context.courseId);
      const newUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);

      expect(updatedCourse.lectures.length).toBe(initialUnitCount + 1);
      expect(newUnit).toBeDefined();
      expect(newUnit.isPublished).toBe(false);
      expect(Array.isArray(newUnit.documents)).toBeTruthy();
      expect(Array.isArray(newUnit.assessmentQuestions)).toBeTruthy();
    } finally {
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('instructor can rename a unit display name and clear it again', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for unit rename tests.');

    const displayName = `E2E Renamed Unit ${Date.now()}`;
    let unitName = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const renameBody = await renameUnit(request, context.courseId, unitName, displayName, context.instructorId);
      expect(renameBody.data.displayName).toBe(displayName);

      let updatedCourse = await getCourseDetails(request, context.courseId);
      let renamedUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);
      expect(renamedUnit.displayName).toBe(displayName);

      const clearBody = await renameUnit(request, context.courseId, unitName, '', context.instructorId);
      expect(clearBody.data.displayName).toBeNull();

      updatedCourse = await getCourseDetails(request, context.courseId);
      renamedUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);
      expect(renamedUnit.displayName || null).toBeNull();
    } finally {
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('deleting a unit removes it from the course structure', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for unit delete tests.');

    const unitName = await createUnit(request, context.courseId, context.instructorId);
    const deleteBody = await deleteUnit(request, context.courseId, unitName, context.instructorId);

    expect(deleteBody.data.deletedUnit).toBe(unitName);

    const updatedCourse = await getCourseDetails(request, context.courseId);
    const deletedUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);

    expect(deletedUnit).toBeUndefined();
  });
});

test.describe.serial('Course content and vector indexing', () => {
  test('uploading text content links it to the unit and indexes it in qdrant', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for content upload tests.');

    const marker = `E2E_VECTOR_${Date.now()}`;
    let unitName = null;
    let documentId = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const uploadBody = await uploadTextDocument(request, context.courseId, unitName, context.instructorId, marker);
      documentId = uploadBody.data.documentId;

      expect(uploadBody.data.qdrantProcessed).toBe(true);
      expect(uploadBody.data.chunksStored).toBeGreaterThan(0);

      const documentResponse = await request.get(`/api/documents/${encodeURIComponent(documentId)}`);
      expect(documentResponse.ok()).toBeTruthy();
      const documentBody = await documentResponse.json();

      expect(documentBody.success).toBeTruthy();
      expect(documentBody.data.lectureName).toBe(unitName);
      expect(documentBody.data.content).toContain(marker);

      const lectureResponse = await request.get(
        `/api/documents/lecture?courseId=${encodeURIComponent(context.courseId)}&lectureName=${encodeURIComponent(unitName)}`
      );
      expect(lectureResponse.ok()).toBeTruthy();
      const lectureBody = await lectureResponse.json();

      expect(lectureBody.success).toBeTruthy();
      expect(lectureBody.data.documents.some((doc) => doc.documentId === documentId)).toBe(true);

      const results = await searchVectors(request, marker, context.courseId, unitName);
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((result) => result.documentId === documentId)).toBe(true);
      expect(results.some((result) => String(result.chunkText).includes(marker))).toBe(true);
    } finally {
      if (documentId) {
        await safeDeleteDocument(request, documentId, context.instructorId);
      }
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('deleting a unit removes its uploaded documents and qdrant vectors', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for content cleanup tests.');

    const marker = `E2E_DELETE_VECTOR_${Date.now()}`;
    let unitName = null;
    let documentId = null;
    let unitDeleted = false;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const uploadBody = await uploadTextDocument(request, context.courseId, unitName, context.instructorId, marker);
      documentId = uploadBody.data.documentId;

      const initialResults = await searchVectors(request, marker, context.courseId, unitName);
      expect(initialResults.some((result) => result.documentId === documentId)).toBe(true);

      const deleteBody = await deleteUnit(request, context.courseId, unitName, context.instructorId);
      unitDeleted = true;

      expect(deleteBody.data.deletedUnit).toBe(unitName);
      expect(deleteBody.data.deletedDocumentsCount).toBeGreaterThanOrEqual(1);

      const updatedCourse = await getCourseDetails(request, context.courseId);
      expect((updatedCourse.lectures || []).some((lecture) => lecture.name === unitName)).toBe(false);

      const lectureResponse = await request.get(
        `/api/documents/lecture?courseId=${encodeURIComponent(context.courseId)}&lectureName=${encodeURIComponent(unitName)}`
      );
      expect(lectureResponse.ok()).toBeTruthy();
      const lectureBody = await lectureResponse.json();
      expect(lectureBody.success).toBeTruthy();
      expect(lectureBody.data.count).toBe(0);

      const documentResponse = await request.get(`/api/documents/${encodeURIComponent(documentId)}`);
      expect(documentResponse.status()).toBe(404);

      const remainingResults = await searchVectors(request, marker, context.courseId, unitName);
      expect(remainingResults.some((result) => result.documentId === documentId)).toBe(false);
    } finally {
      if (!unitDeleted && documentId) {
        await safeDeleteDocument(request, documentId, context.instructorId);
      }
      if (!unitDeleted && unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });
});

test.describe.serial('Course file uploads and lecture settings', () => {
  test('uploading a text file preserves metadata, links it to the unit, and indexes it in qdrant', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for file upload tests.');

    const marker = `E2E_FILE_VECTOR_${Date.now()}`;
    let unitName = null;
    let documentId = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const upload = await uploadFileDocument(request, context.courseId, unitName, context.instructorId, marker);
      documentId = upload.body.data.documentId;

      expect(upload.body.data.filename).toBe(upload.title);
      expect(upload.body.data.qdrantProcessed).toBe(true);
      expect(upload.body.data.chunksStored).toBeGreaterThan(0);

      const documentResponse = await request.get(`/api/documents/${encodeURIComponent(documentId)}`);
      expect(documentResponse.ok()).toBeTruthy();
      const documentBody = await documentResponse.json();

      expect(documentBody.success).toBeTruthy();
      expect(documentBody.data.contentType).toBe('file');
      expect(documentBody.data.filename).toBe(upload.title);
      expect(documentBody.data.originalName).toBe(upload.originalName);
      expect(documentBody.data.mimeType).toBe('text/plain');
      expect(documentBody.data.content).toContain(marker);

      const lectureResponse = await request.get(
        `/api/documents/lecture?courseId=${encodeURIComponent(context.courseId)}&lectureName=${encodeURIComponent(unitName)}`
      );
      expect(lectureResponse.ok()).toBeTruthy();
      const lectureBody = await lectureResponse.json();

      expect(lectureBody.success).toBeTruthy();
      expect(
        lectureBody.data.documents.some((doc) => doc.documentId === documentId && doc.filename === upload.title)
      ).toBe(true);

      const results = await searchVectors(request, marker, context.courseId, unitName);
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((result) => result.documentId === documentId)).toBe(true);
      expect(results.some((result) => String(result.chunkText).includes(marker))).toBe(true);
    } finally {
      if (documentId) {
        await safeDeleteDocument(request, documentId, context.instructorId);
      }
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('document stats reflect uploads and direct document deletion cleanup', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for document stats tests.');

    const marker = `E2E_STATS_${Date.now()}`;
    let unitName = null;
    let documentId = null;

    try {
      const beforeStats = await getDocumentStats(request, context.courseId);
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const uploadBody = await uploadTextDocument(request, context.courseId, unitName, context.instructorId, marker);
      documentId = uploadBody.data.documentId;

      const afterUploadStats = await getDocumentStats(request, context.courseId);
      expect(afterUploadStats.totalDocuments).toBe(beforeStats.totalDocuments + 1);
      expect(afterUploadStats.totalSize).toBeGreaterThan(beforeStats.totalSize);
      expect(afterUploadStats.statusBreakdown.some((entry) => entry.status === 'uploaded' && entry.count > 0)).toBe(true);

      const deleteBody = await deleteDocument(request, documentId, context.instructorId);
      documentId = null;

      expect(deleteBody.data.documentId).toBeTruthy();
      expect(deleteBody.data.removedFromCourse).toBe(true);
      expect(deleteBody.data.removedFromQdrant).toBe(true);
      expect(deleteBody.data.qdrantChunksDeleted).toBeGreaterThan(0);

      const lectureResponse = await request.get(
        `/api/documents/lecture?courseId=${encodeURIComponent(context.courseId)}&lectureName=${encodeURIComponent(unitName)}`
      );
      expect(lectureResponse.ok()).toBeTruthy();
      const lectureBody = await lectureResponse.json();

      expect(lectureBody.success).toBeTruthy();
      expect(lectureBody.data.count).toBe(0);

      const finalStats = await getDocumentStats(request, context.courseId);
      expect(finalStats.totalDocuments).toBe(beforeStats.totalDocuments);
    } finally {
      if (documentId) {
        await safeDeleteDocument(request, documentId, context.instructorId);
      }
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('publishing and unpublishing a unit updates publish status and student visibility', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for lecture publish tests.');

    let unitName = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const publishBody = await setLecturePublishStatus(request, context.courseId, unitName, true);
      expect(publishBody.data.lectureName).toBe(unitName);
      expect(publishBody.data.isPublished).toBe(true);

      let publishStatus = await getLecturePublishStatus(request, context.courseId, context.instructorId);
      expect(publishStatus[unitName]).toBe(true);

      let studentVisibleLectures = await getStudentVisibleLectures(request, context.courseId);
      expect(studentVisibleLectures).toContain(unitName);

      let updatedCourse = await getCourseDetails(request, context.courseId);
      let updatedUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);
      expect(updatedUnit).toBeDefined();
      expect(updatedUnit.isPublished).toBe(true);

      const unpublishBody = await setLecturePublishStatus(request, context.courseId, unitName, false);
      expect(unpublishBody.data.isPublished).toBe(false);

      publishStatus = await getLecturePublishStatus(request, context.courseId, context.instructorId);
      expect(publishStatus[unitName]).toBe(false);

      studentVisibleLectures = await getStudentVisibleLectures(request, context.courseId);
      expect(studentVisibleLectures).not.toContain(unitName);

      updatedCourse = await getCourseDetails(request, context.courseId);
      updatedUnit = (updatedCourse.lectures || []).find((lecture) => lecture.name === unitName);
      expect(updatedUnit).toBeDefined();
      expect(updatedUnit.isPublished).toBe(false);
    } finally {
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });

  test('pass threshold updates are reflected in lecture settings and published lecture payloads', async ({ request }) => {
    const context = await getInstructorCourseContext(request);
    test.skip(!context, 'Need an instructor-owned course for pass threshold tests.');

    const passThreshold = 85;
    let unitName = null;

    try {
      unitName = await createUnit(request, context.courseId, context.instructorId);

      const thresholdBody = await setPassThreshold(
        request,
        context.courseId,
        unitName,
        passThreshold,
        context.instructorId
      );
      expect(thresholdBody.data.passThreshold).toBe(passThreshold);

      const storedThreshold = await getPassThreshold(request, context.courseId, unitName);
      expect(storedThreshold).toBe(passThreshold);

      await setLecturePublishStatus(request, context.courseId, unitName, true);

      const publishedLectures = await getPublishedLecturesWithQuestions(request, context.courseId);
      const publishedUnit = publishedLectures.find((lecture) => lecture.name === unitName);

      expect(publishedUnit).toBeDefined();
      expect(publishedUnit.passThreshold).toBe(passThreshold);
      expect(Array.isArray(publishedUnit.assessmentQuestions)).toBe(true);
      expect(Array.isArray(publishedUnit.documents)).toBe(true);
    } finally {
      if (unitName) {
        await safeDeleteUnit(request, context.courseId, unitName, context.instructorId);
      }
    }
  });
});
