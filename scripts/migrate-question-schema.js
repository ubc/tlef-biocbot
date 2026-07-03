#!/usr/bin/env node

require('dotenv').config();
const { MongoClient } = require('mongodb');

function normalizeAssessmentQuestion(question) {
    const normalized = { ...question };

    if (normalized.questionType === 'true-false') {
        normalized.correctAnswer = normalized.correctAnswer === true
            || String(normalized.correctAnswer).toLowerCase() === 'true';
        return normalized;
    }

    if (normalized.questionType !== 'multiple-choice') return normalized;

    if (Array.isArray(normalized.options)) {
        normalized.options = normalized.options.map(value => String(value).trim());
        if (typeof normalized.correctAnswer === 'string' && /^\d+$/.test(normalized.correctAnswer)) {
            normalized.correctAnswer = Number(normalized.correctAnswer);
        }
        return normalized;
    }

    const entries = Object.entries(normalized.options || {}).sort(([a], [b]) => a.localeCompare(b));
    normalized.options = entries.map(([, value]) => String(value).trim());
    if (typeof normalized.correctAnswer === 'string') {
        const index = entries.findIndex(([key]) => key === normalized.correctAnswer);
        if (index >= 0) normalized.correctAnswer = index;
    }
    return normalized;
}

async function migrateQuestionSchema(db, { dryRun = false } = {}) {
    const courses = await db.collection('courses').find({ 'lectures.assessmentQuestions': { $exists: true } }).toArray();
    let updatedCourses = 0;
    let updatedQuestions = 0;

    for (const course of courses) {
        let changed = false;
        const lectures = (course.lectures || []).map(lecture => ({
            ...lecture,
            assessmentQuestions: (lecture.assessmentQuestions || []).map(question => {
                const normalized = normalizeAssessmentQuestion(question);
                if (JSON.stringify(normalized) !== JSON.stringify(question)) {
                    changed = true;
                    updatedQuestions += 1;
                }
                return normalized;
            })
        }));

        if (changed) {
            updatedCourses += 1;
            if (!dryRun) {
                await db.collection('courses').updateOne(
                    { _id: course._id },
                    { $set: { lectures, updatedAt: new Date() } }
                );
            }
        }
    }

    return { scannedCourses: courses.length, updatedCourses, updatedQuestions, dryRun };
}

async function main() {
    const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;
    const dbName = process.env.DB_NAME || process.env.MONGO_DB_NAME;
    if (!mongoUri) throw new Error('MONGO_URI is required.');

    const client = new MongoClient(mongoUri);
    try {
        await client.connect();
        const dryRun = !process.argv.includes('--apply');
        const result = await migrateQuestionSchema(dbName ? client.db(dbName) : client.db(), { dryRun });
        console.log(`Question migration complete: ${JSON.stringify(result)}`);
        if (dryRun) console.log('Dry run only. Re-run with --apply to persist changes.');
    } finally {
        await client.close();
    }
}

if (require.main === module) {
    main().catch(error => {
        console.error(error.message || error);
        process.exit(1);
    });
}

module.exports = { normalizeAssessmentQuestion, migrateQuestionSchema };
