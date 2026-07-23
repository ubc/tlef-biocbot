#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { MongoClient } = require('mongodb');
const AssessmentScoring = require('../public/common/scripts/assessment-scoring');

function parseArgs(argv) {
    const options = { apply: false };
    for (let index = 0; index < argv.length; index++) {
        const arg = argv[index];
        if (arg === '--apply') {
            options.apply = true;
        } else if (arg === '--course-id') {
            options.courseId = argv[++index];
        } else if (arg === '--student-id') {
            options.studentId = argv[++index];
        } else if (arg === '--session-id') {
            options.sessionId = argv[++index];
        } else if (arg === '--backup-file') {
            options.backupFile = argv[++index];
        } else if (arg === '--help' || arg === '-h') {
            options.help = true;
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }
    for (const key of ['courseId', 'studentId', 'sessionId', 'backupFile']) {
        if (options[key] === undefined && argv.includes(`--${key.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)}`)) {
            throw new Error(`Missing value for --${key.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)}`);
        }
    }
    return options;
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

function same(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
}

function setIfChanged(target, key, value, pathName, changedFields) {
    if (!same(target[key], value)) {
        target[key] = value;
        changedFields.push(pathName);
    }
}

function extractOldScore(message) {
    const combined = `${message?.content ?? ''}\n${message?.htmlContent ?? ''}`;
    const match = combined.match(/Score:\s*(\d+)\s*\/\s*(\d+)/i);
    return match ? `${match[1]}/${match[2]}` : null;
}

function repairChatData(sourceChatData) {
    const chatData = clone(sourceChatData || {});
    const questions = chatData.practiceTests?.questions;
    const answerRecords = chatData.studentAnswers?.answers;
    if (!Array.isArray(questions) || questions.length === 0) {
        return { changed: false, skippedReason: 'practiceTests.questions is missing or empty' };
    }
    if (!Array.isArray(answerRecords) || answerRecords.length < questions.length) {
        return { changed: false, skippedReason: 'studentAnswers is missing or incomplete' };
    }

    const answers = answerRecords.slice(0, questions.length).map(record =>
        record && typeof record === 'object' && Object.prototype.hasOwnProperty.call(record, 'answer')
            ? record.answer
            : record
    );
    let ambiguousShortAnswerIndex = -1;
    const evaluations = questions.map((question, index) => {
        if (AssessmentScoring.getQuestionType(question) !== 'short-answer') return undefined;
        const persistedResult = chatData.assessmentScore?.results?.[index]
            ?? chatData.practiceTests.score?.results?.[index];
        if (typeof persistedResult?.isCorrect === 'boolean') {
            return { correct: persistedResult.isCorrect, feedback: persistedResult.feedback };
        }
        const expected = AssessmentScoring.normalizeAnswer(
            question,
            AssessmentScoring.getExpectedAnswer(question),
            'correct answer'
        );
        const student = AssessmentScoring.normalizeAnswer(
            question,
            answers[index],
            'student answer'
        );
        if (expected.valid && student.valid &&
            student.value.localeCompare(expected.value, undefined, { sensitivity: 'base' }) === 0) {
            return { correct: true };
        }
        ambiguousShortAnswerIndex = index;
        return undefined;
    });
    if (ambiguousShortAnswerIndex !== -1) {
        return {
            changed: false,
            skippedReason: `question ${ambiguousShortAnswerIndex + 1} is a short answer without a trustworthy persisted evaluation`
        };
    }
    const score = AssessmentScoring.evaluateAssessment(
        questions,
        answers,
        chatData.practiceTests.passThreshold,
        evaluations
    );
    if (!score.scorable) {
        const details = score.invalidResults
            .map(result => `question ${result.index + 1}: ${result.reason}`)
            .join('; ');
        return { changed: false, skippedReason: `unscorable structured data (${details})` };
    }

    const messages = Array.isArray(chatData.messages) ? chatData.messages : [];
    let modeResultIndex = -1;
    for (let index = messages.length - 1; index >= 0; index--) {
        if (messages[index]?.messageType === 'mode-result') {
            modeResultIndex = index;
            break;
        }
    }
    if (modeResultIndex === -1) {
        return { changed: false, skippedReason: 'mode-result message is missing' };
    }

    const changedFields = [];
    questions.forEach((question, index) => {
        setIfChanged(
            question,
            'isCorrect',
            score.results[index].isCorrect,
            `practiceTests.questions[${index}].isCorrect`,
            changedFields
        );
        setIfChanged(
            question,
            'studentAnswer',
            answers[index],
            `practiceTests.questions[${index}].studentAnswer`,
            changedFields
        );
        const record = answerRecords[index];
        if (record && typeof record === 'object' && !Array.isArray(record)) {
            setIfChanged(
                record,
                'isCorrect',
                score.results[index].isCorrect,
                `studentAnswers.answers[${index}].isCorrect`,
                changedFields
            );
        }
    });

    setIfChanged(chatData.practiceTests, 'score', score, 'practiceTests.score', changedFields);
    setIfChanged(chatData, 'assessmentScore', score, 'assessmentScore', changedFields);

    const modeMessage = messages[modeResultIndex];
    const oldScore = extractOldScore(modeMessage);
    setIfChanged(
        modeMessage,
        'content',
        AssessmentScoring.buildModeResultText(score, questions),
        `messages[${modeResultIndex}].content`,
        changedFields
    );
    setIfChanged(
        modeMessage,
        'htmlContent',
        AssessmentScoring.buildModeResultHtml(score, questions),
        `messages[${modeResultIndex}].htmlContent`,
        changedFields
    );
    const nextModeData = { ...(modeMessage.modeData || {}), determinedMode: score.mode };
    setIfChanged(
        modeMessage,
        'modeData',
        nextModeData,
        `messages[${modeResultIndex}].modeData`,
        changedFields
    );

    const hasLaterManualToggle = messages
        .slice(modeResultIndex + 1)
        .some(message => message?.messageType === 'mode-toggle-result');
    if (!hasLaterManualToggle && chatData.metadata) {
        setIfChanged(chatData.metadata, 'currentMode', score.mode, 'metadata.currentMode', changedFields);
    }

    return {
        changed: changedFields.length > 0,
        chatData,
        oldScore,
        newScore: `${score.totalCorrect}/${score.totalQuestions}`,
        changedFields,
        skippedReason: null,
        preservedLaterManualMode: hasLaterManualToggle
    };
}

function buildQuery(options) {
    const query = {};
    if (options.courseId) query.courseId = options.courseId;
    if (options.studentId) query.studentId = options.studentId;
    if (options.sessionId) query.sessionId = options.sessionId;
    return query;
}

function printHelp() {
    console.log(`Usage: node scripts/repair-assessment-summaries.js [options]

Dry-run is the default. No database records are updated without --apply.

Options:
  --apply                 Update repairable chat_sessions
  --course-id ID          Limit to one course
  --student-id ID         Limit to one student
  --session-id ID         Limit to one session
  --backup-file PATH      Backup destination used before --apply updates
  --help                   Show this help`);
}

async function main() {
    const options = parseArgs(process.argv.slice(2));
    if (options.help) {
        printHelp();
        return;
    }

    const client = new MongoClient(process.env.MONGODB_URI || 'mongodb://localhost:27017');
    await client.connect();
    try {
        const db = client.db(process.env.MONGODB_DB || 'biocbot-dev');
        const collection = db.collection('chat_sessions');
        const sessions = await collection.find(buildQuery(options)).toArray();
        const pending = [];
        const report = [];

        for (const session of sessions) {
            const repaired = repairChatData(session.chatData);
            const entry = {
                sessionId: session.sessionId,
                oldScore: repaired.oldScore ?? null,
                newScore: repaired.newScore ?? null,
                changedFields: repaired.changedFields ?? [],
                skippedReason: repaired.skippedReason ?? (
                    repaired.changed ? null : 'already consistent'
                )
            };
            report.push(entry);
            if (repaired.changed) pending.push({ session, repaired });
            console.log(JSON.stringify(entry));
        }

        if (options.apply && pending.length > 0) {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = path.resolve(
                options.backupFile || `assessment-summary-repair-backup-${timestamp}.json`
            );
            fs.writeFileSync(
                backupFile,
                JSON.stringify(pending.map(({ session }) => ({
                    _id: session._id,
                    sessionId: session.sessionId,
                    chatData: session.chatData
                })), null, 2),
                { flag: 'wx' }
            );
            for (const { session, repaired } of pending) {
                await collection.updateOne(
                    { _id: session._id },
                    { $set: { chatData: repaired.chatData } }
                );
            }
            console.log(`Backup written before mutation: ${backupFile}`);
        }

        console.log(JSON.stringify({
            mode: options.apply ? 'apply' : 'dry-run',
            scanned: sessions.length,
            repairable: pending.length,
            skippedOrConsistent: sessions.length - pending.length
        }));
    } finally {
        await client.close();
    }
}

module.exports = { parseArgs, repairChatData, buildQuery };

if (require.main === module) {
    main().catch(error => {
        console.error(error.message);
        process.exitCode = 1;
    });
}
