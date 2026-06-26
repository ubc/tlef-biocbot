const TrackerService = require('../../../src/services/tracker');

// Tracker logs verbose debug lines; keep test output clean.
beforeAll(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterAll(() => jest.restoreAllMocks());

function llmReturning(content) {
    return { sendMessage: jest.fn().mockResolvedValue({ content }) };
}
function llmThrowing() {
    return { sendMessage: jest.fn().mockRejectedValue(new Error('llm down')) };
}

describe('TrackerService.analyzeMessage', () => {
    test('maps a struggle to an approved topic (case-insensitive) above the confidence floor', async () => {
        const llm = llmReturning(JSON.stringify({
            isStruggling: true,
            rawTopic: 'the steps of glycolysis',
            mappedTopic: 'glycolysis', // lower-cased; should still match approved "Glycolysis"
            matchConfidence: 0.8,
            reason: 'confused about ordering',
        }));
        const result = await new TrackerService(llm).analyzeMessage('help', 'BIOC-1', 'Unit 1', ['Glycolysis', 'Krebs Cycle']);
        expect(result).toEqual({
            topic: 'Glycolysis',
            rawTopic: 'the steps of glycolysis',
            isMapped: true,
            matchConfidence: 0.8,
            isStruggling: true,
            reason: 'confused about ordering',
        });
    });

    test('confidence below 0.55 leaves the topic unmapped', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: true, mappedTopic: 'Glycolysis', matchConfidence: 0.4 }));
        const result = await new TrackerService(llm).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result.isMapped).toBe(false);
        expect(result.topic).toBe('unmapped');
        expect(result.matchConfidence).toBe(0.4);
    });

    test('a mappedTopic outside the approved list is unmapped', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: true, mappedTopic: 'Photosynthesis', matchConfidence: 0.95 }));
        const result = await new TrackerService(llm).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result.isMapped).toBe(false);
        expect(result.topic).toBe('unmapped');
    });

    test('a non-numeric matchConfidence is treated as 0', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: true, mappedTopic: 'Glycolysis' })); // no matchConfidence
        const result = await new TrackerService(llm).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result.matchConfidence).toBe(0);
        expect(result.isMapped).toBe(false);
    });

    test('extracts JSON even when wrapped in code fences and prose', async () => {
        const llm = llmReturning('Sure!\n```json\n{"isStruggling":true,"mappedTopic":"Glycolysis","matchConfidence":0.9,"rawTopic":"q"}\n```\nHope that helps.');
        const result = await new TrackerService(llm).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result.isMapped).toBe(true);
        expect(result.topic).toBe('Glycolysis');
    });

    test('an empty LLM response is treated as no struggle', async () => {
        const result = await new TrackerService(llmReturning('')).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result).toEqual({ isStruggling: false, topic: 'unmapped', isMapped: false, reason: 'Empty LLM response' });
    });

    test('an LLM error fails gracefully as no struggle', async () => {
        const result = await new TrackerService(llmThrowing()).analyzeMessage('x', 'c', 'u', ['Glycolysis']);
        expect(result).toEqual({ isStruggling: false, topic: 'unmapped', isMapped: false, reason: 'Error' });
    });

    test('only clean approved topics reach the prompt, with the expected options', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: false, mappedTopic: 'unmapped', matchConfidence: 0 }));
        await new TrackerService(llm).analyzeMessage('msg', 'BIOC-1', 'Unit 3', ['Glycolysis', '', '   ', 42, 'Krebs']);
        const [prompt, options] = llm.sendMessage.mock.calls[0];
        expect(prompt).toContain('1. Glycolysis');
        expect(prompt).toContain('2. Krebs');
        expect(prompt).not.toContain('42');
        expect(options).toMatchObject({ temperature: 0.1, maxTokens: 220 });
        expect(options.systemPrompt).toMatch(/JSON only/);
    });

    test('with no approved topics the prompt says so', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: false, mappedTopic: 'unmapped', matchConfidence: 0 }));
        await new TrackerService(llm).analyzeMessage('msg', 'BIOC-1', 'Unit 3');
        expect(llm.sendMessage.mock.calls[0][0]).toContain('No approved topics configured');
    });
});

describe('TrackerService.analyzeMessageAcrossCourses', () => {
    test('returns early (no LLM call) when there are no candidate topics', async () => {
        const llm = llmReturning('{}');
        const result = await new TrackerService(llm).analyzeMessageAcrossCourses('help', []);
        expect(result).toMatchObject({ isStruggling: false, topic: 'unmapped', courseId: null, reason: 'No approved topics across courses' });
        expect(llm.sendMessage).not.toHaveBeenCalled();
    });

    test('attributes a matched candidate back to its course and skips malformed entries', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: true, rawTopic: 'citric acid', matchedIndex: 1, matchConfidence: 0.9 }));
        const courseTopics = [
            { courseId: 'C1', courseName: 'Course One', approvedTopics: ['Glycolysis', '   '] }, // index 0
            { courseId: 'C2', approvedTopics: ['Krebs'] },                                       // index 1, name falls back to id
            { courseName: 'NoId', approvedTopics: ['Skipped'] },                                 // no courseId -> skipped
            { courseId: 'C3', approvedTopics: 'not-an-array' },                                  // skipped
        ];
        const result = await new TrackerService(llm).analyzeMessageAcrossCourses('help', courseTopics);
        expect(result).toMatchObject({ isStruggling: true, topic: 'Krebs', courseId: 'C2', courseName: 'C2', isMapped: true, matchConfidence: 0.9 });

        const prompt = llm.sendMessage.mock.calls[0][0];
        expect(prompt).toContain('0. "Glycolysis" — Course One');
        expect(prompt).toContain('1. "Krebs" — C2');
        expect(prompt).not.toContain('Skipped');
    });

    test('matchedIndex of -1, out of range, or non-integer stays unmapped', async () => {
        const topics = [{ courseId: 'C1', courseName: 'One', approvedTopics: ['Glycolysis'] }];
        for (const matchedIndex of [-1, 5, 0.5]) {
            const llm = llmReturning(JSON.stringify({ isStruggling: true, matchedIndex, matchConfidence: 0.9 }));
            const result = await new TrackerService(llm).analyzeMessageAcrossCourses('help', topics);
            expect(result.isMapped).toBe(false);
            expect(result.topic).toBe('unmapped');
            expect(result.courseId).toBeNull();
        }
    });

    test('a valid index below the confidence floor is unmapped', async () => {
        const llm = llmReturning(JSON.stringify({ isStruggling: true, matchedIndex: 0, matchConfidence: 0.3 }));
        const result = await new TrackerService(llm).analyzeMessageAcrossCourses('help', [
            { courseId: 'C1', courseName: 'One', approvedTopics: ['Glycolysis'] },
        ]);
        expect(result.isMapped).toBe(false);
        expect(result.topic).toBe('unmapped');
    });

    test('empty content and LLM errors both fail gracefully', async () => {
        const topics = [{ courseId: 'C1', courseName: 'One', approvedTopics: ['Glycolysis'] }];
        const empty = await new TrackerService(llmReturning('')).analyzeMessageAcrossCourses('help', topics);
        expect(empty.reason).toBe('Empty LLM response');

        const errored = await new TrackerService(llmThrowing()).analyzeMessageAcrossCourses('help', topics);
        expect(errored.reason).toBe('Error');
        expect(errored.topic).toBe('unmapped');
    });
});
