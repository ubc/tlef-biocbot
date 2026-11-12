const { LANES } = require('./llmLanes');

/**
 * Tracker Service
 * Analyzes student messages to detect struggle and identify topics.
 */

class TrackerService {
    constructor(llmService) {
        this.llmService = llmService;
    }

    /**
     * The instructions for the struggle check, without the student's message.
     * The old chat path appends the message to this; the agent path sends this
     * as the tracker agent's system prompt and the message as JSON.
     * @param {string} courseId
     * @param {string} unitName
     * @param {Array<string>} approvedTopics - Already-cleaned approved topics
     * @returns {string}
     */
    static buildAnalysisPrompt(courseId, unitName, approvedTopics = []) {
        return `You are analyzing student struggle in a biochemistry chat.

Context: Course ${courseId}, Unit ${unitName}
Approved Course Topics:
${approvedTopics.length > 0 ? approvedTopics.map((topic, index) => `${index + 1}. ${topic}`).join('\n') : 'No approved topics configured'}

Tasks:
1. Detect if the student is struggling (confusion, frustration, or explicit lack of understanding).
2. Identify the raw topic from the student's language.
3. Map that raw topic to the closest approved topic using semantic similarity.
4. If no approved topic is a reasonable semantic match, use "unmapped".
5. Return JSON only.

Output JSON schema:
{
  "isStruggling": boolean,
  "rawTopic": "string",
  "mappedTopic": "string (must be one approved topic or 'unmapped')",
  "matchConfidence": "number 0-1",
  "reason": "string"
}

Rules:
- Never invent a mapped topic outside the approved list.
- If semantic match confidence is below 0.55, use "unmapped".
- If message is not a struggle, mappedTopic should still be "unmapped" unless there is a clear mapped struggle topic.`;
    }

    /**
     * Turn the model's parsed answer into the analysis the route uses: a topic
     * counts only if it is on the approved list with enough confidence.
     * @param {Object} result - The parsed JSON from the model
     * @param {Array<string>} approvedTopics - Already-cleaned approved topics
     * @returns {Object} { topic, rawTopic, isMapped, matchConfidence, isStruggling, reason }
     */
    static normalizeAnalysis(result, approvedTopics = []) {
        const mappedTopic = typeof result.mappedTopic === 'string' ? result.mappedTopic.trim() : '';
        const approvedTopicMap = new Map(
            approvedTopics.map((topic) => [topic.toLowerCase(), topic])
        );
        const matchedApprovedTopic = approvedTopicMap.get(mappedTopic.toLowerCase()) || '';
        const matchConfidence = typeof result.matchConfidence === 'number' ? result.matchConfidence : 0;
        const isMapped = !!matchedApprovedTopic && matchConfidence >= 0.55;

        return {
            topic: isMapped ? matchedApprovedTopic : 'unmapped',
            rawTopic: result.rawTopic || '',
            isMapped,
            matchConfidence,
            isStruggling: result.isStruggling || false,
            reason: result.reason || ''
        };
    }

    /**
     * Analyze a student message for struggle and topic
     * @param {string} message - The student's message
     * @param {string} courseId - Course context
     * @param {string} unitName - Unit context
     * @param {Array<string>} approvedTopics - Instructor-approved per-course topics
     * @returns {Promise<Object>} Analysis result
     */
    async analyzeMessage(message, courseId, unitName, approvedTopics = []) {
        try {
            const cleanApprovedTopics = Array.isArray(approvedTopics)
                ? approvedTopics.filter(topic => typeof topic === 'string' && topic.trim())
                : [];

            const prompt = `
You are analyzing student struggle in a biochemistry chat.

Student Message: "${message}"
Context: Course ${courseId}, Unit ${unitName}
Approved Course Topics:
${cleanApprovedTopics.length > 0 ? cleanApprovedTopics.map((topic, index) => `${index + 1}. ${topic}`).join('\n') : 'No approved topics configured'}

Tasks:
1. Detect if the student is struggling (confusion, frustration, or explicit lack of understanding).
2. Identify the raw topic from the student's language.
3. Map that raw topic to the closest approved topic using semantic similarity.
4. If no approved topic is a reasonable semantic match, use "unmapped".
5. Return JSON only.

Output JSON schema:
{
  "isStruggling": boolean,
  "rawTopic": "string",
  "mappedTopic": "string (must be one approved topic or 'unmapped')",
  "matchConfidence": "number 0-1",
  "reason": "string"
}

Rules:
- Never invent a mapped topic outside the approved list.
- If semantic match confidence is below 0.55, use "unmapped".
- If message is not a struggle, mappedTopic should still be "unmapped" unless there is a clear mapped struggle topic.
            `;

            const response = await this.llmService.sendMessage(prompt, {
                lane: LANES.BACKEND,
                temperature: 0.1,
                maxTokens: 220,
                systemPrompt: "You are an empathetic analyst detecting student struggle. Output JSON only."
            });

            const rawContent = (response.content || '').replace(/```json/g, '').replace(/```/g, '').trim();
            if (!rawContent) {
                console.warn('⚠️ [TRACKER] Empty LLM response — likely token budget consumed by reasoning. Treating as no struggle.');
                return { isStruggling: false, topic: 'unmapped', isMapped: false, reason: 'Empty LLM response' };
            }

            // Extract the JSON object even if the model wrapped it in extra prose
            const jsonStart = rawContent.indexOf('{');
            const jsonEnd = rawContent.lastIndexOf('}') + 1;
            const content = (jsonStart !== -1 && jsonEnd > 0) ? rawContent.substring(jsonStart, jsonEnd) : rawContent;
            const result = JSON.parse(content);
            
            return TrackerService.normalizeAnalysis(result, cleanApprovedTopics);

        } catch (error) {
            console.error('❌ [TRACKER] Error analyzing message:', error);
            // Fail gracefully - assume no struggle
            return { isStruggling: false, topic: 'unmapped', isMapped: false, reason: 'Error' };
        }
    }

    /**
     * Analyze a student message for struggle across MULTIPLE courses at once
     * (used by the Super Course chat, which spans several courses' material).
     *
     * Unlike analyzeMessage, there is no single course context, so the struggle
     * must be attributed back to the course that owns the matched approved topic.
     * Candidates are presented to the model as a numbered list, each tagged with
     * its course, and the model returns the matched candidate index — this keeps
     * attribution unambiguous even when two courses share a topic name.
     *
     * @param {string} message - The student's message
     * @param {Array<{courseId: string, courseName: string, approvedTopics: Array<string>}>} courseTopics
     * @returns {Promise<Object>} { isStruggling, rawTopic, topic, courseId, courseName, isMapped, matchConfidence, reason }
     */
    async analyzeMessageAcrossCourses(message, courseTopics = []) {
        const noStruggle = { isStruggling: false, rawTopic: '', topic: 'unmapped', courseId: null, courseName: null, isMapped: false, matchConfidence: 0, reason: '' };

        try {
            // Flatten every course's approved topics into a single indexed candidate
            // list. Each candidate remembers which course it came from so we can
            // attribute the struggle once the model picks one.
            const candidates = [];
            for (const entry of Array.isArray(courseTopics) ? courseTopics : []) {
                if (!entry || !entry.courseId || !Array.isArray(entry.approvedTopics)) continue;
                const courseName = typeof entry.courseName === 'string' && entry.courseName.trim()
                    ? entry.courseName.trim()
                    : entry.courseId;
                for (const rawTopic of entry.approvedTopics) {
                    if (typeof rawTopic !== 'string' || !rawTopic.trim()) continue;
                    candidates.push({ courseId: entry.courseId, courseName, topic: rawTopic.trim() });
                }
            }

            if (candidates.length === 0) {
                return { ...noStruggle, reason: 'No approved topics across courses' };
            }

            console.log(`🕵️ [TRACKER_DEBUG] Cross-course analyze for: "${message}" (${candidates.length} candidate topics)`);

            const candidateList = candidates
                .map((c, index) => `${index}. "${c.topic}" — ${c.courseName}`)
                .join('\n');

            const prompt = `
You are analyzing student struggle in a cross-course biochemistry "Super Chat" that spans several courses.

Student Message: "${message}"

Candidate approved topics (each belongs to one course):
${candidateList}

Tasks:
1. Detect if the student is struggling (confusion, frustration, or explicit lack of understanding).
2. Identify the raw topic from the student's language.
3. Map that raw topic to the single best-matching candidate above using semantic similarity, and return its index.
4. If no candidate is a reasonable semantic match, return -1.
5. Return JSON only.

Output JSON schema:
{
  "isStruggling": boolean,
  "rawTopic": "string",
  "matchedIndex": "number (the candidate index, or -1 if none match)",
  "matchConfidence": "number 0-1",
  "reason": "string"
}

Rules:
- matchedIndex must be a valid index from the list above, or -1.
- If semantic match confidence is below 0.55, return matchedIndex -1.
- Pick only ONE candidate — the closest match.`;

            const response = await this.llmService.sendMessage(prompt, {
                lane: LANES.BACKEND,
                temperature: 0.1,
                maxTokens: 220,
                systemPrompt: "You are an empathetic analyst detecting student struggle across courses. Output JSON only."
            });

            const rawContent = (response.content || '').replace(/```json/g, '').replace(/```/g, '').trim();
            if (!rawContent) {
                console.warn('⚠️ [TRACKER] Empty cross-course LLM response. Treating as no struggle.');
                return { ...noStruggle, reason: 'Empty LLM response' };
            }

            const jsonStart = rawContent.indexOf('{');
            const jsonEnd = rawContent.lastIndexOf('}') + 1;
            const content = (jsonStart !== -1 && jsonEnd > 0) ? rawContent.substring(jsonStart, jsonEnd) : rawContent;
            const result = JSON.parse(content);

            const matchedIndex = Number.isInteger(result.matchedIndex) ? result.matchedIndex : -1;
            const matchConfidence = typeof result.matchConfidence === 'number' ? result.matchConfidence : 0;
            const matched = matchedIndex >= 0 && matchedIndex < candidates.length ? candidates[matchedIndex] : null;
            const isMapped = !!matched && matchConfidence >= 0.55;

            return {
                isStruggling: result.isStruggling || false,
                rawTopic: result.rawTopic || '',
                topic: isMapped ? matched.topic : 'unmapped',
                courseId: isMapped ? matched.courseId : null,
                courseName: isMapped ? matched.courseName : null,
                isMapped,
                matchConfidence,
                reason: result.reason || ''
            };

        } catch (error) {
            console.error('❌ [TRACKER] Error analyzing message across courses:', error);
            return { ...noStruggle, reason: 'Error' };
        }
    }
}

module.exports = TrackerService;
