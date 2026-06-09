/**
 * LLM Service
 * Integrates with UBC GenAI Toolkit for chat functionality
 * Supports multiple providers: Ollama, OpenAI, UBC LLM Sandbox
 */

const { LLMModule } = require('ubc-genai-toolkit-llm');
const config = require('./config');
const prompts = require('./prompts');

const ALLOWED_LLM_MODELS = ['gpt-4.1-mini', 'gpt-5-nano', 'gpt-5.4-nano'];
const ALLOWED_REASONING_EFFORTS = ['minimal', 'low', 'medium', 'high'];
const MODEL_SETTINGS_TTL_MS = 30 * 1000; // Re-read at most every 30 seconds

class LLMService {
    constructor() {
        this.llm = null;
        this.isInitialized = false;
        this.llmConfig = null;
        this._dbAccessor = null;
        this._modelSettingsCache = null;
        this._modelSettingsCacheAt = 0;

        console.log(`🔧 Creating LLM service...`);
    }

    /**
     * Provide a function returning the active MongoDB instance so the
     * service can look up the current LLM settings on demand.
     */
    setDbAccessor(fn) {
        this._dbAccessor = typeof fn === 'function' ? fn : null;
    }

    invalidateModelSettingsCache() {
        this._modelSettingsCache = null;
        this._modelSettingsCacheAt = 0;
    }

    /**
     * Look up the configured model + reasoning effort from MongoDB.
     * Falls back to the env-configured default if no override is stored.
     */
    async _getModelSettings() {
        const now = Date.now();
        if (this._modelSettingsCache && (now - this._modelSettingsCacheAt) < MODEL_SETTINGS_TTL_MS) {
            return this._modelSettingsCache;
        }

        const envDefault = (this.llmConfig && this.llmConfig.defaultModel) || process.env.OPENAI_MODEL || 'gpt-4.1-mini';
        let model = ALLOWED_LLM_MODELS.includes(envDefault) ? envDefault : 'gpt-4.1-mini';
        let reasoningEffort = 'minimal';

        try {
            const db = this._dbAccessor ? this._dbAccessor() : null;
            if (db) {
                const doc = await db.collection('settings').findOne({ _id: 'llm' });
                if (doc) {
                    if (ALLOWED_LLM_MODELS.includes(doc.model)) {
                        model = doc.model;
                    }
                    if (ALLOWED_REASONING_EFFORTS.includes(doc.reasoningEffort)) {
                        reasoningEffort = doc.reasoningEffort;
                    }
                }
            }
        } catch (error) {
            console.warn('⚠️ Could not load LLM settings from DB, using defaults:', error.message);
        }

        this._modelSettingsCache = { model, reasoningEffort };
        this._modelSettingsCacheAt = now;
        return this._modelSettingsCache;
    }

    _isGpt5Family(model) {
        return typeof model === 'string' && model.startsWith('gpt-5');
    }

    /**
     * Different gpt-5 variants accept different reasoning_effort values.
     * Returns the requested effort if supported, otherwise the closest fallback.
     * gpt-5-nano:    minimal, low, medium, high
     * gpt-5.4-nano:  none,    low, medium, high, xhigh   (no "minimal")
     */
    _coerceReasoningEffort(model, requested) {
        const supportedByModel = {
            'gpt-5-nano': ['minimal', 'low', 'medium', 'high'],
            'gpt-5.4-nano': ['none', 'low', 'medium', 'high', 'xhigh']
        };
        const supported = supportedByModel[model];
        if (!supported) return requested; // Unknown model — pass through
        if (supported.includes(requested)) return requested;
        // Map requested → closest supported value
        if (requested === 'minimal' && supported.includes('low')) return 'low';
        if (requested === 'xhigh' && supported.includes('high')) return 'high';
        return supported[0]; // Fallback to first supported
    }

    /**
     * Adjust an outgoing LLM options object based on the configured model.
     * - Forces the active model.
     * - For gpt-5 family models, drops temperature (unsupported), translates
     *   max_tokens to max_completion_tokens, and adds reasoning_effort.
     */
    async _applyModelOptions(options = {}) {
        const settings = await this._getModelSettings();
        const result = { ...options, model: settings.model };

        if (this._isGpt5Family(settings.model)) {
            delete result.temperature;
            if (result.max_tokens !== undefined) {
                result.max_completion_tokens = result.max_tokens;
                delete result.max_tokens;
            }
            if (result.maxTokens !== undefined) {
                // Toolkit-known key, also translate for safety
                result.max_completion_tokens = result.max_completion_tokens || result.maxTokens;
                delete result.maxTokens;
            }
            // Reasoning models consume tokens internally before producing output.
            // Enforce a floor so small caller-supplied budgets don't get fully eaten
            // by reasoning, leaving an empty/truncated response.
            const REASONING_FLOOR = 2000;
            if (!result.max_completion_tokens || result.max_completion_tokens < REASONING_FLOOR) {
                result.max_completion_tokens = REASONING_FLOOR;
            }
            const requestedEffort = settings.reasoningEffort || 'minimal';
            const coercedEffort = this._coerceReasoningEffort(settings.model, requestedEffort);
            if (coercedEffort !== requestedEffort) {
                console.warn(`⚠️ [LLM] reasoning_effort "${requestedEffort}" not supported by ${settings.model}; coerced to "${coercedEffort}"`);
            }
            result.reasoning_effort = coercedEffort;
        }

        return result;
    }

    /**
     * Initialize the LLM service instance
     * @returns {Promise<LLMService>} The initialized service
     */
    static async create() {
        const service = new LLMService();
        await service._performInitialization();
        return service;
    }

    /**
     * Perform LLM initialization
     * @returns {Promise<void>}
     * @private
     */
    async _performInitialization() {
        try {
            // Test stub mode: skip real provider wiring entirely so the e2e
            // suite can run without hitting ChatGPT. Gated by an env flag the
            // Playwright web server sets.
            if (process.env.BIOCBOT_TEST_LLM_STUB === '1') {
                const { getLLMStub } = require('./llmStub');
                this.llm = getLLMStub();
                this.llmConfig = { provider: 'test-stub', defaultModel: 'gpt-4.1-mini' };
                this.isInitialized = true;
                console.log('🧪 LLM service initialized with test stub (BIOCBOT_TEST_LLM_STUB=1)');
                return;
            }

            // Get configuration for current environment
            this.llmConfig = config.getLLMConfig();

            console.log(`🚀 Initializing LLM service with provider: ${this.llmConfig.provider}`);

            // Initialize UBC GenAI Toolkit with the configured provider
            this.llm = new LLMModule(this.llmConfig);
            this.isInitialized = true;

            console.log(`✅ LLM service initialized successfully`);

        } catch (error) {
            console.error('❌ Failed to initialize LLM service:', error.message);
            this.isInitialized = false;
            this.llm = null;
            throw error;
        }
    }

    /**
     * Send a single message to the LLM
     * @param {string} message - The message to send
     * @param {Object} options - Additional options for the LLM
     * @returns {Promise<Object>} LLM response
     */
    async sendMessage(message, options = {}) {
        try {
            // Initialize LLM service on first use
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for first use...`);
                await this._performInitialization();
            }

            console.log(`📤 Sending message to LLM: "${message.substring(0, 50)}..."`);

            // Set default options for BiocBot context - provider-aware
            const defaultOptions = {
                systemPrompt: this.getSystemPrompt(),
                temperature: 0.1,
                ...this._getProviderSpecificOptions(),
                ...options
            };
            const finalOptions = await this._applyModelOptions(defaultOptions);
            console.log('🔍 [LLM_OPTIONS] Final options:', finalOptions);

            const response = await this.llm.sendMessage(message, finalOptions);

            console.log(`✅ LLM response received (${response.content.length} characters)`);
            return response;

        } catch (error) {
            console.error('❌ Error sending message to LLM:', error.message);
            throw error;
        }
    }

    /**
     * Describe an image using the configured multi-modal model.
     *
     * Used by the document-parsing module's `imageDescriber` hook to turn
     * images embedded in PowerPoint slides (charts, screenshots, photos) into
     * searchable text. Routes through the UBC GenAI Toolkit LLM module's
     * multi-modal message support, so it works with whichever provider/model is
     * configured (e.g. gpt-5-nano).
     *
     * @param {Buffer|string} imageData - Raw image bytes (Buffer) or base64 string.
     * @param {string} mimeType - Image MIME type, e.g. 'image/png'.
     * @param {Object} [context] - Optional context, e.g. { slideNumber }.
     * @returns {Promise<string>} A textual description (empty string if none).
     */
    async describeImage(imageData, mimeType, context = {}) {
        if (!this.isInitialized) {
            await this._performInitialization();
        }

        const base64 = Buffer.isBuffer(imageData)
            ? imageData.toString('base64')
            : imageData;

        const slideInfo = context.slideNumber
            ? ` (from slide ${context.slideNumber})`
            : '';
        const prompt =
            `You are extracting content from a lecture slide${slideInfo} so it can be used as ` +
            `searchable course notes. Describe this image factually and concisely. ` +
            `If it is a chart, graph, or diagram, summarize what it shows and any key data, ` +
            `labels, or trends. If it contains text (e.g. a screenshot), transcribe that text. ` +
            `If you identify topics or concepts, include only biochemistry topics. If there ` +
            `are no biochemistry topics, do not mention that fact; just describe/transcribe ` +
            `any visible factual content, or return nothing if there is no useful content. ` +
            `Do not add commentary or preamble. If the image is purely decorative and carries ` +
            `no information, respond with nothing.`;

        // Reuse provider/model handling (gpt-5 family param translation, etc.).
        const baseOptions = {
            ...this._getProviderSpecificOptions(),
            temperature: 0,
            max_tokens: 1000,
        };
        const finalOptions = await this._applyModelOptions(baseOptions);

        const response = await this.llm.sendConversation(
            [
                {
                    role: 'user',
                    content: prompt,
                    images: [{ data: base64, mimeType }],
                },
            ],
            finalOptions
        );

        const content = (response && response.content) ? response.content.trim() : '';
        if (/^(nothing|no)\b.*\b(biochemistry|biochemical)\b/i.test(content)) {
            return '';
        }
        if (/\bno biochemistry topics?\b/i.test(content)) {
            return content
                .replace(/\.?\s*no biochemistry topics?[^.]*\./ig, '')
                .replace(/\bThere are no biochemistry topics?[^.]*\./ig, '')
                .trim();
        }

        return content;
    }

    /**
     * Get provider-specific options based on the current LLM provider
     * @returns {Object} Provider-specific options
     * @private
     */
    _getProviderSpecificOptions() {
        const provider = this.llmConfig?.provider;

        switch (provider) {
            case 'ollama':
                return {
                    num_ctx: 2048  // Ollama-specific context window parameter
                };
            case 'openai':
                return {
                    // OpenAI doesn't use num_ctx, uses max_tokens instead
                    max_tokens: 32768
                };
            case 'ubc-llm-sandbox':
                return {
                    num_ctx: 2048  // UBC sandbox likely uses Ollama-compatible parameters
                };
            default:
                console.warn(`⚠️ Unknown provider: ${provider}, using default options`);
                return {};
        }
    }

    /**
     * Create a conversation for multi-turn chat
     * @returns {Object} Conversation object
     */
    async createConversation() {
        try {
            // Initialize LLM service on first use
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for first use...`);
                await this._performInitialization();
            }

            const conversation = this.llm.createConversation();

            // Set initial system prompt for BiocBot
            conversation.addMessage('system', this.getSystemPrompt());

            console.log('💬 Conversation created successfully');
            return conversation;

        } catch (error) {
            console.error('❌ Error creating conversation:', error.message);
            throw error;
        }
    }

    /**
     * Send a message in conversation context
     * @param {Object} conversation - The conversation object
     * @param {string} message - The user message
     * @param {Object} options - Additional options
     * @returns {Promise<Object>} LLM response
     */
    async sendConversationMessage(conversation, message, options = {}) {
        try {
            // Initialize LLM service on first use
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for first use...`);
                await this._performInitialization();
            }

            // Add user message to conversation
            conversation.addMessage('user', message);

            // Set default options for BiocBot - provider-aware
            const defaultOptions = {
                temperature: 0.1,
                ...this._getProviderSpecificOptions(),
                ...options
            };
            const finalOptions = await this._applyModelOptions(defaultOptions);

            // Send message and get response
            const response = await conversation.send(finalOptions);

            console.log(`💬 Conversation response received (${response.content.length} characters)`);
            return response;

        } catch (error) {
            console.error('❌ Error in conversation:', error.message);
            throw error;
        }
    }

    /**
     * Get available models from the current provider
     * @returns {Promise<Array>} List of available models
     */
    async getAvailableModels() {
        try {
            // Initialize LLM service on first use
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for first use...`);
                await this._performInitialization();
            }

            const models = await this.llm.getAvailableModels();
            console.log(`📋 Available models: ${models.length} found`);
            return models;
        } catch (error) {
            console.error('❌ Error getting available models:', error.message);
            throw error;
        }
    }

    /**
     * Get the current provider name
     * @returns {string} Provider name
     */
    getProviderName() {
        if (!this.isInitialized) {
            return 'Not initialized';
        }
        return this.llm.getProviderName();
    }

    /**
     * Get system prompt for BiocBot
     * @returns {string} System prompt
     */
    getSystemPrompt() {
        return prompts.BASE_SYSTEM_PROMPT;
    }

    /**
     * Test the LLM connection
     * @returns {Promise<boolean>} True if connection is working
     */
    async testConnection() {
        try {
            console.log('🔍 Testing LLM connection...');

            const response = await this.sendMessage('Hello, this is a connection test.');

            if (response && response.content) {
                console.log('✅ LLM connection test successful');
                return true;
            } else {
                console.log('❌ LLM connection test failed - no response content');
                return false;
            }

        } catch (error) {
            console.error('❌ LLM connection test failed:', error.message);
            return false;
        }
    }

    /**
     * Check if the LLM service is ready to use
     * @returns {boolean} True if service is initialized and ready
     */
    isReady() {
        return this.isInitialized && !!this.llm;
    }

    /**
     * Get service status information
     * @returns {Object} Service status
     */
    getStatus() {
        return {
            provider: this.getProviderName(),
            isConnected: this.isInitialized && !!this.llm,
            isInitialized: this.isInitialized,
            timestamp: new Date().toISOString()
        };
    }

    /**
     * Generate assessment questions based on course material content
     * @param {string} questionType - Type of question to generate ('true-false', 'multiple-choice', 'short-answer')
     * @param {string} courseMaterialContent - The course material text content
     * @param {string} unitName - Name of the unit (e.g., 'Unit 1')
     * @param {string} learningObjectives - Learning objectives for the unit (optional)
     * @param {Object} customPrompts - Optional course-specific custom prompts
     * @returns {Promise<Object>} Generated question content
     */
    async generateAssessmentQuestion(questionType, courseMaterialContent, unitName, learningObjectives = '', customPrompts = null) {
        try {
            // Initialize LLM service on first use if not already initialized
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for question generation...`);
                await this._performInitialization();
            }

            console.log(`🤖 Generating ${questionType} question for ${unitName}...`);
            if (customPrompts) {
                console.log(`📝 Using custom question generation prompts for this course`);
            }

            // Create specific prompt based on question type (use custom prompts if provided)
            const prompt = this.createQuestionGenerationPrompt(questionType, courseMaterialContent, unitName, learningObjectives, customPrompts);

            // Create system prompt - use custom if provided, otherwise use template function
            let systemPrompt;
            if (customPrompts && customPrompts.systemPrompt) {
                // Replace placeholder in custom system prompt
                systemPrompt = customPrompts.systemPrompt.replace(/\{\{questionType\}\}/g, questionType);
            } else {
                systemPrompt = prompts.createQuestionGenerationSystemPrompt(
                    questionType,
                    this.getJsonSchemaForQuestionType(questionType)
                );
            }

            // Set specific options for question generation - provider-aware
            // Use higher temperature (0.7) for more creative question generation
            // Note: timeout is handled via Promise.race() below, not as an LLM option
            const generationOptions = await this._applyModelOptions({
                temperature: 0.7,
                systemPrompt: systemPrompt,
                ...this._getProviderSpecificOptions()
            });

            // Log prompt length and content for debugging
            console.log(`🤖 [LLM_REQUEST] Sending prompt to LLM (${prompt.length} chars)`);
            console.log('🤖 [LLM_PROMPT] Full prompt being sent:', prompt);

            // Create a promise that rejects after the timeout
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('LLM request timed out after 2 minutes')), 120000);
            });

            // Race between the LLM response and the timeout
            console.log('📝 Generating question...');
            console.log('⏳ This may take up to 2 minutes for complex questions...');

            const response = await Promise.race([
                this.llm.sendMessage(prompt, generationOptions),
                timeoutPromise
            ]);

            console.log('🤖 [LLM_RESPONSE] Raw response from LLM:', response);

            if (!response || !response.content) {
                throw new Error('No response content received from LLM');
            }

            console.log('🤖 [LLM_CONTENT] Response content:', response.content);

            // Parse the response to extract question components
            const parsedQuestion = this.parseGeneratedQuestion(response.content, questionType);
            console.log('🤖 [LLM_PARSED] Parsed question:', parsedQuestion);

            console.log(`✅ Question generated successfully for ${unitName}`);
            return parsedQuestion;

        } catch (error) {
            console.error('❌ Error generating assessment question:', error.message);
            throw error;
        }
    }

    /**
     * Evaluate a student's answer to a question
     * @param {string} question - The question text
     * @param {string} studentAnswer - The student's answer
     * @param {string} expectedAnswer - The expected/correct answer
     * @param {string} questionType - Type of question (short-answer, etc.)
     * @param {string} studentName - The name of the student (optional, defaults to 'Student')
     * @returns {Promise<Object>} Evaluation result { correct: boolean, feedback: string }
     */
    async evaluateStudentAnswer(question, studentAnswer, expectedAnswer, questionType, studentName = 'Student') {
        try {
            if (!this.isInitialized) {
                await this._performInitialization();
            }

            console.log('📝 Evaluating student answer...');

            const prompt = `You are an automated grader for a biology course.
Question: ${question}
Expected Answer: ${expectedAnswer}
Student Answer: ${studentAnswer}

Evaluate the answer from ${studentName} based on the expected answer.
Address the student directly by name (e.g. "${studentName}, your answer is...").
For short answer questions, the answer doesn't need to be identical, but must capture the key concepts.
Be lenient with spelling if the meaning is clear.

Return ONLY a JSON object with the following structure:
{
    "correct": boolean,
    "feedback": "Brief explanation addressed to ${studentName} of why it is correct or incorrect"
}`;

            const response = await this.sendMessage(prompt, {
                temperature: 0.1,
                response_format: { type: "json_object" } // For providers that support it
            });

            console.log('🤖 [EVALUATION] Raw response:', response.content);

            // Parse JSON response
            let result;
            try {
                const jsonStart = response.content.indexOf('{');
                const jsonEnd = response.content.lastIndexOf('}') + 1;
                if (jsonStart !== -1 && jsonEnd !== 0) {
                    const jsonStr = response.content.substring(jsonStart, jsonEnd);
                    result = JSON.parse(jsonStr);
                } else {
                    throw new Error('No JSON found');
                }
            } catch (e) {
                console.error('Failed to parse evaluation JSON:', e);
                // Fallback parsing
                const isCorrect = response.content.toLowerCase().includes('correct": true');
                result = {
                    correct: isCorrect,
                    feedback: response.content
                };
            }

            return result;

        } catch (error) {
            console.error('❌ Error evaluating answer:', error);
            throw error;
        }
    }

    /**
     * Analyze a conversation for mental health concerns
     * @param {Array} conversationHistory - Array of {role, content} messages
     * @param {string} detectionPrompt - The detection system prompt
     * @returns {Promise<Object>} { concernLevel: string, reason: string }
     */
    async analyzeMentalHealth(conversationHistory, detectionPrompt) {
        try {
            if (!this.isInitialized) {
                await this._performInitialization();
            }

            // Serialize the conversation into a single string for the user message
            const conversationText = conversationHistory
                .map(msg => `[${msg.role}]: ${msg.content}`)
                .join('\n\n');

            const mhOptions = await this._applyModelOptions({
                systemPrompt: detectionPrompt,
                temperature: 0.1,
                max_tokens: 256
            });
            const response = await this.llm.sendMessage(conversationText, mhOptions);

            if (!response || !response.content) {
                return { concernLevel: 'no concern', reason: 'No response from detection model' };
            }

            // Parse JSON from response
            try {
                const jsonStart = response.content.indexOf('{');
                const jsonEnd = response.content.lastIndexOf('}') + 1;
                if (jsonStart !== -1 && jsonEnd > 0) {
                    const parsed = JSON.parse(response.content.substring(jsonStart, jsonEnd));
                    return {
                        concernLevel: parsed.concernLevel || 'no concern',
                        reason: parsed.reason || ''
                    };
                }
            } catch (e) {
                console.error('Failed to parse mental health detection JSON:', e);
            }

            return { concernLevel: 'no concern', reason: 'Failed to parse detection response' };

        } catch (error) {
            console.error('Error in mental health analysis:', error.message);
            return { concernLevel: 'no concern', reason: 'Detection error: ' + error.message };
        }
    }

    /**
     * Regenerate an assessment question with instructor feedback
     * @param {string} questionType - Type of question to regenerate
     * @param {string} courseMaterialContent - Course material content
     * @param {string} unitName - Unit name
     * @param {string} learningObjectives - Learning objectives (optional)
     * @param {Object} previousQuestion - The previous question that needs improvement
     * @param {string} feedback - Instructor feedback on what to improve
     * @returns {Promise<Object>} Generated question object
     */
    async regenerateAssessmentQuestion(questionType, courseMaterialContent, unitName, learningObjectives = '', previousQuestion, feedback) {
        try {
            // Initialize LLM service on first use if not already initialized
            if (!this.isInitialized) {
                console.log(`🔄 Initializing LLM service for question regeneration...`);
                await this._performInitialization();
            }

            console.log(`🔄 Regenerating ${questionType} question for ${unitName} based on feedback...`);

            // Create regeneration prompt with feedback
            const prompt = this.createQuestionRegenerationPrompt(
                questionType,
                courseMaterialContent,
                unitName,
                learningObjectives,
                previousQuestion,
                feedback
            );

            // Create system prompt using template function
            const systemPrompt = prompts.createQuestionGenerationSystemPrompt(
                questionType,
                this.getJsonSchemaForQuestionType(questionType)
            );

            // Set specific options for question regeneration - provider-aware
            // Use lower temperature (0.5) for more focused improvements based on feedback
            // Note: timeout is handled via Promise.race() below, not as an LLM option
            const generationOptions = await this._applyModelOptions({
                temperature: 0.5,  // Lower temperature for more focused regeneration
                systemPrompt: systemPrompt,
                ...this._getProviderSpecificOptions()
            });

            // Log prompt length and content for debugging
            console.log(`🔄 [LLM_REGENERATE] Sending regeneration prompt to LLM (${prompt.length} chars)`);
            console.log('🔄 [LLM_REGENERATE_PROMPT] Full prompt being sent:', prompt);

            // Create a promise that rejects after the timeout
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => reject(new Error('LLM regeneration request timed out after 2 minutes')), 120000);
            });

            // Race between the LLM response and the timeout
            console.log('🔄 Regenerating question based on feedback...');
            console.log('⏳ This may take up to 2 minutes...');

            const response = await Promise.race([
                this.llm.sendMessage(prompt, generationOptions),
                timeoutPromise
            ]);

            console.log('🔄 [LLM_REGENERATE_RESPONSE] Raw response from LLM:', response);

            if (!response || !response.content) {
                throw new Error('No response content received from LLM during regeneration');
            }

            console.log('🔄 [LLM_REGENERATE_CONTENT] Response content:', response.content);

            // Parse the response to extract question components
            const parsedQuestion = this.parseGeneratedQuestion(response.content, questionType);
            console.log('🔄 [LLM_REGENERATE_PARSED] Parsed regenerated question:', parsedQuestion);

            console.log(`✅ Question regenerated successfully for ${unitName}`);
            return parsedQuestion;

        } catch (error) {
            console.error('❌ Error regenerating assessment question:', error.message);
            throw error;
        }
    }

    /**
     * Create a specific prompt for question generation based on type
     * @param {string} questionType - Type of question to generate
     * @param {string} courseMaterialContent - Course material content
     * @param {string} unitName - Unit name
     * @param {string} learningObjectives - Learning objectives (optional)
     * @param {Object} customPrompts - Optional custom prompts with templates
     * @returns {string} Formatted prompt for the LLM
     */
    createQuestionGenerationPrompt(questionType, courseMaterialContent, unitName, learningObjectives = '', customPrompts = null) {
        // If custom prompts are provided, use them with placeholder substitution
        if (customPrompts) {
            let template;
            switch (questionType) {
                case 'true-false':
                    template = customPrompts.trueFalse;
                    break;
                case 'multiple-choice':
                    template = customPrompts.multipleChoice;
                    break;
                case 'short-answer':
                    template = customPrompts.shortAnswer;
                    break;
                default:
                    throw new Error(`Unsupported question type: ${questionType}`);
            }
            
            // Replace placeholders with actual values
            if (template) {
                return template
                    .replace(/\{\{learningObjectives\}\}/g, learningObjectives || '')
                    .replace(/\{\{courseMaterial\}\}/g, courseMaterialContent)
                    .replace(/\{\{unitName\}\}/g, unitName)
                    .replace(/\{\{questionType\}\}/g, questionType);
            }
        }
        
        // Fall back to default prompts
        switch (questionType) {
            case 'true-false':
                return prompts.QUESTION_GENERATION_PROMPT_TEMPLATE.trueFalse(learningObjectives, courseMaterialContent, unitName);
            case 'multiple-choice':
                return prompts.QUESTION_GENERATION_PROMPT_TEMPLATE.multipleChoice(learningObjectives, courseMaterialContent, unitName);
            case 'short-answer':
                return prompts.QUESTION_GENERATION_PROMPT_TEMPLATE.shortAnswer(learningObjectives, courseMaterialContent, unitName);
            default:
                throw new Error(`Unsupported question type: ${questionType}`);
        }
    }

    /**
     * Create a regeneration prompt based on instructor feedback
     * @param {string} questionType - Type of question to regenerate
     * @param {string} courseMaterialContent - Course material content
     * @param {string} unitName - Unit name
     * @param {string} learningObjectives - Learning objectives (optional)
     * @param {Object} previousQuestion - The previous question that needs improvement
     * @param {string} feedback - Instructor feedback on what to improve
     * @returns {string} Formatted regeneration prompt for the LLM
     */
    createQuestionRegenerationPrompt(questionType, courseMaterialContent, unitName, learningObjectives = '', previousQuestion, feedback) {
        // Base regeneration prompt template
        let regenerationPrompt = `You are tasked with regenerating an assessment question based on instructor feedback.

ORIGINAL QUESTION TO IMPROVE:
Question Type: ${questionType}
Question: ${previousQuestion.question || 'No question text'}`;

        // Add question-specific details
        if (questionType === 'multiple-choice' && previousQuestion.options) {
            regenerationPrompt += `
Options:
A) ${previousQuestion.options.A || 'No option A'}
B) ${previousQuestion.options.B || 'No option B'}
C) ${previousQuestion.options.C || 'No option C'}
D) ${previousQuestion.options.D || 'No option D'}
Correct Answer: ${previousQuestion.answer || 'No answer'}`;
        } else if (questionType === 'true-false') {
            regenerationPrompt += `
Correct Answer: ${previousQuestion.answer || 'No answer'}`;
        } else if (questionType === 'short-answer') {
            regenerationPrompt += `
Expected Answer: ${previousQuestion.answer || 'No answer'}`;
        }

        regenerationPrompt += `

INSTRUCTOR FEEDBACK:
${feedback}

COURSE MATERIAL CONTEXT:
${courseMaterialContent}

UNIT: ${unitName}`;

        if (learningObjectives) {
            regenerationPrompt += `

LEARNING OBJECTIVES:
${learningObjectives}`;
        }

        regenerationPrompt += `

INSTRUCTIONS:
Please create a NEW and IMPROVED question that addresses the instructor's feedback while:
1. Staying relevant to the course material and learning objectives
2. Maintaining the same question type (${questionType})
3. Being clearly different from the original question
4. Incorporating the specific improvements requested in the feedback
5. Ensuring the question is pedagogically sound and appropriate for the unit

Generate a completely new question that addresses the feedback, don't just modify the existing one.`;

        return regenerationPrompt;
    }


    /**
     * Get JSON schema for specific question type
     * @param {string} questionType - Type of question
     * @returns {string} JSON schema string
     */
    getJsonSchemaForQuestionType(questionType) {
        switch (questionType) {
            case 'true-false':
                return `{
    "type": "true-false",
    "question": "string - the question text",
    "correctAnswer": "boolean - true or false",
    "explanation": "string - explanation of the correct answer"
}`;
            case 'multiple-choice':
                return `{
    "type": "multiple-choice",
    "question": "string - the question text",
    "options": {
        "A": "string - option A",
        "B": "string - option B",
        "C": "string - option C",
        "D": "string - option D"
    },
    "correctAnswer": "string - letter of correct answer (A, B, C, or D)",
    "explanation": "string - explanation of the correct answer"
}`;
            case 'short-answer':
                return `{
    "type": "short-answer",
    "question": "string - the question text",
    "expectedAnswer": "string - model answer",
    "keyPoints": "array - key points for the answer",
    "explanation": "string - explanation of the answer"
}`;
            default:
                return '{}';
        }
    }

    /**
     * Parse the LLM response to extract question components
     * @param {string} responseContent - Raw response from LLM
     * @param {string} questionType - Type of question
     * @returns {Object} Parsed question object
     */
    parseGeneratedQuestion(responseContent, questionType) {
        try {
            console.log('🔍 [PARSE] Starting to parse response content:', responseContent);

            // Try to parse the response as JSON
            let jsonResponse;
            try {
                // Find the first '{' and last '}' to handle any extra text before or after the JSON
                const jsonStart = responseContent.indexOf('{');
                const jsonEnd = responseContent.lastIndexOf('}') + 1;
                if (jsonStart === -1 || jsonEnd === 0) {
                    throw new Error('No JSON object found in response');
                }
                const jsonStr = responseContent.substring(jsonStart, jsonEnd);
                jsonResponse = JSON.parse(jsonStr);
            } catch (jsonError) {
                console.error('❌ [PARSE] Failed to parse JSON:', jsonError);
                throw new Error('Invalid JSON format in response');
            }

            console.log('🔍 [PARSE] Parsed JSON response:', jsonResponse);

            // Validate the parsed response based on question type
            if (!jsonResponse.type || !jsonResponse.question || !jsonResponse.explanation) {
                throw new Error('Missing required fields in response');
            }

            // Ensure the response type matches the expected type
            if (jsonResponse.type !== questionType) {
                console.warn(`⚠️ [PARSE] Question type mismatch. Expected: ${questionType}, Got: ${jsonResponse.type}`);
            }

            const parsed = {
                type: questionType,
                question: jsonResponse.question,
                explanation: jsonResponse.explanation
            };

            // Handle type-specific fields
            switch (questionType) {
                case 'true-false':
                    if (typeof jsonResponse.correctAnswer !== 'boolean') {
                        throw new Error('True/False question must have a boolean correctAnswer');
                    }
                    parsed.answer = jsonResponse.correctAnswer.toString();
                    break;

                case 'multiple-choice':
                    if (!jsonResponse.options || !jsonResponse.correctAnswer) {
                        throw new Error('Multiple choice question must have options and correctAnswer');
                    }
                    // Validate options
                    const options = jsonResponse.options;
                    const hasAllOptions = ['A', 'B', 'C', 'D'].every(opt => options[opt]);
                    if (!hasAllOptions) {
                        throw new Error('Multiple choice question must have all options (A, B, C, D)');
                    }
                    parsed.options = options;
                    parsed.answer = jsonResponse.correctAnswer.toUpperCase();
                    break;

                case 'short-answer':
                    if (!jsonResponse.expectedAnswer) {
                        throw new Error('Short answer question must have an expectedAnswer');
                    }
                    parsed.answer = jsonResponse.expectedAnswer;
                    parsed.expectedAnswer = jsonResponse.expectedAnswer;
                    if (jsonResponse.keyPoints) {
                        parsed.keyPoints = jsonResponse.keyPoints;
                    }
                    break;

                default:
                    console.warn(`⚠️ [PARSE] Unknown question type: ${questionType}`);
            }

            console.log('✅ [PARSE] Successfully parsed question:', parsed);
            return parsed;

        } catch (error) {
            console.error('❌ Error parsing generated question:', error);
            // Return a fallback structure
            return {
                type: questionType,
                question: 'Error parsing generated question. Please try again.',
                answer: questionType === 'true-false' ? 'true' : questionType === 'multiple-choice' ? 'A' : 'Please review the generated content.',
                options: questionType === 'multiple-choice' ? { A: 'Option A', B: 'Option B', C: 'Option C', D: 'Option D' } : {},
                explanation: 'Question generation completed but parsing failed. Please review and edit the content.'
            };
        }
    }
}

// Export the class instead of an instance
module.exports = LLMService;
