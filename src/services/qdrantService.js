/**
 * Qdrant Service
 * Handles vector database operations for document embeddings and semantic search
 */

const { QdrantClient } = require('@qdrant/js-client-rest');
const { EmbeddingsModule } = require('ubc-genai-toolkit-embeddings');
const { ChunkingModule } = require('ubc-genai-toolkit-chunking');
const { ConsoleLogger } = require('ubc-genai-toolkit-core');
const { randomUUID } = require('crypto');
const config = require('./config');
const llmService = require('./llm');

console.log('✅ Successfully imported embeddings library:', typeof EmbeddingsModule);

class QdrantService {
    constructor() {
        this.client = null;
        this.embeddings = null;
        this.chunker = null;
        this.collectionName = 'biocbot_documents';
        this.vectorSize = process.env.QDRANT_VECTOR_SIZE || 768; // Will be determined dynamically from embeddings
    }

    /**
     * Initialize Qdrant client and embeddings service
     */
    async initialize() {
        try {
            console.log('🔧 Initializing Qdrant service...');
            console.log('Environment variables for Qdrant:', {
                QDRANT_URL: process.env.QDRANT_URL,
                QDRANT_API_KEY: process.env.QDRANT_API_KEY ? 'SET' : 'NOT SET'
            });
            
            // Initialize Qdrant client using centralized configuration
            let vectorDBConfig;
            try {
                vectorDBConfig = config.getVectorDBConfig();
                console.log('Vector DB config:', vectorDBConfig);
            } catch (configError) {
                console.error('❌ Failed to get vector DB config:', configError);
                throw new Error(`Vector DB configuration error: ${configError.message}`);
            }
            
            const qdrantUrl = process.env.QDRANT_URL || `http://${vectorDBConfig.host}:${vectorDBConfig.port}`;
            const qdrantApiKey = process.env.QDRANT_API_KEY || 'super-secret-dev-key';
            
            console.log('Qdrant connection details:', {
                url: qdrantUrl,
                apiKey: qdrantApiKey ? 'SET' : 'NOT SET'
            });
            
            this.client = new QdrantClient({
                url: qdrantUrl,
                apiKey: qdrantApiKey
            });

            // Test Qdrant connection
            console.log('Testing Qdrant connection...');
            await this.client.getCollections();
            console.log('✅ Successfully connected to Qdrant');

            // Initialize embeddings service using centralized configuration
            console.log('Initializing embeddings service...');
            
            // Use the centralized LLM configuration from config service
            let llmConfig;
            try {
                llmConfig = config.getLLMConfig();
                console.log('LLM config retrieved:', {
                    provider: llmConfig.provider,
                    endpoint: llmConfig.endpoint || llmConfig.apiKey ? 'SET' : 'NOT SET',
                    model: llmConfig.defaultModel
                });
            } catch (configError) {
                console.error('❌ Failed to get LLM config:', configError);
                throw new Error(`LLM configuration error: ${configError.message}`);
            }
            
            const logger = new ConsoleLogger('biocbot-qdrant');
            
            // Add embedding-specific configuration
            const embeddingConfig = {
                providerType: 'ubc-genai-toolkit-llm',
                logger: logger,
                llmConfig: {
                    ...llmConfig,
                    embeddingModel: process.env.LLM_EMBEDDING_MODEL,
                    // // Drop unsupported parameters when talking to Ollama
                    litellm: {
                        drop_params: true
                    }
                }
            };

            console.log('Embedding config:', {
                providerType: embeddingConfig.providerType,
                embeddingModel: embeddingConfig.llmConfig.embeddingModel,
                llmProvider: embeddingConfig.llmConfig.provider
            });

            try {
                this.embeddings = await EmbeddingsModule.create(embeddingConfig);
                console.log('✅ Successfully initialized embeddings service');
            } catch (embeddingError) {
                console.error('❌ Failed to initialize embeddings service:', embeddingError);
                throw new Error(`Embeddings initialization error: ${embeddingError.message}`);
            }

            // Initialize chunking service using centralized configuration
            console.log('Initializing chunking service...');
            const chunkLogger = new ConsoleLogger('biocbot-chunking');
            
            // Use centralized configuration for chunking parameters
            const chunkingConfig = {
                strategy: process.env.CHUNK_STRATEGY || 'recursiveCharacter',
                defaultOptions: {
                    chunkSize: Number(process.env.CHUNK_SIZE) || 1000,
                    chunkOverlap: Number(process.env.CHUNK_OVERLAP) || 200,
                    minChunkSize: Number(process.env.CHUNK_MIN) || 100
                },
                logger: chunkLogger
            };
            
            this.chunker = new ChunkingModule(chunkingConfig);
            console.log(`✅ Successfully initialized chunking service (strategy=${this.chunker.getDefaultStrategyName()})`);

            // Set vector size based on the embedding model (more reliable than test embedding)
            console.log('Setting vector size based on embedding model...');
            const embeddingModel = process.env.LLM_EMBEDDING_MODEL;
            
            if (embeddingModel === 'text-embedding-3-small') {
                this.vectorSize = 1536;
                console.log(`🔍 Using text-embedding-3-small vector size: ${this.vectorSize}`);
            } else if (embeddingModel === 'text-embedding-ada-002') {
                this.vectorSize = 1536;
                console.log(`🔍 Using text-embedding-ada-002 vector size: ${this.vectorSize}`);
            } else if (embeddingModel === 'nomic-embed-text') {
                this.vectorSize = 768;
                console.log(`🔍 Using nomic-embed-text vector size: ${this.vectorSize}`);
            } else {
                // Fallback to environment variable or default
                this.vectorSize = process.env.QDRANT_VECTOR_SIZE || 768;
                console.log(`🔍 Using fallback vector size: ${this.vectorSize}`);
            }
            
            console.log(`✅ Successfully initialized embeddings service (vector size: ${this.vectorSize} dimensions)`);
            
            // Test embeddings service to verify it's working (but don't rely on it for vector size)
            console.log('Testing embeddings service...');
            try {
                const testEmbedding = await this.embeddings.embed('test');
                console.log(`🔍 Test embedding result:`, {
                    isArray: Array.isArray(testEmbedding),
                    length: testEmbedding ? testEmbedding.length : 'undefined',
                    type: typeof testEmbedding,
                    firstFew: testEmbedding ? testEmbedding.slice(0, 5) : 'undefined'
                });
                
                if (testEmbedding && Array.isArray(testEmbedding) && testEmbedding.length > 0) {
                    // Check if the embedding is nested (UBC GenAI Toolkit sometimes returns [[...]] instead of [...])
                    let actualEmbedding = testEmbedding;
                    if (testEmbedding.length === 1 && Array.isArray(testEmbedding[0])) {
                        console.log(`🔧 Detected nested array format, flattening...`);
                        actualEmbedding = testEmbedding[0];
                    }
                    
                    if (actualEmbedding.length === 1 && actualEmbedding[0] === 1) {
                        console.warn(`⚠️ Embeddings service returned fallback value [1] - this indicates an error in embedding generation`);
                        console.warn(`⚠️ The actual embedding generation may be failing silently`);
                    } else if (actualEmbedding.length === this.vectorSize) {
                        console.log(`✅ Embeddings service test successful (${actualEmbedding.length} dimensions)`);
                    } else {
                        console.warn(`⚠️ Embeddings service returned ${actualEmbedding.length} dimensions, expected ${this.vectorSize}`);
                    }
                } else {
                    console.warn(`⚠️ Embeddings service test returned unexpected result, but continuing with model-based vector size`);
                }
                
            } catch (embeddingTestError) {
                console.warn(`⚠️ Embeddings service test failed:`, embeddingTestError.message);
                console.log(`🔧 Continuing with model-based vector size: ${this.vectorSize}`);
            }

            // Ensure collection exists
            await this.ensureCollectionExists();

        } catch (error) {
            console.error('❌ Failed to initialize Qdrant service:', error);
            console.error('Error details:', {
                message: error.message,
                stack: error.stack,
                name: error.name
            });
            throw error;
        }
    }

    /**
     * Ensure the documents collection exists in Qdrant with correct vector dimensions
     */
    async ensureCollectionExists() {
        try {
            const collections = await this.client.getCollections();
            const collectionExists = collections.collections.some(
                col => col.name === this.collectionName
            );

            if (!collectionExists) {
                console.log(`Creating collection: ${this.collectionName}`);
                
                await this.client.createCollection(this.collectionName, {
                    vectors: {
                        size: this.vectorSize,
                        distance: 'Cosine'
                    }
                });

                console.log(`✅ Collection ${this.collectionName} created successfully`);
            } else {
                // Check if existing collection has correct vector dimensions
                const collectionInfo = await this.client.getCollection(this.collectionName);
                const existingVectorSize = collectionInfo.config.params.vectors.size;
                
                console.log(`🔍 Collection validation: existing=${existingVectorSize}, required=${this.vectorSize}`);
                
                if (existingVectorSize !== this.vectorSize) {
                    console.log(`⚠️ Vector dimension mismatch detected!`);
                    console.log(`   Existing collection: ${existingVectorSize} dimensions`);
                    console.log(`   Required: ${this.vectorSize} dimensions`);
                    console.log(`   Recreating collection with correct dimensions...`);
                    
                    // Delete the existing collection
                    await this.client.deleteCollection(this.collectionName);
                    console.log(`🗑️ Deleted existing collection`);
                    
                    // Create new collection with correct dimensions
                    await this.client.createCollection(this.collectionName, {
                        vectors: {
                            size: this.vectorSize,
                            distance: 'Cosine'
                        }
                    });
                    
                    console.log(`✅ Collection ${this.collectionName} recreated with correct dimensions`);
                } else {
                    console.log(`✅ Collection ${this.collectionName} already exists with correct dimensions`);
                }
            }
        } catch (error) {
            console.error('❌ Error ensuring collection exists:', error);
            throw error;
        }
    }

    /**
     * Process and store a document in Qdrant
     * @param {Object} documentData - Document information
     * @param {string} documentData.courseId - Course ID
     * @param {string} documentData.lectureName - Lecture/Unit name
     * @param {string} documentData.documentId - Document ID
     * @param {string} documentData.content - Document text content
     * @param {string} documentData.fileName - Original filename
     * @param {string} documentData.mimeType - File MIME type
     * @param {string} documentData.documentType - Document type for source attribution
     * @param {string} documentData.type - Specific document type
     * @returns {Promise<Object>} Result of document processing
     */
    async processAndStoreDocument(documentData) {
        try {
            console.log(`Processing document: ${documentData.fileName} for ${documentData.lectureName}`);
            console.log(`Document content length: ${documentData.content ? documentData.content.length : 'undefined'} characters`);
            
            // Validate input
            if (!documentData.content || typeof documentData.content !== 'string') {
                throw new Error('Invalid document content: content must be a non-empty string');
            }
            
            if (documentData.content.trim().length === 0) {
                throw new Error('Document content is empty or contains only whitespace');
            }

            // Sanitize content - remove any non-printable characters that might cause issues
            let sanitizedContent = documentData.content
                .replace(/[\x00-\x1F\x7F-\x9F]/g, '') // Remove control characters
                .replace(/\r\n/g, '\n') // Normalize line endings
                .replace(/\r/g, '\n'); // Convert remaining carriage returns
            
            // Check if content looks reasonable
            if (sanitizedContent.length < 10) {
                throw new Error('Document content is too short to process meaningfully');
            }
            
            // Check for suspicious patterns (like repeated characters)
            const suspiciousPattern = /(.)\1{10,}/; // Same character repeated 10+ times
            if (suspiciousPattern.test(sanitizedContent)) {
                console.warn('⚠️ Document content contains suspicious patterns (repeated characters)');
                // Clean up the suspicious patterns
                sanitizedContent = sanitizedContent.replace(/(.)\1{10,}/g, '$1$1$1');
            }
            
            console.log(`Sanitized content length: ${sanitizedContent.length} characters`);
            console.log(`Content preview: "${sanitizedContent.substring(0, 100)}..."`);

            // Chunk the document content using toolkit chunker
            if (!this.chunker) {
                throw new Error('Chunking service is not initialized');
            }

            const documents = [{
                content: sanitizedContent,
                metadata: { sourceId: documentData.documentId }
            }];

            const chunkResp = await this.chunker.chunkDocuments(documents, {});
            const sortedChunks = [...chunkResp.chunks].sort(
                (a, b) => a.metadata.chunkNumber - b.metadata.chunkNumber
            );
            const chunks = sortedChunks.map(c => c.text);
            const strategyUsed = chunkResp.strategy || this.chunker.getDefaultStrategyName();

            console.log(`Created ${chunks.length} chunks from document (strategy=${strategyUsed})`);
            
            if (chunks.length === 0) {
                throw new Error('No chunks were created from the document content');
            }

            // Generate embeddings for each chunk
            const embeddings = await this.generateEmbeddings(chunks);
            console.log(`Generated embeddings for ${embeddings.length} chunks`);
            
            if (embeddings.length === 0) {
                throw new Error('No embeddings were generated for the document chunks');
            }

            // Store chunks and embeddings in Qdrant
            const storedChunks = await this.storeChunks(documentData, chunks, embeddings, strategyUsed);
            console.log(`Stored ${storedChunks.length} chunks in Qdrant`);

            return {
                success: true,
                chunksProcessed: chunks.length,
                chunksStored: storedChunks.length,
                message: `Document processed and ${storedChunks.length} chunks stored successfully`
            };

        } catch (error) {
            console.error('❌ Error processing document:', error);
            console.error('Document data:', {
                fileName: documentData.fileName,
                lectureName: documentData.lectureName,
                contentLength: documentData.content ? documentData.content.length : 'undefined',
                contentPreview: documentData.content ? documentData.content.substring(0, 100) + '...' : 'undefined'
            });
            return {
                success: false,
                error: error.message
            };
        }
    }

    

    /**
     * Generate embeddings for text chunks
     * @param {Array<string>} chunks - Array of text chunks
     * @returns {Promise<Array<Array<number>>>} Array of embedding vectors
     */
    async generateEmbeddings(chunks) {
        try {
            if (!chunks || !Array.isArray(chunks) || chunks.length === 0) {
                throw new Error('Invalid chunks array provided to generateEmbeddings');
            }
            
            console.log(`Generating embeddings for ${chunks.length} chunks...`);
            const embeddings = [];
            
            for (let i = 0; i < chunks.length; i++) {
                const chunk = chunks[i];
                console.log(`Processing chunk ${i + 1}/${chunks.length}: "${chunk.substring(0, 50)}..."`);
                
                if (!chunk || typeof chunk !== 'string' || chunk.trim().length === 0) {
                    console.warn(`Skipping empty chunk ${i + 1}`);
                    continue;
                }
                
                try {
                    const embedding = await this.embeddings.embed(chunk);
                    
                    if (!embedding || !Array.isArray(embedding) || embedding.length === 0) {
                        throw new Error(`Invalid embedding returned for chunk ${i + 1}: ${typeof embedding}`);
                    }
                    
                    // The embed method returns an array, we want the first (and only) embedding
                    const embeddingVector = embedding[0];
                    if (!Array.isArray(embeddingVector)) {
                        throw new Error(`Embedding vector is not an array for chunk ${i + 1}: ${typeof embeddingVector}`);
                    }
                    
                    if (embeddingVector.length !== this.vectorSize) {
                        console.warn(`Warning: Chunk ${i + 1} embedding size (${embeddingVector.length}) doesn't match expected size (${this.vectorSize})`);
                    }
                    
                    embeddings.push(embeddingVector);
                    console.log(`✅ Generated embedding for chunk ${i + 1}: ${embeddingVector.length} dimensions`);
                    
                } catch (chunkError) {
                    console.error(`❌ Error generating embedding for chunk ${i + 1}:`, chunkError);
                    throw new Error(`Failed to generate embedding for chunk ${i + 1}: ${chunkError.message}`);
                }
            }
            
            console.log(`Successfully generated ${embeddings.length} embeddings`);
            return embeddings;
            
        } catch (error) {
            console.error('❌ Error generating embeddings:', error);
            throw error;
        }
    }

    /**
     * Store document chunks and embeddings in Qdrant
     * @param {Object} documentData - Document metadata
     * @param {Array<string>} chunks - Text chunks
     * @param {Array<Array<number>>} embeddings - Embedding vectors
     * @param {string} strategyUsed - Chunking strategy identifier
     * @returns {Promise<Array<Object>>} Array of stored chunk IDs
     */
    async storeChunks(documentData, chunks, embeddings, strategyUsed = 'toolkit') {
        try {
            // Ensure collection exists before storing chunks
            await this.ensureCollectionExists();
            
            const points = [];
            const storedChunks = [];

            for (let i = 0; i < chunks.length; i++) {
                const chunkId = randomUUID();
                
                const point = {
                    id: chunkId,
                    vector: embeddings[i],
                    payload: {
                        courseId: documentData.courseId,
                        lectureName: documentData.lectureName,
                        documentId: documentData.documentId,
                        fileName: documentData.fileName,
                        mimeType: documentData.mimeType,
                        documentType: documentData.documentType || 'unknown',
                        type: documentData.type || 'unknown',
                        chunkIndex: i,
                        totalChunks: chunks.length,
                        chunkText: chunks[i],
                        chunkLength: chunks[i].length,
                        strategyUsed: strategyUsed,
                        timestamp: new Date().toISOString()
                    }
                };

                points.push(point);
                storedChunks.push({ 
                    id: chunkId, 
                    chunkIndex: i,
                    documentId: documentData.documentId,
                    chunkText: chunks[i].substring(0, 50) + '...' // First 50 chars for reference
                });
            }

            // Upsert points to Qdrant
            await this.client.upsert(this.collectionName, {
                points: points
            });

            return storedChunks;

        } catch (error) {
            console.error('❌ Error storing chunks in Qdrant:', error);
            throw error;
        }
    }

    /**
     * Search for relevant document chunks using semantic similarity
     * @param {string} query - Search query text
     * @param {Object} filters - Optional filters for search
     * @param {number} limit - Maximum number of results to return
     * @returns {Promise<Array<Object>>} Array of search results
     */
    async searchDocuments(query, filters = {}, limit = 10) {
        try {
            console.log(`Searching for: "${query}"`);

            // Ensure collection exists before searching
            await this.ensureCollectionExists();

            // Generate embedding for the search query and normalize to number[]
            const rawEmbedding = await this.embeddings.embed(query);
            let queryVector = rawEmbedding;
            if (Array.isArray(rawEmbedding)) {
                // If provider returns a batch ([[...]]), unwrap the first vector
                if (rawEmbedding.length > 0 && Array.isArray(rawEmbedding[0])) {
                    if (rawEmbedding.length !== 1) {
                        console.warn(`Embed returned ${rawEmbedding.length} vectors for a single query; using the first`);
                    }
                    queryVector = rawEmbedding[0];
                }
            } else if (rawEmbedding && typeof rawEmbedding === 'object') {
                // Handle possible object wrappers
                if (Array.isArray(rawEmbedding.embedding)) {
                    queryVector = rawEmbedding.embedding;
                } else if (Array.isArray(rawEmbedding.data) && Array.isArray(rawEmbedding.data[0])) {
                    queryVector = rawEmbedding.data[0];
                }
            }

            if (!Array.isArray(queryVector) || !queryVector.every(n => typeof n === 'number')) {
                throw new Error('Invalid query embedding shape: expected number[]');
            }
            if (this.vectorSize && queryVector.length !== this.vectorSize) {
                console.warn(`Query embedding size (${queryVector.length}) does not match expected collection size (${this.vectorSize})`);
            }

            // Build search parameters
            const searchParams = {
                vector: queryVector,
                limit: limit,
                with_payload: true,
                with_vector: false
            };

            // Add filters if provided
            if (filters.courseId) {
                searchParams.filter = {
                    must: [
                        {
                            key: 'courseId',
                            match: { value: filters.courseId }
                        }
                    ]
                };
            }

            if (filters.lectureName) {
                if (!searchParams.filter) {
                    searchParams.filter = { must: [] };
                }
                searchParams.filter.must.push({
                    key: 'lectureName',
                    match: { value: filters.lectureName }
                });
            }

            // Support array of lecture names (any-of match)
            if (filters.lectureNames && Array.isArray(filters.lectureNames) && filters.lectureNames.length > 0) {
                if (!searchParams.filter) {
                    searchParams.filter = { must: [] };
                }
                searchParams.filter.must.push({
                    key: 'lectureName',
                    match: { any: filters.lectureNames }
                });
            }

            // Perform search
            const searchResults = await this.client.search(
                this.collectionName,
                searchParams
            );

            console.log(`Found ${searchResults.length} relevant chunks`);

            // Transform results to a more useful format
            const transformedResults = searchResults.map(result => ({
                id: result.id,
                score: result.score,
                courseId: result.payload.courseId,
                lectureName: result.payload.lectureName,
                documentId: result.payload.documentId,
                fileName: result.payload.fileName,
                documentType: result.payload.documentType,
                type: result.payload.type,
                chunkText: result.payload.chunkText,
                chunkIndex: result.payload.chunkIndex,
                timestamp: result.payload.timestamp
            }));

            return transformedResults;

        } catch (error) {
            console.error('❌ Error searching documents:', error);
            throw error;
        }
    }

    /**
     * Delete all chunks for a specific document
     * @param {string} documentId - Document ID to delete
     * @param {string} [courseId] - Optional course ID to scope the deletion
     * @returns {Promise<Object>} Result of deletion
     */
    async deleteDocumentChunks(documentId, courseId = null) {
        try {
            console.log(`Deleting chunks for document: ${documentId}${courseId ? ` in course: ${courseId}` : ''}`);

            const filter = {
                must: [
                    {
                        key: 'documentId',
                        match: { value: documentId }
                    }
                ]
            };

            // Add courseId scope if provided
            if (courseId) {
                filter.must.push({
                    key: 'courseId',
                    match: { value: courseId }
                });
            }

            let totalDeleted = 0;
            let nextOffset = null;
            let loopCount = 0;
            const MAX_LOOPS = 100; // Safety break

            console.log('Starting deletion loop...');

            do {
                loopCount++;
                
                // Find chunks for this document (page by page)
                const scrollResult = await this.client.scroll(this.collectionName, {
                    filter: filter,
                    limit: 1000, // Processing in batches of 1000
                    with_payload: false,
                    offset: nextOffset
                });

                const points = scrollResult.points || [];
                nextOffset = scrollResult.next_page_offset;

                if (points.length === 0) {
                    if (loopCount === 1) {
                        return {
                            success: true,
                            message: 'No chunks found for document',
                            deletedCount: 0
                        };
                    }
                    break; // No more points
                }

                // Delete the chunks in this batch
                const chunkIds = points.map(point => point.id);
                await this.client.delete(this.collectionName, {
                    points: chunkIds
                });
                
                totalDeleted += chunkIds.length;
                console.log(`Batch ${loopCount}: Deleted ${chunkIds.length} chunks. Total so far: ${totalDeleted}`);

                if (loopCount >= MAX_LOOPS) {
                    console.warn(`Safety break triggered in deletion loop after ${MAX_LOOPS} iterations`);
                    break;
                }

            } while (nextOffset);

            console.log(`Successfully deleted total ${totalDeleted} chunks for document: ${documentId}`);

            return {
                success: true,
                message: `Deleted ${totalDeleted} chunks successfully`,
                deletedCount: totalDeleted
            };

        } catch (error) {
            console.error('❌ Error deleting document chunks:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get collection statistics
     * @returns {Promise<Object>} Collection statistics
     */
    async getCollectionStats() {
        try {
            // Ensure service is initialized
            if (!this.client) {
                await this.initialize();
            }

            const collectionInfo = await this.client.getCollection(this.collectionName);
            const collectionStats = await this.client.getCollection(this.collectionName);
            
            return {
                name: collectionInfo.name,
                vectorSize: collectionInfo.config.params.vectors.size,
                distance: collectionInfo.config.params.vectors.distance,
                pointsCount: collectionStats.points_count,
                segmentsCount: collectionStats.segments_count,
                status: collectionInfo.status
            };
        } catch (error) {
            console.error('❌ Error getting collection stats:', error);
            throw error;
        }
    }

    /**
     * Delete the entire collection
     * @returns {Promise<Object>} Result of collection deletion
     */
    async deleteCollection() {
        try {
            console.log(`Deleting entire collection: ${this.collectionName}`);

            // Ensure service is initialized
            if (!this.client) {
                await this.initialize();
            }

            // Check if collection exists
            const collections = await this.client.getCollections();
            const collectionExists = collections.collections.some(
                col => col.name === this.collectionName
            );

            if (!collectionExists) {
                return {
                    success: true,
                    message: 'Collection does not exist',
                    deletedCount: 0
                };
            }

            // Delete the collection
            await this.client.deleteCollection(this.collectionName);
            console.log(`✅ Successfully deleted collection: ${this.collectionName}`);

            return {
                success: true,
                message: `Collection ${this.collectionName} deleted successfully`,
                deletedCount: 'all'
            };

        } catch (error) {
            console.error('❌ Error deleting collection:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }

    /**
     * Get service status and LLM integration information
     * @returns {Object} Service status information
     */
    getStatus() {
        return {
            qdrant: {
                isConnected: !!this.client,
                collectionName: this.collectionName,
                vectorSize: this.vectorSize
            },
            embeddings: {
                isInitialized: !!this.embeddings,
                provider: llmService.getProviderName(),
                isReady: llmService.isReady()
            },
            chunking: {
                isInitialized: !!this.chunker,
                strategy: this.chunker ? this.chunker.getDefaultStrategyName() : null
            },
            timestamp: new Date().toISOString()
        };
    }

}

module.exports = QdrantService;
