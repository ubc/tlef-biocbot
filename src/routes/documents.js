const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Import the Document model and Course model
const DocumentModel = require('../models/Document');
const CourseModel = require('../models/Course');
const QdrantService = require('../services/qdrantService');
const { QUESTION_EXTRACTION_SYSTEM_PROMPT, buildQuestionExtractionPrompt } = require('../services/prompts');
const { encodingForModel } = require('js-tiktoken');

// Token encoder using cl100k_base (same as tokencounter.space)
const tokenEncoder = encodingForModel('gpt-4o');

function inferExtensionFromMimeType(mimeType) {
    switch ((mimeType || '').toLowerCase()) {
        case 'application/pdf':
            return '.pdf';
        case 'text/markdown':
            return '.md';
        case 'application/msword':
            return '.doc';
        case 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            return '.docx';
        case 'application/rtf':
            return '.rtf';
        case 'text/plain':
            return '.txt';
        default:
            return '';
    }
}

function resolveDownloadFilename(document) {
    const fallbackName = `document-${document.documentId || Date.now()}`;
    const rawOriginal = (document.originalName || '').trim();
    const rawFile = (document.filename || '').trim();
    const preferredName = rawOriginal || rawFile || fallbackName;
    let safeName = path.basename(preferredName).replace(/[\r\n]/g, '');

    if (!path.extname(safeName)) {
        if (rawFile && path.extname(rawFile)) {
            safeName = path.basename(rawFile).replace(/[\r\n]/g, '');
        } else {
            safeName += inferExtensionFromMimeType(document.mimeType);
        }
    }

    return safeName || `${fallbackName}.txt`;
}

function setAttachmentHeaders(res, filename) {
    const encodedName = encodeURIComponent(filename);
    const asciiFallback = filename.replace(/[^\x20-\x7E]/g, '_').replace(/"/g, '');
    res.setHeader(
        'Content-Disposition',
        `attachment; filename="${asciiFallback}"; filename*=UTF-8''${encodedName}`
    );
}

function getStoredFileBuffer(fileData) {
    if (!fileData) {
        return null;
    }

    if (Buffer.isBuffer(fileData)) {
        return fileData;
    }

    if (fileData.buffer) {
        return Buffer.from(fileData.buffer);
    }

    if (Array.isArray(fileData.data)) {
        return Buffer.from(fileData.data);
    }

    if (typeof fileData === 'string') {
        return Buffer.from(fileData, 'base64');
    }

    return null;
}

/**
 * Count tokens accurately using tiktoken (cl100k_base encoding)
 * @param {string} text - Text to count tokens for
 * @returns {number} Token count
 */
function countTokens(text) {
    return tokenEncoder.encode(text).length;
}

// Import UBC GenAI Toolkit document parsing module
const { DocumentParsingModule } = require('ubc-genai-toolkit-document-parsing');
const { ConsoleLogger } = require('ubc-genai-toolkit-core');

// Initialize document parsing module
const docParser = new DocumentParsingModule({
    logger: new ConsoleLogger(),
    debug: true
});

// Initialize Qdrant service
const qdrantService = new QdrantService();

// Initialize Qdrant service when the module loads
(async () => {
    try {
        await qdrantService.initialize();
        console.log('✅ Qdrant service initialized in documents route');
    } catch (error) {
        console.error('❌ Failed to initialize Qdrant service in documents route:', error);
    }
})();

// Configure multer for file uploads
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 50 * 1024 * 1024, // 50MB limit (increased from 10MB)
    },
    fileFilter: (req, file, cb) => {
        // Allow common document types
        const allowedTypes = [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain',
            'text/markdown',
            'application/rtf'
        ];
        
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PDF, DOC, DOCX, TXT, MD, and RTF files are allowed.'), false);
        }
    }
});

// Middleware for JSON parsing
router.use(express.json({ limit: '50mb' }));

/**
 * POST /api/documents/upload
 * Upload a file document
 */
router.post('/upload', upload.single('file'), async (req, res) => {
    try {
        const { courseId, lectureName, documentType, instructorId } = req.body;
        const file = req.file;
        
        // Validate required fields
        if (!courseId || !lectureName || !documentType || !instructorId || !file) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, documentType, instructorId, file'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Determine filename
        let filename = file.originalname;
        if (req.body.title) {
            // If title is provided, use it. Append extension if it doesn't have one and we can determine it from original
            filename = req.body.title;
            // Optional: preserve extension if the strict title doesn't include it. 
            // In this case, the frontend strict titles (*Lecture Notes - Week 1) don't have extensions.
            // But for file download/viewing, extension might be useful. 
            // However, the user specifically wants the DISPLAY name to be the strict title.
            // Let's stick to the title as provided for the "filename" field which is likely used for display.
            // The 'originalName' usually tracks the actual uploaded file. But DocumentModel might use filename for display.
        }

        // Prepare document data
        const documentData = {
            courseId,
            lectureName,
            documentType,
            instructorId,
            contentType: 'file',
            filename: filename,       // Use the determined filename (strict title or original)
            originalName: file.originalname, // Keep the actual original filename for reference
            fileData: file.buffer,
            mimeType: file.mimetype,
            size: file.size,
            content: '', // Initialize content field for extracted text
            metadata: {
                description: req.body.description || '',
                tags: req.body.tags ? req.body.tags.split(',').map(tag => tag.trim()) : [],
                learningObjectives: req.body.learningObjectives ? req.body.learningObjectives.split(',').map(obj => obj.trim()) : []
            }
        };
        
        // Note: The DocumentModel.uploadDocument() function will automatically add the 'type' field
        // based on the documentType using the mapContentTypeToDocumentType function
        
        // Extract text content from file using UBC GenAI Toolkit BEFORE creating the document
        let textContent = '';
        try {
            if (file.mimetype === 'text/plain' || file.mimetype === 'text/markdown') {
                // Handle text files directly
                textContent = file.buffer.toString('utf8');
                console.log(`✅ Text content extracted from ${file.mimetype}: ${textContent.length} characters`);
            } else {
                // Use UBC GenAI Toolkit for PDF, DOCX, and other document types
                console.log(`🔄 Extracting text from ${file.mimetype} using UBC GenAI Toolkit...`);
                console.log(`📊 File size: ${(file.size / 1024 / 1024).toFixed(2)} MB`);
                
                // Create a temporary file path for the parser
                const tempFilePath = `/tmp/${Date.now()}_${file.originalname}`;
                
                try {
                    // Write buffer to temporary file
                    console.log(`💾 Writing file to temporary path: ${tempFilePath}`);
                    fs.writeFileSync(tempFilePath, file.buffer);
                    console.log(`✅ File written to temp path successfully`);
                    
                    // Parse document to extract text with timeout
                    console.log(`🔍 Starting document parsing...`);
                    const parsePromise = docParser.parse({ filePath: tempFilePath }, 'text');
                    const timeoutPromise = new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('Document parsing timed out after 60 seconds')), 60000)
                    );
                    
                    const parseResult = await Promise.race([parsePromise, timeoutPromise]);
                    
                    if (parseResult && parseResult.content) {
                        textContent = parseResult.content;
                        console.log(`✅ Text content extracted from ${file.mimetype}: ${textContent.length} characters`);
                        console.log(`📝 Content preview: ${textContent.substring(0, 200)}...`);
                    } else {
                        throw new Error('Failed to extract text content from document');
                    }
                } finally {
                    // Clean up temporary file
                    try {
                        fs.unlinkSync(tempFilePath);
                        console.log(`🧹 Temporary file cleaned up: ${tempFilePath}`);
                    } catch (cleanupError) {
                        console.warn(`⚠️ Failed to clean up temp file: ${cleanupError.message}`);
                    }
                }
            }
        } catch (parseError) {
            console.error(`❌ Error extracting text from ${file.mimetype}:`, parseError);
            // Continue without text extraction - document will still be stored in MongoDB
        }
        
        // Update documentData with extracted content
        if (textContent) {
            documentData.content = textContent;
            console.log(`📝 Document will be created with ${textContent.length} characters of extracted text`);
        }
        
        // Upload document to MongoDB with content already included
        const result = await DocumentModel.uploadDocument(db, documentData);
        
        // Also add document reference to the course structure
        const courseResult = await CourseModel.addDocumentToUnit(db, courseId, lectureName, {
            documentId: result.documentId,
            documentType: documentType,
            filename: documentData.filename, // Use the same filename as stored in DocumentModel
            originalName: file.originalname,
            mimeType: file.mimetype,
            size: file.size,
            status: 'uploaded',
            metadata: documentData.metadata
        }, instructorId);
        
        if (!courseResult.success) {
            console.warn('Warning: Document uploaded but failed to link to course structure:', courseResult.error);
        }
        
        // Process document through Qdrant for vector search
        let qdrantResult = null;
        if (textContent) {
            try {
                // Ensure Qdrant service is initialized
                if (!qdrantService.embeddings) {
                    console.log('Initializing Qdrant service before processing document...');
                    await qdrantService.initialize();
                }
                
                // Try to process through Qdrant for vector search
            console.log(`Processing document through Qdrant: ${file.originalname} -> ${documentData.filename}`);
            qdrantResult = await qdrantService.processAndStoreDocument({
                courseId,
                lectureName,
                documentId: result.documentId,
                content: textContent,
                fileName: documentData.filename, // Use the strict title/filename
                mimeType: file.mimetype,
                documentType: documentType,
                type: result.type
            });
                
                if (qdrantResult.success) {
                    console.log(`✅ Document processed and stored in Qdrant: ${qdrantResult.chunksStored} chunks`);
                } else {
                    console.warn(`⚠️ Qdrant processing failed: ${qdrantResult.error}`);
                }
            } catch (qdrantError) {
                console.warn('Warning: Document uploaded but Qdrant processing failed:', qdrantError.message);
            }
        }
        
        console.log(`Document uploaded: ${file.originalname} for ${lectureName}`);
        
        res.json({
            success: true,
            message: 'Document uploaded successfully!',
            data: {
                documentId: result.documentId,
                filename: documentData.filename, // Return the stored filename (strict title)
                size: file.size,
                uploadDate: result.uploadDate,
                linkedToCourse: courseResult.success,
                qdrantProcessed: qdrantResult ? qdrantResult.success : false,
                chunksStored: qdrantResult ? qdrantResult.chunksStored : 0
            }
        });
        
    } catch (error) {
        console.error('Error uploading document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while uploading document',
            error: error.message
        });
    }
});

/**
 * POST /api/documents/text
 * Submit text content as a document
 */
router.post('/text', async (req, res) => {
    try {
        const { courseId, lectureName, documentType, instructorId, content, title, description } = req.body;
        
        // Validate required fields
        if (!courseId || !lectureName || !documentType || !instructorId || !content || !title) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, lectureName, documentType, instructorId, content, title'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Prepare document data
        const documentData = {
            courseId,
            lectureName,
            documentType,
            instructorId,
            contentType: 'text',
            filename: `${title}.txt`,
            originalName: title,
            content: content,
            mimeType: 'text/plain',
            size: Buffer.byteLength(content, 'utf8'),
            metadata: {
                description: description || '',
                tags: req.body.tags ? req.body.tags.split(',').map(tag => tag.trim()) : [],
                learningObjectives: req.body.learningObjectives ? req.body.learningObjectives.split(',').map(obj => obj.trim()) : []
            }
        };
        
        // Upload document to MongoDB
        const result = await DocumentModel.uploadDocument(db, documentData);
        
        // Also add document reference to the course structure
        const courseResult = await CourseModel.addDocumentToUnit(db, courseId, lectureName, {
            documentId: result.documentId,
            documentType: documentType,
            filename: documentData.filename,
            originalName: documentData.originalName,
            mimeType: documentData.mimeType,
            size: documentData.size,
            status: 'uploaded',
            metadata: documentData.metadata
        }, instructorId);
        
        if (!courseResult.success) {
            console.warn('Warning: Text document uploaded but failed to link to course structure:', courseResult.error);
        }
        
        // Process text document through Qdrant for vector search
        let qdrantResult = null;
        try {
            // Ensure Qdrant service is initialized
            if (!qdrantService.embeddings) {
                console.log('Initializing Qdrant service before processing document...');
                await qdrantService.initialize();
            }
            
            console.log(`Processing text document through Qdrant: ${title}`);
            qdrantResult = await qdrantService.processAndStoreDocument({
                courseId,
                lectureName,
                documentId: result.documentId,
                content: content,
                fileName: title,
                mimeType: 'text/plain',
                documentType: documentType,
                type: result.type
            });
            
            if (qdrantResult.success) {
                console.log(`✅ Text document processed and stored in Qdrant: ${qdrantResult.chunksStored} chunks`);
            } else {
                console.warn(`⚠️ Qdrant processing failed: ${qdrantResult.error}`);
            }
        } catch (qdrantError) {
            console.warn('Warning: Text document uploaded but Qdrant processing failed:', qdrantError.message);
        }
        
        console.log(`Text document submitted: ${title} for ${lectureName}`);
        
        res.json({
            success: true,
            message: 'Text document submitted successfully!',
            data: {
                documentId: result.documentId,
                title: title,
                size: result.size,
                uploadDate: result.uploadDate,
                linkedToCourse: courseResult.success,
                qdrantProcessed: qdrantResult ? qdrantResult.success : false,
                chunksStored: qdrantResult ? qdrantResult.chunksStored : 0
            }
        });
        
    } catch (error) {
        console.error('Error submitting text document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while submitting text document',
            error: error.message
        });
    }
});

/**
 * GET /api/documents/lecture
 * Get all documents for a specific lecture/unit
 */
router.get('/lecture', async (req, res) => {
    try {
        const { courseId, lectureName } = req.query;
        
        if (!courseId || !lectureName) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameters: courseId, lectureName'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Fetch documents from MongoDB
        const documents = await DocumentModel.getDocumentsForLecture(db, courseId, lectureName);
        
        // Remove file data from response for security
        const safeDocuments = documents.map(doc => ({
            ...doc,
            fileData: undefined // Don't send binary data in response
        }));
        
        res.json({
            success: true,
            data: {
                courseId,
                lectureName,
                documents: safeDocuments,
                count: safeDocuments.length
            }
        });
        
    } catch (error) {
        console.error('Error fetching documents:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching documents'
        });
    }
});

/**
 * GET /api/documents/stats
 * Get document statistics for a course
 */
router.get('/stats', async (req, res) => {
    try {
        const { courseId } = req.query;
        
        if (!courseId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: courseId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Fetch document statistics from MongoDB
        const stats = await DocumentModel.getDocumentStats(db, courseId);
        
        res.json({
            success: true,
            data: {
                courseId,
                stats
            }
        });
        
    } catch (error) {
        console.error('Error fetching document stats:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while fetching document stats'
        });
    }
});

/**
 * GET /api/documents/:documentId/download
 * Download the original source document for instructors/TAs
 */
router.get('/:documentId/download', async (req, res) => {
    try {
        const { documentId } = req.params;

        if (!documentId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: documentId'
            });
        }

        const user = req.user;
        if (!user || !['instructor', 'ta'].includes(user.role)) {
            return res.status(403).json({
                success: false,
                message: 'Only instructors and TAs can download course materials from this page'
            });
        }

        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }

        const document = await DocumentModel.getDocumentById(db, documentId);
        if (!document) {
            return res.status(404).json({
                success: false,
                message: 'Document not found'
            });
        }

        let hasAccess = await CourseModel.userHasCourseAccess(db, document.courseId, user.userId, user.role);

        if (hasAccess && user.role === 'ta') {
            hasAccess = await CourseModel.checkTAPermission(db, document.courseId, user.userId, 'courses');
        }

        if (!hasAccess) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to download this document'
            });
        }

        const downloadFilename = resolveDownloadFilename(document);
        setAttachmentHeaders(res, downloadFilename);

        const isFileDocument = document.contentType === 'file' || (!!document.fileData && document.contentType !== 'text');

        if (isFileDocument) {
            const payload = getStoredFileBuffer(document.fileData);

            if (!payload) {
                return res.status(500).json({
                    success: false,
                    message: 'Stored file data is invalid'
                });
            }

            res.setHeader('Content-Type', document.mimeType || 'application/octet-stream');
            return res.send(payload);
        }

        const textContent = typeof document.content === 'string' ? document.content : '';
        res.setHeader('Content-Type', `${document.mimeType || 'text/plain'}; charset=utf-8`);
        return res.send(textContent);
    } catch (error) {
        console.error('Error downloading document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while downloading document'
        });
    }
});

/**
 * GET /api/documents/:documentId
 * Get a specific document by ID
 */
router.get('/:documentId', async (req, res) => {
    try {
        const { documentId } = req.params;
        
        if (!documentId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required parameter: documentId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Get the document from the database
        const document = await DocumentModel.getDocumentById(db, documentId);
        if (!document) {
            return res.status(404).json({
                success: false,
                message: 'Document not found'
            });
        }
        
        console.log(`Document retrieved: ${documentId}`);
        
        res.json({
            success: true,
            message: 'Document retrieved successfully!',
            data: document
        });
        
    } catch (error) {
        console.error('Error retrieving document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while retrieving document'
        });
    }
});

/**
 * DELETE /api/documents/:documentId
 * Delete a specific document
 */
router.delete('/:documentId', async (req, res) => {
    try {
        const { documentId } = req.params;
        const { instructorId } = req.body;
        
        if (!documentId || !instructorId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: documentId, instructorId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Verify the document exists
        const document = await DocumentModel.getDocumentById(db, documentId);
        if (!document) {
            return res.status(404).json({
                success: false,
                message: 'Document not found'
            });
        }
        
        // Check if instructor has access to the course (not just document ownership)
        // This allows any instructor with course access to delete documents
        const hasAccess = await CourseModel.userHasCourseAccess(db, document.courseId, instructorId, 'instructor');
        if (!hasAccess) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to delete this document'
            });
        }
        
        // Delete the document from the documents collection
        const result = await DocumentModel.deleteDocument(db, documentId);
        
        // DELETE FROM ALL THREE STORAGE SYSTEMS: MongoDB documents, course structure, and Qdrant
        let qdrantDeleted = false;
        let qdrantDeletedCount = 0;
        
        if (result.deletedCount > 0) {
            console.log(`Document deleted from documents collection, now cleaning up course structure and Qdrant...`);
            
            // Step 1: Delete from course structure
            const coursesCollection = db.collection('courses');
            const courseDeleteResult = await coursesCollection.updateOne(
                { courseId: document.courseId },
                { 
                    $pull: { 
                        'lectures.$[].documents': { documentId: documentId } 
                    }
                }
            );
            
            console.log(`Course delete result:`, courseDeleteResult);
            
            // Step 2: Delete from Qdrant vector database
            try {
                // Ensure Qdrant service is initialized
                if (!qdrantService.client) {
                    await qdrantService.initialize();
                }
                
                const qdrantResult = await qdrantService.deleteDocumentChunks(documentId, document.courseId);
                if (qdrantResult.success) {
                    qdrantDeleted = true;
                    qdrantDeletedCount = qdrantResult.deletedCount;
                    console.log(`✅ Deleted ${qdrantDeletedCount} chunks from Qdrant for document ${documentId}`);
                } else {
                    console.warn(`⚠️ Failed to delete chunks from Qdrant: ${qdrantResult.error}`);
                }
            } catch (qdrantError) {
                console.warn(`⚠️ Error deleting from Qdrant (non-fatal):`, qdrantError.message);
                // Don't fail the entire deletion if Qdrant cleanup fails
            }
            
            console.log(`Document ${documentId} deleted from MongoDB documents, course structure, and Qdrant`);
        }
        
        console.log(`Document deleted: ${documentId} by instructor ${instructorId}`);
        
        res.json({
            success: true,
            message: 'Document deleted successfully!',
            data: {
                documentId,
                deletedCount: result.deletedCount,
                removedFromCourse: result.deletedCount > 0,
                removedFromQdrant: qdrantDeleted,
                qdrantChunksDeleted: qdrantDeletedCount
            }
        });
        
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while deleting document'
        });
    }
});

/**
 * POST /api/documents/cleanup-orphans
 * Clean up orphaned document references in course structure
 */
router.post('/cleanup-orphans', async (req, res) => {
    try {
        const { courseId, instructorId } = req.body;
        
        if (!courseId || !instructorId) {
            return res.status(400).json({
                success: false,
                message: 'Missing required fields: courseId, instructorId'
            });
        }
        
        // Get database instance from app.locals
        const db = req.app.locals.db;
        if (!db) {
            return res.status(503).json({
                success: false,
                message: 'Database connection not available'
            });
        }
        
        // Get the course
        const course = await CourseModel.getCourseWithOnboarding(db, courseId);
        if (!course) {
            return res.status(404).json({
                success: false,
                message: 'Course not found'
            });
        }
        
        // Check each document reference and remove orphaned ones
        let totalOrphans = 0;
        let cleanedUnits = 0;
        
        if (course.lectures) {
            for (const unit of course.lectures) {
                if (unit.documents && unit.documents.length > 0) {
                    const validDocuments = [];
                    for (const doc of unit.documents) {
                        try {
                            const docExists = await DocumentModel.getDocumentById(db, doc.documentId);
                            if (docExists) {
                                validDocuments.push(doc);
                            } else {
                                totalOrphans++;
                                console.log(`Found orphaned document: ${doc.documentId} in unit ${unit.name}`);
                            }
                        } catch (error) {
                            console.log(`Error checking document ${doc.documentId}:`, error);
                            totalOrphans++;
                        }
                    }
                    
                    // Update the unit with only valid documents
                    if (validDocuments.length !== unit.documents.length) {
                        unit.documents = validDocuments;
                        unit.updatedAt = new Date();
                        cleanedUnits++;
                    }
                }
            }
            
            // Update the course if any changes were made
            if (totalOrphans > 0) {
                const result = await CourseModel.upsertCourse(db, course);
                console.log(`Cleaned up ${totalOrphans} orphaned documents from ${cleanedUnits} units`);
            }
        }
        
        res.json({
            success: true,
            message: `Cleanup completed. Removed ${totalOrphans} orphaned documents from ${cleanedUnits} units.`,
            data: {
                totalOrphans,
                cleanedUnits
            }
        });
        
    } catch (error) {
        console.error('Error cleaning up orphaned documents:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while cleaning up orphaned documents'
        });
    }
});

/**
 * POST /api/documents/:documentId/extract-questions
 * Extract assessment questions from a practice quiz document using LLM
 */
router.post('/:documentId/extract-questions', async (req, res) => {
    try {
        const { documentId } = req.params;
        const db = req.app.locals.db;
        const llm = req.app.locals.llm;

        if (!db) {
            return res.status(503).json({ success: false, message: 'Database connection not available' });
        }
        if (!llm || typeof llm.sendMessage !== 'function') {
            return res.status(503).json({ success: false, message: 'LLM service not available' });
        }

        // Fetch the document
        const document = await DocumentModel.getDocumentById(db, documentId);
        if (!document) {
            return res.status(404).json({ success: false, message: 'Document not found' });
        }

        const TOKEN_LIMIT = 32000;
        const content = typeof document.content === 'string' ? document.content : '';
        const estimatedTokens = content.length > 0 ? countTokens(content) : 0;

        let extractedQuestions = [];

        if (estimatedTokens <= TOKEN_LIMIT && content.length > 0) {
            // Content fits in one call
            const result = await extractQuestionsFromText(llm, content);
            extractedQuestions = result;
        } else if (content.length > 0) {
            // Content too large — use Qdrant chunks
            console.log(`Document ${documentId} exceeds token limit (${estimatedTokens} est. tokens). Using Qdrant chunks.`);
            try {
                const qdrantService = new QdrantService();
                if (!qdrantService.client) {
                    await qdrantService.initialize();
                }
                const chunks = await qdrantService.getDocumentChunks(documentId);

                if (chunks.length === 0) {
                    return res.status(400).json({
                        success: false,
                        message: 'Document is too large and no chunks were found. Please try uploading a smaller file.'
                    });
                }

                // Group chunks into batches that fit under the token limit
                const batches = groupChunksIntoBatches(chunks, TOKEN_LIMIT);
                console.log(`Processing ${chunks.length} chunks in ${batches.length} batch(es)`);

                for (const batch of batches) {
                    const batchText = batch.join('\n\n');
                    const batchQuestions = await extractQuestionsFromText(llm, batchText);
                    extractedQuestions.push(...batchQuestions);
                }
            } catch (qdrantError) {
                console.error('Error retrieving chunks from Qdrant:', qdrantError);
                return res.status(400).json({
                    success: false,
                    message: 'Document is too large to process in one call and chunk retrieval failed. Please try uploading a smaller file.'
                });
            }
        } else {
            return res.status(400).json({
                success: false,
                message: 'No text content found in document. Please ensure the file contains readable text.'
            });
        }

        res.json({
            success: true,
            data: {
                documentId,
                lectureName: document.lectureName,
                courseId: document.courseId,
                questions: extractedQuestions,
                totalFound: extractedQuestions.length,
                wasChunked: estimatedTokens > TOKEN_LIMIT
            }
        });

    } catch (error) {
        console.error('Error extracting questions from document:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error while extracting questions'
        });
    }
});

/**
 * Send text to LLM and extract assessment questions
 */
async function extractQuestionsFromText(llm, text) {
    const prompt = buildQuestionExtractionPrompt(text);

    const response = await llm.sendMessage(prompt, {
        temperature: 0.1,
        maxTokens: 4096,
        systemPrompt: QUESTION_EXTRACTION_SYSTEM_PROMPT
    });

    const parsed = extractFirstJSONObject(response?.content || '');
    if (parsed && Array.isArray(parsed.questions)) {
        return parsed.questions.map(q => {
            // Normalize MC options to uppercase A, B, C, D keys
            let options = q.options || {};
            if (q.questionType === 'multiple-choice' && Object.keys(options).length > 0) {
                const normalized = {};
                const letters = ['A', 'B', 'C', 'D', 'E', 'F'];
                const entries = Object.entries(options);
                entries.forEach(([key, val], idx) => {
                    const normalizedKey = letters[idx] || key.toUpperCase();
                    normalized[normalizedKey] = val;
                });
                options = normalized;
            }

            // Normalize correctAnswer for MC to uppercase letter
            let correctAnswer = q.correctAnswer || null;
            if (correctAnswer && q.questionType === 'multiple-choice' && typeof correctAnswer === 'string') {
                correctAnswer = correctAnswer.trim().toUpperCase().charAt(0);
            }
            // Normalize T/F answers
            if (correctAnswer && q.questionType === 'true-false' && typeof correctAnswer === 'string') {
                const lower = correctAnswer.trim().toLowerCase();
                if (lower === 'true' || lower === 't') correctAnswer = 'True';
                else if (lower === 'false' || lower === 'f') correctAnswer = 'False';
            }

            return {
                questionType: q.questionType || 'short-answer',
                question: q.question || '',
                options,
                correctAnswer,
                explanation: q.explanation || '',
                hasAnswer: correctAnswer !== null && correctAnswer !== undefined && correctAnswer !== ''
            };
        });
    }
    return [];
}

/**
 * Extract the first JSON object from a string (handles LLM responses with extra text)
 */
function extractFirstJSONObject(str) {
    try {
        return JSON.parse(str);
    } catch {
        const match = str.match(/\{[\s\S]*\}/);
        if (match) {
            try { return JSON.parse(match[0]); } catch { return null; }
        }
        return null;
    }
}

/**
 * Group text chunks into batches that fit under a token limit
 */
function groupChunksIntoBatches(chunks, tokenLimit) {
    const batches = [];
    let currentBatch = [];
    let currentTokens = 0;

    for (const chunk of chunks) {
        const chunkTokens = countTokens(chunk);
        if (currentTokens + chunkTokens > tokenLimit && currentBatch.length > 0) {
            batches.push(currentBatch);
            currentBatch = [];
            currentTokens = 0;
        }
        currentBatch.push(chunk);
        currentTokens += chunkTokens;
    }

    if (currentBatch.length > 0) {
        batches.push(currentBatch);
    }

    return batches;
}

module.exports = router;
