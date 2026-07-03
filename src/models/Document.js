const { createId } = require('../services/id');

/**
 * Document Model for MongoDB
 * Stores uploaded documents, text content, and metadata
 */

/**
 * Document Schema Structure:
 * {
 *   _id: ObjectId,
 *   documentId: String,           // Unique document identifier
 *   courseId: String,             // Course this document belongs to
 *   lectureName: String,          // Unit/Week this document is for
 *   instructorId: String,         // ID of the instructor who uploaded
 *   documentType: String,         // "lecture-notes", "practice-quiz", "additional", "text" (legacy)
 *   type: String,                 // "lecture_notes", "practice_q_tutorials", "additional" (new specific type)
 *   contentType: String,          // "file" or "text"
 *   filename: String,             // Original filename (for file uploads)
 *   originalName: String,         // Display name
 *   content: String,              // Text content (for text uploads)
 *   fileData: Buffer,             // File binary data (for file uploads)
 *   mimeType: String,             // MIME type of the file
 *   size: Number,                 // File size in bytes
 *   status: String,               // "uploaded", "parsing", "parsed", "error"
 *   uploadDate: Date,             // When the document was uploaded
 *   lastModified: Date,           // Last modification timestamp
 *   metadata: {                   // Additional metadata
 *     description: String,
 *     tags: [String],
 *     learningObjectives: [String]
 *   }
 * }
 */

/**
 * Get the documents collection from the database
 * @param {Object} db - MongoDB database instance
 * @returns {Collection} Documents collection
 */
function getDocumentsCollection(db) {
    return db.collection('documents');
}

/**
 * Map content type to specific document type for robust categorization
 * @param {string} contentType - The content type from the upload modal
 * @returns {string} The specific document type for database storage
 */
function mapContentTypeToDocumentType(contentType) {
    switch (contentType) {
        case 'lecture-notes':
            return 'lecture_notes';
        case 'practice-quiz':
            return 'practice_q_tutorials';
        case 'additional':
            return 'additional';
        case 'text':
            return 'text';
        default:
            return 'additional'; // Default fallback
    }
}

/**
 * Upload a new document (file or text)
 * @param {Object} db - MongoDB database instance
 * @param {Object} documentData - Document data object
 * @returns {Promise<Object>} Created document
 */
async function uploadDocument(db, documentData) {
    const collection = getDocumentsCollection(db);
    
    const now = new Date();
    
    // Map content type to specific document type
    const specificType = mapContentTypeToDocumentType(documentData.documentType);
    console.log(`🔧 [DOCUMENT_UPLOAD] Mapping content type "${documentData.documentType}" to specific type "${specificType}"`);
    
    const document = {
        ...documentData,
        type: specificType, // Add the new specific type field
        uploadDate: now,
        lastModified: now,
        status: 'uploaded'
    };
    
    // Generate unique document ID
    document.documentId = createId('doc');
    
    const result = await collection.insertOne(document);
    
    return {
        ...document,
        _id: result.insertedId
    };
}

/**
 * Get all documents for a specific lecture/unit
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @param {string} lectureName - Name of the lecture/unit
 * @returns {Promise<Array>} Array of documents
 */
async function getDocumentsForLecture(db, courseId, lectureName) {
    const collection = getDocumentsCollection(db);
    
    const documents = await collection.find({
        courseId: courseId,
        lectureName: lectureName
    }).sort({ uploadDate: -1 }).toArray();
    
    return documents;
}

/**
 * Get a specific document by ID
 * @param {Object} db - MongoDB database instance
 * @param {string} documentId - Document identifier
 * @returns {Promise<Object|null>} Document object or null
 */
async function getDocumentById(db, documentId) {
    const collection = getDocumentsCollection(db);
    
    const document = await collection.findOne({ documentId: documentId });
    return document;
}

/**
 * Update document content with extracted text
 * @param {Object} db - MongoDB database instance
 * @param {string} documentId - Document identifier
 * @param {string} content - Extracted text content
 * @returns {Promise<Object>} Update result
 */
async function updateDocumentContent(db, documentId, content) {
    const collection = getDocumentsCollection(db);
    
    try {
        const result = await collection.updateOne(
            { documentId: documentId },
            { 
                $set: { 
                    content: content,
                    lastModified: new Date(),
                    status: 'parsed'
                }
            }
        );
        
        if (result.matchedCount > 0) {
            return {
                success: true,
                message: 'Document content updated successfully',
                modifiedCount: result.modifiedCount
            };
        } else {
            return {
                success: false,
                error: 'Document not found'
            };
        }
    } catch (error) {
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Update document status
 * @param {Object} db - MongoDB database instance
 * @param {string} documentId - Document identifier
 * @param {string} status - New status
 * @param {Object} additionalData - Additional data to update
 * @returns {Promise<Object>} Update result
 */
async function updateDocumentStatus(db, documentId, status, additionalData = {}) {
    const collection = getDocumentsCollection(db);
    
    const updateData = {
        status: status,
        lastModified: new Date(),
        ...additionalData
    };
    
    const result = await collection.updateOne(
        { documentId: documentId },
        { $set: updateData }
    );
    
    return result;
}

/**
 * Delete a document
 * @param {Object} db - MongoDB database instance
 * @param {string} documentId - Document identifier
 * @returns {Promise<Object>} Delete result
 */
async function deleteDocument(db, documentId) {
    const collection = getDocumentsCollection(db);
    
    const result = await collection.deleteOne({ documentId: documentId });
    return result;
}

/**
 * Get document statistics for a course
 * @param {Object} db - MongoDB database instance
 * @param {string} courseId - Course identifier
 * @returns {Promise<Object>} Document statistics
 */
async function getDocumentStats(db, courseId) {
    const collection = getDocumentsCollection(db);
    
    const stats = await collection.aggregate([
        { $match: { courseId: courseId } },
        { $group: {
            _id: '$status',
            count: { $sum: 1 },
            totalSize: { $sum: '$size' }
        }},
        { $group: {
            _id: null,
            totalDocuments: { $sum: '$count' },
            totalSize: { $sum: '$totalSize' },
            statusBreakdown: { $push: { status: '$_id', count: '$count' } }
        }}
    ]).toArray();
    
    return stats[0] || { totalDocuments: 0, totalSize: 0, statusBreakdown: [] };
}

module.exports = {
    getDocumentsCollection,
    uploadDocument,
    getDocumentsForLecture,
    getDocumentById,
    updateDocumentContent,
    updateDocumentStatus,
    deleteDocument,
    getDocumentStats,
    mapContentTypeToDocumentType
};
