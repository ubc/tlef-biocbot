/**
 * GridFS helper for storing uploaded document binaries outside the document
 * record.
 *
 * MongoDB caps a single document (BSON) at 16 MB, so embedding raw file bytes in
 * the document (`fileData`) fails for large uploads (e.g. image-heavy
 * PowerPoint decks). GridFS chunks the binary into a separate bucket and we keep
 * only a reference (`fileId`) on the document, removing the size limit while
 * still allowing the original file to be downloaded.
 */

const { GridFSBucket, ObjectId } = require('mongodb');
const { Readable } = require('stream');

const BUCKET_NAME = 'documentFiles';

/**
 * @param {import('mongodb').Db} db
 * @returns {GridFSBucket}
 */
function getBucket(db) {
    return new GridFSBucket(db, { bucketName: BUCKET_NAME });
}

/** Coerce a string or ObjectId into an ObjectId (returns null if invalid). */
function toObjectId(id) {
    if (!id) return null;
    if (id instanceof ObjectId) return id;
    try {
        return new ObjectId(id);
    } catch {
        return null;
    }
}

/**
 * Store a buffer in GridFS and resolve with its file id.
 * @param {import('mongodb').Db} db
 * @param {Buffer} buffer
 * @param {string} filename
 * @param {{ contentType?: string, metadata?: Object }} [options]
 * @returns {Promise<ObjectId>}
 */
function uploadBuffer(db, buffer, filename, options = {}) {
    return new Promise((resolve, reject) => {
        const bucket = getBucket(db);
        const uploadStream = bucket.openUploadStream(filename, {
            contentType: options.contentType,
            metadata: options.metadata || {},
        });
        Readable.from(buffer)
            .pipe(uploadStream)
            .on('error', reject)
            .on('finish', () => resolve(uploadStream.id));
    });
}

/**
 * Open a readable stream for a stored file.
 * @param {import('mongodb').Db} db
 * @param {string|ObjectId} fileId
 * @returns {import('stream').Readable}
 */
function openDownloadStream(db, fileId) {
    const id = toObjectId(fileId);
    if (!id) {
        throw new Error(`Invalid GridFS file id: ${fileId}`);
    }
    return getBucket(db).openDownloadStream(id);
}

/**
 * Copy an existing GridFS file into a new one and resolve with the new id.
 * Used when cloning a document (e.g. super-course transfer) so each copy owns
 * its own binary and deletes are independent. Resolves null if the source is
 * missing/invalid.
 * @param {import('mongodb').Db} db
 * @param {string|ObjectId} sourceFileId
 * @returns {Promise<ObjectId|null>}
 */
async function copyFile(db, sourceFileId) {
    const id = toObjectId(sourceFileId);
    if (!id) return null;

    const bucket = getBucket(db);
    const fileDoc = await db
        .collection(`${BUCKET_NAME}.files`)
        .findOne({ _id: id });
    if (!fileDoc) return null;

    return new Promise((resolve, reject) => {
        const uploadStream = bucket.openUploadStream(fileDoc.filename || 'copy', {
            contentType: fileDoc.contentType,
            metadata: fileDoc.metadata || {},
        });
        bucket
            .openDownloadStream(id)
            .on('error', reject)
            .pipe(uploadStream)
            .on('error', reject)
            .on('finish', () => resolve(uploadStream.id));
    });
}

/**
 * Delete a stored file. Never throws — a missing file is treated as success so
 * document deletion is not blocked by an already-removed binary.
 * @param {import('mongodb').Db} db
 * @param {string|ObjectId} fileId
 */
async function deleteFile(db, fileId) {
    const id = toObjectId(fileId);
    if (!id) return;
    try {
        await getBucket(db).delete(id);
    } catch (err) {
        console.warn(`⚠️ GridFS delete skipped for ${fileId}: ${err.message}`);
    }
}

module.exports = {
    BUCKET_NAME,
    getBucket,
    uploadBuffer,
    openDownloadStream,
    copyFile,
    deleteFile,
    toObjectId,
};
