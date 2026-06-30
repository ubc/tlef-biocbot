const { PassThrough } = require('stream');
const { ObjectId } = require('mongodb');

const bucketInstances = [];

jest.mock('mongodb', () => {
    const actual = jest.requireActual('mongodb');
    return {
        ...actual,
        GridFSBucket: jest.fn(function GridFSBucket(db, options) {
            const bucket = {
                db,
                options,
                openUploadStream: jest.fn(),
                openDownloadStream: jest.fn(),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        })
    };
});

const { GridFSBucket } = require('mongodb');
const gridfs = require('../../../src/services/gridfs');

function uploadStream(id = new ObjectId()) {
    const stream = new PassThrough();
    stream.id = id;
    return stream;
}

describe('gridfs', () => {
    beforeEach(() => {
        bucketInstances.length = 0;
    });

    test('uses the dedicated document bucket', () => {
        const db = { marker: 'db' };
        const bucket = gridfs.getBucket(db);

        expect(gridfs.BUCKET_NAME).toBe('documentFiles');
        expect(GridFSBucket).toHaveBeenCalledWith(db, { bucketName: 'documentFiles' });
        expect(bucket.db).toBe(db);
    });

    test('coerces valid ids and rejects empty or malformed ids', () => {
        const id = new ObjectId();
        expect(gridfs.toObjectId(id)).toBe(id);
        expect(gridfs.toObjectId(id.toHexString())).toEqual(id);
        expect(gridfs.toObjectId()).toBeNull();
        expect(gridfs.toObjectId('not-an-object-id')).toBeNull();
    });

    test('uploads bytes and defaults metadata to an empty object', async () => {
        const id = new ObjectId();
        const stream = uploadStream(id);
        GridFSBucket.mockImplementationOnce(function Bucket(db, options) {
            const bucket = {
                db,
                options,
                openUploadStream: jest.fn(() => stream),
                openDownloadStream: jest.fn(),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });
        const chunks = [];
        stream.on('data', chunk => chunks.push(chunk));

        await expect(gridfs.uploadBuffer({}, Buffer.from('hello'), 'notes.txt')).resolves.toEqual(id);
        expect(bucketInstances[0].openUploadStream).toHaveBeenCalledWith('notes.txt', {
            contentType: undefined,
            metadata: {}
        });
        expect(Buffer.concat(chunks).toString()).toBe('hello');
    });

    test('passes upload options and rejects upload stream failures', async () => {
        const stream = uploadStream();
        stream._write = (chunk, encoding, callback) => callback(new Error('upload failed'));
        GridFSBucket.mockImplementationOnce(function Bucket(db, options) {
            const bucket = {
                openUploadStream: jest.fn(() => stream),
                openDownloadStream: jest.fn(),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        await expect(gridfs.uploadBuffer({}, Buffer.from('x'), 'x.bin', {
            contentType: 'application/octet-stream',
            metadata: { kind: 'source' }
        })).rejects.toThrow('upload failed');
        expect(bucketInstances[0].openUploadStream).toHaveBeenCalledWith('x.bin', {
            contentType: 'application/octet-stream',
            metadata: { kind: 'source' }
        });
    });

    test('opens a download with the normalized ObjectId', () => {
        const id = new ObjectId();
        const expected = new PassThrough();
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openDownloadStream: jest.fn(() => expected),
                openUploadStream: jest.fn(),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        expect(gridfs.openDownloadStream({}, id.toHexString())).toBe(expected);
        expect(bucketInstances[0].openDownloadStream).toHaveBeenCalledWith(id);
    });

    test('rejects invalid download ids before constructing a bucket', () => {
        expect(() => gridfs.openDownloadStream({}, 'bad-id')).toThrow(
            'Invalid GridFS file id: bad-id'
        );
    });

    test('copy returns null for invalid or missing source files', async () => {
        await expect(gridfs.copyFile({}, 'bad-id')).resolves.toBeNull();

        const id = new ObjectId();
        const findOne = jest.fn().mockResolvedValue(null);
        const db = { collection: jest.fn(() => ({ findOne })) };
        await expect(gridfs.copyFile(db, id)).resolves.toBeNull();
        expect(db.collection).toHaveBeenCalledWith('documentFiles.files');
        expect(findOne).toHaveBeenCalledWith({ _id: id });
    });

    test('copies content and preserves file metadata', async () => {
        const sourceId = new ObjectId();
        const targetId = new ObjectId();
        const download = new PassThrough();
        const upload = uploadStream(targetId);
        const chunks = [];
        upload.on('data', chunk => chunks.push(chunk));
        const fileDoc = {
            _id: sourceId,
            filename: 'slides.pptx',
            contentType: 'application/vnd.ms-powerpoint',
            metadata: { courseId: 'C1' }
        };
        const db = {
            collection: jest.fn(() => ({ findOne: jest.fn().mockResolvedValue(fileDoc) }))
        };
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openUploadStream: jest.fn(() => upload),
                openDownloadStream: jest.fn(() => download),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        const copied = gridfs.copyFile(db, sourceId);
        download.end(Buffer.from('binary'));

        await expect(copied).resolves.toEqual(targetId);
        expect(bucketInstances[0].openUploadStream).toHaveBeenCalledWith('slides.pptx', {
            contentType: fileDoc.contentType,
            metadata: fileDoc.metadata
        });
        expect(Buffer.concat(chunks).toString()).toBe('binary');
    });

    test('copy applies filename and metadata defaults', async () => {
        const sourceId = new ObjectId();
        const download = new PassThrough();
        const upload = uploadStream();
        const db = {
            collection: jest.fn(() => ({ findOne: jest.fn().mockResolvedValue({ _id: sourceId }) }))
        };
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openUploadStream: jest.fn(() => upload),
                openDownloadStream: jest.fn(() => download),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        const copied = gridfs.copyFile(db, sourceId);
        download.end();
        await copied;

        expect(bucketInstances[0].openUploadStream).toHaveBeenCalledWith('copy', {
            contentType: undefined,
            metadata: {}
        });
    });

    test.each(['download', 'upload'])('copy rejects %s stream failures', async failurePoint => {
        const sourceId = new ObjectId();
        const download = new PassThrough();
        const upload = uploadStream();
        if (failurePoint === 'upload') {
            upload._write = (chunk, encoding, callback) => callback(new Error('upload failed'));
        }
        const db = {
            collection: jest.fn(() => ({
                findOne: jest.fn().mockResolvedValue({ _id: sourceId, filename: 'x' })
            }))
        };
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openUploadStream: jest.fn(() => upload),
                openDownloadStream: jest.fn(() => download),
                delete: jest.fn()
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        const copied = gridfs.copyFile(db, sourceId);
        await new Promise(resolve => setImmediate(resolve));
        if (failurePoint === 'download') download.emit('error', new Error('download failed'));
        else download.end(Buffer.from('x'));

        await expect(copied).rejects.toThrow(`${failurePoint} failed`);
    });

    test('delete ignores invalid ids and deletes valid ids', async () => {
        await expect(gridfs.deleteFile({}, 'bad-id')).resolves.toBeUndefined();

        const id = new ObjectId();
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openUploadStream: jest.fn(),
                openDownloadStream: jest.fn(),
                delete: jest.fn().mockResolvedValue(undefined)
            };
            bucketInstances.push(bucket);
            return bucket;
        });
        await expect(gridfs.deleteFile({}, id.toHexString())).resolves.toBeUndefined();
        expect(bucketInstances[0].delete).toHaveBeenCalledWith(id);
    });

    test('delete logs driver failures instead of throwing', async () => {
        const id = new ObjectId();
        const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
        GridFSBucket.mockImplementationOnce(function Bucket() {
            const bucket = {
                openUploadStream: jest.fn(),
                openDownloadStream: jest.fn(),
                delete: jest.fn().mockRejectedValue(new Error('already gone'))
            };
            bucketInstances.push(bucket);
            return bucket;
        });

        await expect(gridfs.deleteFile({}, id)).resolves.toBeUndefined();
        expect(warn).toHaveBeenCalledWith(
            `⚠️ GridFS delete skipped for ${id}: already gone`
        );
        warn.mockRestore();
    });
});
