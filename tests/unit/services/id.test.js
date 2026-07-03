const { createId } = require('../../../src/services/id');

describe('createId', () => {
    test('creates collision-resistant prefixed UUID identifiers', () => {
        const first = createId('doc');
        const second = createId('doc');
        expect(first).toMatch(/^doc_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
        expect(second).not.toBe(first);
    });

    test.each(['', 'bad prefix', '_bad', null])('rejects invalid prefix %p', prefix => {
        expect(() => createId(prefix)).toThrow(/prefix/i);
    });
});
