const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadDownloadsScript() {
    const context = vm.createContext({
        console,
        document: { addEventListener: jest.fn() },
        window: {},
        localStorage: { getItem: jest.fn(), setItem: jest.fn() },
        URLSearchParams,
        setTimeout,
        clearTimeout
    });
    const source = fs.readFileSync(
        path.join(__dirname, '../../../public/instructor/scripts/downloads.js'),
        'utf8'
    );
    vm.runInContext(source, context);
    return context;
}

describe('chat download anonymization', () => {
    test('replaces identity fields with the stable Student code recursively', () => {
        const context = loadDownloadsScript();
        const result = context.anonymizeGroupedExport({
            courseId: 'C1',
            students: [{
                studentId: 'user_1763939284126_wanzt07hw',
                studentName: 'Eden',
                username: 'eden',
                sessions: [{
                    studentId: 'user_1763939284126_wanzt07hw',
                    chatData: {
                        metadata: { studentName: 'Eden', email: 'eden@example.test', puid: '12345678' },
                        messages: [{ type: 'user', content: 'hello' }]
                    }
                }]
            }]
        }, new Map([['user_1763939284126_wanzt07hw', 'A042']]));

        expect(JSON.parse(JSON.stringify(result))).toEqual({
            courseId: 'C1',
            students: [{
                student: 'A042',
                sessions: [{
                    chatData: {
                        metadata: {},
                        messages: [{ type: 'user', content: 'hello' }]
                    }
                }]
            }]
        });
        const json = JSON.stringify(result);
        expect(json).not.toContain('user_1763939284126_wanzt07hw');
        expect(json).not.toContain('Eden');
        expect(json).not.toContain('12345678');
    });

    test('plain-text exports show the pseudonym and omit an internal-ID line', () => {
        const context = loadDownloadsScript();
        const text = context.formatChatAsText({
            courseId: 'C1',
            exportDate: '2026-08-24T00:00:00.000Z',
            totalStudents: 1,
            students: [{ student: 'A042', sessions: [] }]
        });
        expect(text).toContain('Student: A042');
        expect(text).not.toContain('Student ID:');
    });
});
