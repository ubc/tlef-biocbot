// @ts-check
/// <reference types="node" />
const [major, minor] = process.versions.node.split('.').map(Number);
const supported = major === 24 && minor >= 17;

if (!supported) {
    process.stderr.write(
        `Accessibility tests require Node.js >=24.17.0 <25 (current: ${process.versions.node}).\n` +
        'Install Node 24 and run "nvm use" (which reads .nvmrc), then rerun "npm run test:a11y".\n'
    );
    process.exit(1);
}
