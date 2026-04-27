import { test } from 'node:test';
import { strictEqual } from 'node:assert/strict';
import { PROTOCOL_VERSION } from '../src/index.js';
test('PROTOCOL_VERSION is exported from package entry point', () => {
    strictEqual(PROTOCOL_VERSION, '0.1.0-beta');
});
//# sourceMappingURL=index.test.js.map