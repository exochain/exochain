// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
import { strictEqual } from 'node:assert/strict';
import { test } from 'node:test';
import { TransportError } from '../src/errors.js';
import { MAX_HTTP_RESPONSE_BYTES as EXPORTED_MAX_HTTP_RESPONSE_BYTES } from '../src/index.js';
import { HttpTransport, MAX_HTTP_RESPONSE_BYTES, } from '../src/transport/http.js';
const RESPONSE_LIMIT_BYTES = 1048576;
const OVERSIZED_RESPONSE_MESSAGE = 'response body exceeds the 1048576-byte limit';
const encoder = new TextEncoder();
test('HTTP response limit is the fixed one-mebibyte SDK contract', () => {
    strictEqual(MAX_HTTP_RESPONSE_BYTES, RESPONSE_LIMIT_BYTES);
    strictEqual(EXPORTED_MAX_HTTP_RESPONSE_BYTES, RESPONSE_LIMIT_BYTES);
});
function paddedJson(byteLength) {
    const prefix = '{"ok":true,"padding":"';
    const suffix = '"}';
    const fixedLength = encoder.encode(`${prefix}${suffix}`).byteLength;
    if (byteLength < fixedLength) {
        throw new Error(`test JSON length ${byteLength} is too small`);
    }
    const body = encoder.encode(`${prefix}${'a'.repeat(byteLength - fixedLength)}${suffix}`);
    strictEqual(body.byteLength, byteLength);
    return body;
}
function responseFromChunks(chunks, init) {
    return new Response(new ReadableStream({
        start(controller) {
            for (const chunk of chunks)
                controller.enqueue(chunk);
            controller.close();
        },
    }), init);
}
function fetchReturning(factory) {
    return (async () => factory());
}
async function captureTransportError(task) {
    try {
        await task();
    }
    catch (error) {
        if (error instanceof TransportError)
            return error;
        throw error;
    }
    throw new Error('expected TransportError');
}
test('HTTP transport accepts valid success JSON at the exact response byte limit', async () => {
    const body = paddedJson(RESPONSE_LIMIT_BYTES);
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([body.subarray(0, 17), body.subarray(17)], {
            status: 200,
            headers: { 'content-length': String(RESPONSE_LIMIT_BYTES) },
        })),
    });
    const result = (await transport.get('/bounded'));
    strictEqual(result.ok, true);
    strictEqual(encoder.encode(result.padding).byteLength, RESPONSE_LIMIT_BYTES - 24);
});
test('HTTP transport rejects a chunked response at response limit plus one', async () => {
    const body = paddedJson(RESPONSE_LIMIT_BYTES + 1);
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([body.subarray(0, RESPONSE_LIMIT_BYTES), body.subarray(RESPONSE_LIMIT_BYTES)], {
            status: 200,
        })),
    });
    const error = await captureTransportError(() => transport.get('/oversized'));
    strictEqual(error.message, OVERSIZED_RESPONSE_MESSAGE);
    strictEqual(error.status, 200);
    strictEqual(error.body, undefined);
});
test('HTTP transport accepts chunked JSON without Content-Length', async () => {
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([encoder.encode('{"ok":'), encoder.encode('true}')], {
            status: 200,
        })),
    });
    const result = (await transport.get('/chunked'));
    strictEqual(result.ok, true);
});
test('dishonest small Content-Length cannot bypass streamed response accounting', async () => {
    const body = paddedJson(RESPONSE_LIMIT_BYTES + 1);
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([body], {
            status: 200,
            headers: { 'content-length': '1' },
        })),
    });
    const error = await captureTransportError(() => transport.get('/dishonest-small'));
    strictEqual(error.message, OVERSIZED_RESPONSE_MESSAGE);
    strictEqual(error.status, 200);
    strictEqual(error.body, undefined);
});
test('dishonest large Content-Length is rejected before a small body is trusted', async () => {
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([encoder.encode('{"ok":true}')], {
            status: 200,
            headers: { 'content-length': String(RESPONSE_LIMIT_BYTES + 1) },
        })),
    });
    const error = await captureTransportError(() => transport.get('/dishonest-large'));
    strictEqual(error.message, OVERSIZED_RESPONSE_MESSAGE);
    strictEqual(error.status, 200);
    strictEqual(error.body, undefined);
});
test('bounded HTTP errors retain valid JSON bodies and status metadata', async () => {
    const body = '{"error_code":"consent_required","message":"denied"}';
    const transport = new HttpTransport('https://gateway.example', {
        fetch: fetchReturning(() => responseFromChunks([encoder.encode(body)], {
            status: 403,
            statusText: 'Forbidden',
        })),
    });
    const error = await captureTransportError(() => transport.post('/governed', {}));
    strictEqual(error.message, 'HTTP 403 Forbidden for POST /governed');
    strictEqual(error.status, 403);
    strictEqual(error.body, body);
});
test('oversized success and error responses use the same bounded stable error', async () => {
    for (const status of [200, 502]) {
        const body = paddedJson(RESPONSE_LIMIT_BYTES + 1);
        const transport = new HttpTransport('https://gateway.example', {
            fetch: fetchReturning(() => responseFromChunks([body], {
                status,
                headers: { 'content-length': String(RESPONSE_LIMIT_BYTES + 1) },
            })),
        });
        const error = await captureTransportError(() => transport.get('/oversized-stable'));
        strictEqual(error.message, OVERSIZED_RESPONSE_MESSAGE);
        strictEqual(error.status, status);
        strictEqual(error.body, undefined);
    }
});
test('HTTP transport preserves the configured request timeout behavior', async () => {
    const neverReply = (async (_input, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), {
            once: true,
        });
    }));
    const transport = new HttpTransport('https://gateway.example', {
        fetch: neverReply,
        timeout: 5,
    });
    const error = await captureTransportError(() => transport.get('/timeout'));
    strictEqual(error.message, 'network error: request timed out');
});
test('HTTP transport keeps the configured timeout active while reading the body', async () => {
    const stalledBody = (async (_input, init) => new Response(new ReadableStream({
        start(controller) {
            const lateFailure = setTimeout(() => controller.error(new Error('body remained stalled')), 25);
            init?.signal?.addEventListener('abort', () => {
                clearTimeout(lateFailure);
                controller.error(init.signal?.reason);
            }, { once: true });
        },
    }), { status: 200 }));
    const transport = new HttpTransport('https://gateway.example', {
        fetch: stalledBody,
        timeout: 5,
    });
    const error = await captureTransportError(() => transport.get('/stalled-body'));
    strictEqual(error.message, 'network error: request timed out');
});
//# sourceMappingURL=http_transport.test.js.map