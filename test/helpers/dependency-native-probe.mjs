// Deliberately separate Node process: Windows browser/native fallback uses Node.
// No external models, API credentials, network requests or installer scripts.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import sharp from 'sharp';
import AdmZip from 'adm-zip';
import * as ort from 'onnxruntime-node';
import { BertTokenizer, RawImage, env } from '@huggingface/transformers';

env.allowRemoteModels = false;
globalThis.fetch = async () => { throw new Error('Network is forbidden in the offline compatibility probe'); };

const png = await sharp({ create: { width: 2, height: 2, channels: 3, background: '#ff0000' } }).png().toBuffer();
const decoded = await RawImage.fromBlob(new Blob([png], { type: 'image/png' }));
assert.equal(decoded.width, 2);
assert.equal(decoded.height, 2);
assert.deepEqual(Array.from(decoded.data.slice(0, 3)), [255, 0, 0]);

const tokenizer = new BertTokenizer({
  version: '1.0', added_tokens: [], normalizer: null, pre_tokenizer: { type: 'Whitespace' },
  post_processor: null, decoder: { type: 'WordPiece', prefix: '##', cleanup: true },
  model: { type: 'WordPiece', unk_token: '[UNK]', continuing_subword_prefix: '##', max_input_chars_per_word: 100,
    vocab: { '[UNK]': 0, '[PAD]': 1, hello: 2, world: 3 } },
}, { unk_token: '[UNK]', pad_token: '[PAD]', model_max_length: 100 });
// The classifier uses this field to cap unbounded tokenizer configurations.
tokenizer._tokenizerConfig.model_max_length = 2;
assert.equal(tokenizer.model_max_length, 2);
assert.deepEqual(tokenizer('hello world hello', { truncation: true, return_tensor: false }).input_ids, [2, 3]);

// Encode a minimal ONNX Identity graph directly. No model downloads or protobuf dependency.
const varint = (n) => {
  const bytes = [];
  do { bytes.push((n & 127) | (n > 127 ? 128 : 0)); n = Math.floor(n / 128); } while (n);
  return Buffer.from(bytes);
};
const int = (field, n) => Buffer.concat([varint(field * 8), varint(n)]);
const bytes = (field, value) => {
  const body = typeof value === 'string' ? Buffer.from(value) : value;
  return Buffer.concat([varint(field * 8 + 2), varint(body.length), body]);
};
const concat = (...parts) => Buffer.concat(parts);
const valueInfo = (name) => concat(bytes(1, name), bytes(2, bytes(1, concat(int(1, 1), bytes(2, bytes(1, int(1, 3)))))));
const graph = concat(bytes(1, concat(bytes(1, 'x'), bytes(2, 'y'), bytes(4, 'Identity'))),
  bytes(2, 'offline-identity'), bytes(11, valueInfo('x')), bytes(12, valueInfo('y')));
const model = concat(int(1, 8), bytes(7, graph), bytes(8, int(2, 13)));
const session = await ort.InferenceSession.create(model, { executionProviders: ['cpu'] });
try {
  const result = await session.run({ x: new ort.Tensor('float32', Float32Array.from([1, -2, 3]), [3]) });
  assert.deepEqual(Array.from(result.y.data), [1, -2, 3]);
} finally { await session.release(); }

// Exercise ONNX installer's actual AdmZip API without running its downloader.
const zip = new AdmZip();
zip.addFile('native/fixture.txt', Buffer.from('offline archive fixture'));
const reopened = new AdmZip(zip.toBuffer());
const output = mkdtempSync(join(tmpdir(), 'gstack-dependency-zip-'));
assert.equal(reopened.extractEntryTo(reopened.getEntry('native/fixture.txt'), output, false, true), true);
assert.equal(readFileSync(join(output, 'fixture.txt'), 'utf8'), 'offline archive fixture');
assert.throws(() => reopened.extractEntryTo('missing.txt', output, false, true));
console.log('offline native compatibility passed');
