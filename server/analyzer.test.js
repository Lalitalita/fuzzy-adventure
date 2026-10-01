import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreSource, parseAudit } from './analyzer.js';

const src = (o) => ({ count: 1, ports: new Set([80]), dsts: new Set(['a']), first: 0, last: 0, ids: [], ...o });

test('hit isolé = bruit', () => assert.equal(scoreSource(src({})).level, 'bruit'));
test('scan de ports + hôtes = tryhard', () => {
  const r = scoreSource(src({ count: 120, ports: new Set(Array.from({ length: 60 }, (_, i) => i + 1)), dsts: new Set(Array.from({ length: 12 }, (_, i) => 'h' + i)) }));
  assert.equal(r.level, 'tryhard');
});
test('parseAudit', () => {
  const r = parseAudit('curl-8.5 is vulnerable:\n  curl -- bug\n  CVE: CVE-2024-1\n  WWW: https://x\n\n1 problem(s)');
  assert.deepEqual(r[0].cves, ['CVE-2024-1']);
});
