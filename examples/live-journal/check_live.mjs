// node check_live.mjs watched_first.html deltas.json final.json [states.json]
// Runs the page's own merge function, taken from a watched page (sbgk audit-watch), on what the server sent after that page:
// the data of the page with every delta merged in must equal the whole data the server gives at the end, field by field.
// With states.json (the kernel's states at every frame, written by make_page.py --states from `sbgk audit-prov --upto N+1`), the
// page's own stateAt on the merged data must give those states at every frame.
// It exits 0 when all agree, 1 otherwise. Node.js 18 or newer, no packages.
import { readFileSync } from 'node:fs';

const [pagePath, deltasPath, finalPath, statesPath] = process.argv.slice(2);
if (!pagePath || !deltasPath || !finalPath) {
  console.error('usage: node check_live.mjs watched_first.html deltas.json final.json [states.json]');
  process.exit(2);
}
const page = readFileSync(pagePath, 'utf8');
const start = page.indexOf('const D = ') + 'const D = '.length;
const after = page.indexOf(';\n', start);
const D = JSON.parse(page.slice(start, after));
// the markers are searched after the data, so a journal whose text holds them cannot move them
const between = (name) => {
  const begin = page.indexOf(`// BEGIN ${name}`, after), end = page.indexOf(`// END ${name}`, after);
  if (begin < 0 || end < begin) {
    console.error(`the page has no marked ${name} function`);
    process.exit(1);
  }
  return page.slice(page.indexOf('\n', begin) + 1, end);
};
const merge = new Function(`${between('merge')}\nreturn merge;`)();
const deltas = JSON.parse(readFileSync(deltasPath, 'utf8'));
const first = D.frames.length;
for (const d of deltas) merge(D, d);
delete D.live;
const final = JSON.parse(readFileSync(finalPath, 'utf8'));
// the same members whatever their order
const canon = (v) => (Array.isArray(v) ? v.map(canon) : v && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v);
const problems = [];
for (const k of new Set([...Object.keys(D), ...Object.keys(final)])) {
  if (JSON.stringify(canon(D[k])) !== JSON.stringify(canon(final[k]))) problems.push(`"${k}": the merged page and the whole data differ`);
}
// the records come in the order of the journal on both sides: the page draws them in that order
for (const k of ['quotes', 'recs', 'periods']) {
  if (JSON.stringify(Object.keys(D[k])) !== JSON.stringify(Object.keys(final[k]))) problems.push(`"${k}": another order of the records`);
}
let frames = 0;
if (statesPath) {
  const stateAt = new Function('Q', 'R', 'P', `${between('stateAt')}\nreturn stateAt;`)(D.quotes, D.recs, D.periods);
  const kernel = JSON.parse(readFileSync(statesPath, 'utf8')).frames;
  for (const [f, want] of Object.entries(kernel)) {
    frames += 1;
    const s = stateAt(Number(f));
    const got = {};
    for (const id of s.here) got[id] = s.gone[id] ? ['ended', ...s.gone[id]] : s.never.has(id) ? ['never', null, null, []] : ['stands', null, null, []];
    for (const id of new Set([...Object.keys(want), ...Object.keys(got)])) {
      if (JSON.stringify(got[id]) !== JSON.stringify(want[id])) problems.push(`frame ${f}, ${id}: the page ${JSON.stringify(got[id])}, the kernel ${JSON.stringify(want[id])}`);
    }
  }
  if (!frames) problems.push('no kernel states to compare with');
}
for (const p of problems.slice(0, 20)) console.log('  ' + p);
console.log(`check_live: a page of ${first} frames and ${deltas.length} deltas, ${final.frames.length} frames at the end` +
  `${statesPath ? `, ${frames} frames of kernel states` : ''}: ${problems.length ? `${problems.length} difference(s)` : 'the merged page equals the whole data' + (statesPath ? ' and the kernel' : '')}`);
process.exit(problems.length || !deltas.length ? 1 : 0);
