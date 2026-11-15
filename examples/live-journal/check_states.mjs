// node check_states.mjs page.html states.json
// Runs the page's own stateAt function, taken from the made page, on its own data at every frame of states.json (the kernel's
// states, written by make_page.py --states from `sbgk audit-prov --upto N+1`), and compares: the same records handed in by
// that frame, and for each the same state (stands, ended, never), the same frame and reason for an end, the same grounds lost.
// It exits 0 when every frame agrees, 1 otherwise. Node.js 18 or newer, no packages.
import { readFileSync } from 'node:fs';

const [pagePath, statesPath] = process.argv.slice(2);
if (!pagePath || !statesPath) {
  console.error('usage: node check_states.mjs page.html states.json');
  process.exit(2);
}
const page = readFileSync(pagePath, 'utf8');
const start = page.indexOf('const D = ') + 'const D = '.length;
const D = JSON.parse(page.slice(start, page.indexOf(';\n', start)));
const begin = page.indexOf('// BEGIN stateAt'), end = page.indexOf('// END stateAt');
if (begin < 0 || end < begin) {
  console.error('the page has no marked stateAt function');
  process.exit(1);
}
const source = page.slice(page.indexOf('\n', begin) + 1, end);
const stateAt = new Function('Q', 'R', 'P', `${source}\nreturn stateAt;`)(D.quotes, D.recs, D.periods);
const kernel = JSON.parse(readFileSync(statesPath, 'utf8')).frames;
const problems = [];
for (const [f, want] of Object.entries(kernel)) {
  const s = stateAt(Number(f));
  const got = {};
  for (const id of s.here) {
    got[id] = s.gone[id] ? ['ended', ...s.gone[id]] : s.never.has(id) ? ['never', null, null, []] : ['stands', null, null, []];
  }
  const ids = new Set([...Object.keys(want), ...Object.keys(got)]);
  for (const id of ids) {
    if (JSON.stringify(got[id]) !== JSON.stringify(want[id])) {
      problems.push(`frame ${f}, ${id}: the page ${JSON.stringify(got[id])}, the kernel ${JSON.stringify(want[id])}`);
    }
  }
}
for (const p of problems.slice(0, 20)) console.log('  ' + p);
console.log(`check_states: ${Object.keys(kernel).length} frames, ${problems.length ? `${problems.length} difference(s)` : 'the page equals the kernel'}`);
process.exit(problems.length || !Object.keys(kernel).length ? 1 : 0);
