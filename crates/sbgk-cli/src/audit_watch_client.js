// The script of a watched page (sbgk audit-watch): every so often it asks the server that gave the page for what changed since
// the frames the page has, and hands the answer to the page. The page itself draws; this script only fetches.
(() => {
  'use strict';
  const live = window.yuceLive;
  if (!live) return;
  let failed = 0;
  async function ask() {
    try {
      const answer = await fetch(`delta?epoch=${live.epoch()}&frames=${live.frames()}`, { cache: 'no-store' });
      if (!answer.ok) throw new Error(String(answer.status));
      const body = await answer.json();
      failed = 0;
      // another journal at this path, or data that must be taken whole again: the page is loaded anew
      if (body.reset) { window.location.reload(); return; }
      live.grow(body.delta);
    } catch (e) {
      failed += 1;
      if (failed >= 3) live.lost();
    }
    // a server that does not answer is asked less often
    setTimeout(ask, failed >= 3 ? 5000 : live.every());
  }
  setTimeout(ask, live.every());
})();
