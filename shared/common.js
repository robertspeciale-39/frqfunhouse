/* FRQ Funhouse — shared helpers (storage, chmod checker, misc) */
(function () {
  const FH = {};

  /* ---------- storage (localStorage, never throws) ---------- */
  FH.load = function (key, fallback) {
    try { const v = localStorage.getItem('frqfh_' + key); return v ? JSON.parse(v) : fallback; }
    catch (e) { return fallback; }
  };
  FH.save = function (key, value) {
    try { localStorage.setItem('frqfh_' + key, JSON.stringify(value)); } catch (e) {}
  };
  FH.saveBest = function (game, pct) {
    const best = FH.load('best', {});
    if (best[game] == null || pct > best[game]) best[game] = pct;
    FH.save('best', best);
  };

  /* ---------- small utils ---------- */
  FH.esc = function (s) {
    return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  };
  FH.shuffle = function (arr) {
    const a = arr.slice();
    for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
    return a;
  };
  FH.today = function () { return new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }); };

  /* ---------- permissions ---------- */
  // 'rw-r--r--' -> [6,4,4]
  FH.permToNums = function (p) {
    const n = [];
    for (let i = 0; i < 3; i++) {
      const t = p.substr(i * 3, 3);
      n.push((t[0] === 'r' ? 4 : 0) + (t[1] === 'w' ? 2 : 0) + (t[2] === 'x' ? 1 : 0));
    }
    return n;
  };
  FH.numsToPerm = function (n) {
    return n.map(v => (v & 4 ? 'r' : '-') + (v & 2 ? 'w' : '-') + (v & 1 ? 'x' : '-')).join('');
  };

  /*
   * Run one or more chmod commands against a map of {filename: 'rwxr-x---'}.
   * Accepts: chmod 640 file | sudo chmod go-r file | chmod u+x,g-w file
   * Several commands may be separated by newlines, ';' or '&&'.
   * Returns { ok, error, changed: {file: {before, after}} }
   */
  FH.runChmod = function (input, files) {
    const state = {};
    Object.keys(files).forEach(f => state[f] = FH.permToNums(files[f]));
    const changed = {};
    const cmds = String(input).replace(/[‘’“”`"']/g, '').split(/\n|;|&&|\band then\b|\bthen\b/i)
      .map(s => s.trim()).filter(Boolean);
    if (!cmds.length) return { ok: false, error: 'No command entered.' };
    for (const raw of cmds) {
      const tok = raw.split(/\s+/);
      if (tok[0] === 'sudo') tok.shift();
      if (tok[0] !== 'chmod') return { ok: false, error: 'Each command must start with chmod (sudo is optional): "' + raw + '"' };
      if (tok.length < 3) return { ok: false, error: 'chmod needs a mode and a file name: "' + raw + '"' };
      const mode = tok[1];
      const targets = tok.slice(2);
      for (const f of targets) {
        if (!(f in state)) return { ok: false, error: 'File "' + f + '" is not in the listing.' };
        const before = FH.numsToPerm(state[f]);
        if (/^[0-7]{3}$/.test(mode)) {
          state[f] = mode.split('').map(Number);
        } else {
          const clauses = mode.split(',');
          for (const c of clauses) {
            const m = c.match(/^([ugoa]*)([+\-=])([rwx]*)$/);
            if (!m) return { ok: false, error: 'Mode "' + mode + '" is not valid chmod syntax (try 640 or g-r).' };
            const who = (m[1] || 'a').replace('a', 'ugo');
            const bits = (m[3].includes('r') ? 4 : 0) + (m[3].includes('w') ? 2 : 0) + (m[3].includes('x') ? 1 : 0);
            ['u', 'g', 'o'].forEach((w, i) => {
              if (!who.includes(w)) return;
              if (m[2] === '+') state[f][i] |= bits;
              else if (m[2] === '-') state[f][i] &= ~bits;
              else state[f][i] = bits;
            });
          }
        }
        if (!changed[f]) changed[f] = { before: before };
        changed[f].after = FH.numsToPerm(state[f]);
      }
    }
    return { ok: true, changed: changed };
  };

  // describe 'rw-r-----' as plain English
  FH.describePerm = function (p) {
    const names = ['Owner', 'Group', 'Others'];
    return names.map((n, i) => {
      const t = p.substr(i * 3, 3); const parts = [];
      if (t[0] === 'r') parts.push('read'); if (t[1] === 'w') parts.push('write'); if (t[2] === 'x') parts.push('execute');
      return n + ': ' + (parts.length ? parts.join(', ') : 'none');
    }).join(' · ');
  };

  /* ---------- source rendering (used by Evidence Locker + Mission Clock) ---------- */
  // returns HTML for one source; each line/row gets data-line="S2-4"
  FH.renderSource = function (src, opts) {
    opts = opts || {};
    let h = '<div class="src" data-src="' + src.id + '"><div class="src-title"><b>' + src.id.replace('S', 'Source ') + '</b> · ' + FH.esc(src.title) + '</div>';
    if (src.cmd) h += '<div class="src-cmd">$ ' + FH.esc(src.cmd) + '</div>';
    if (src.type === 'table') {
      h += '<table class="src-table"><thead><tr>' + src.head.map(c => '<th>' + FH.esc(c) + '</th>').join('') + '</tr></thead><tbody>';
      src.rows.forEach((r, i) => {
        h += '<tr class="ln" data-line="' + src.id + '-' + (i + 1) + '">' + r.map(c => '<td>' + FH.esc(c) + '</td>').join('') + '</tr>';
      });
      h += '</tbody></table>';
    } else {
      h += '<div class="src-log">';
      src.lines.forEach((l, i) => {
        h += '<div class="ln" data-line="' + src.id + '-' + (i + 1) + '"><span class="lnno">' + (i + 1) + '</span><span class="lntx">' + FH.esc(l) + '</span></div>';
      });
      h += '</div>';
    }
    return h + '</div>';
  };

  FH.lineLabel = function (id) {
    const [s, n] = id.split('-');
    return 'Source ' + s.slice(1) + (s === 'S1' ? ' rule ' : s === 'S6' ? ' item ' : s === 'S5' ? ' row ' : ' line ') + n;
  };

  window.FH = FH;
})();
