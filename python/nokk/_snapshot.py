"""A compact, agent-readable outline of the page.

The page's text in reading order, with every control an agent can act on
numbered: ``- button "Sign in" [e5]``. The numbered elements come back as one
CDP remote object, so ``click``/``fill`` reach them by number without marking
the page: nothing is written to the DOM or to a global the page could read.
"""

# Evaluated with returnByValue=false: the result is [outline, el1, el2, ...],
# and element N is the remote array's index N.
SNAPSHOT_JS = r"""
((rootSel, maxChars) => {
  const root = rootSel ? document.querySelector(rootSel) : document.body || document.documentElement;
  if (!root) return [null];
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'META', 'LINK', 'IFRAME', 'OBJECT', 'EMBED', 'CANVAS']);
  const BLOCK = new Set(['ADDRESS', 'ARTICLE', 'ASIDE', 'BLOCKQUOTE', 'BR', 'DD', 'DETAILS', 'DIALOG', 'DIV', 'DL', 'DT',
    'FIELDSET', 'FIGCAPTION', 'FIGURE', 'FOOTER', 'FORM', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'HEADER', 'HR', 'LI',
    'MAIN', 'NAV', 'OL', 'P', 'PRE', 'SECTION', 'SUMMARY', 'TABLE', 'TBODY', 'THEAD', 'TFOOT', 'TR', 'UL']);
  const LANDMARK = { HEADER: 'header', NAV: 'navigation', MAIN: 'main', ASIDE: 'aside', FOOTER: 'footer', FORM: 'form', DIALOG: 'dialog' };
  const ROLES = new Set(['button', 'link', 'checkbox', 'radio', 'switch', 'tab', 'menuitem', 'menuitemcheckbox',
    'menuitemradio', 'option', 'combobox', 'textbox', 'searchbox', 'slider', 'spinbutton']);
  const els = [];
  const out = [];
  let size = 0;
  let cut = false;
  let line = '';

  const clean = (s) => (s || '').replace(/\s+/g, ' ').trim();
  const clip = (s, n) => (s.length > n ? s.slice(0, n - 1) + '…' : s);
  const q = (s) => JSON.stringify(s);
  const emit = (depth, s) => {
    if (cut) return;
    const l = '  '.repeat(depth) + s;
    if (size + l.length + 1 > maxChars) { cut = true; return; }
    out.push(l);
    size += l.length + 1;
  };
  const flush = (depth) => {
    const t = clean(line);
    line = '';
    // Separators alone (`|`, `•`, `·`) carry nothing an agent reads.
    if (/[\p{L}\p{N}]/u.test(t)) emit(depth, '- text: ' + clip(t, 400));
  };
  const hidden = (el) => {
    if (el.hidden || el.getAttribute('aria-hidden') === 'true') return true;
    if (el.tagName === 'INPUT' && (el.getAttribute('type') || '').toLowerCase() === 'hidden') return true;
    const cs = getComputedStyle(el);
    return cs.display === 'none' || cs.visibility === 'hidden';
  };
  const byIds = (ids) => clean(ids.split(/\s+/).map((id) => {
    const e = document.getElementById(id);
    return e ? e.textContent : '';
  }).join(' '));
  const name = (el) => {
    const aria = el.getAttribute('aria-label');
    if (aria && clean(aria)) return clean(aria);
    const lb = el.getAttribute('aria-labelledby');
    if (lb) { const t = byIds(lb); if (t) return t; }
    const tag = el.tagName;
    if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') {
      if (el.id) {
        const l = document.querySelector('label[for="' + CSS.escape(el.id) + '"]');
        if (l && clean(l.textContent)) return clean(l.textContent);
      }
      const wrap = el.closest('label');
      if (wrap && clean(wrap.textContent)) return clean(wrap.textContent);
      const type = (el.getAttribute('type') || '').toLowerCase();
      if (['submit', 'button', 'reset'].includes(type)) return clean(el.value) || type;
      return clean(el.getAttribute('placeholder') || el.getAttribute('title') || el.getAttribute('name') || '');
    }
    const text = clean(el.textContent);
    if (text) return text;
    const img = el.querySelector('img[alt]');
    if (img && clean(img.getAttribute('alt'))) return clean(img.getAttribute('alt'));
    if (clean(el.getAttribute('title'))) return clean(el.getAttribute('title'));
    const titled = el.querySelector('[title], [aria-label]');
    return titled ? clean(titled.getAttribute('aria-label') || titled.getAttribute('title')) : '';
  };
  const role = (el) => {
    const r = (el.getAttribute('role') || '').toLowerCase();
    if (ROLES.has(r)) return r;
    const tag = el.tagName;
    if (tag === 'A' && el.hasAttribute('href')) return 'link';
    if (tag === 'BUTTON' || tag === 'SUMMARY') return 'button';
    if (tag === 'SELECT') return 'combobox';
    if (tag === 'TEXTAREA') return 'textbox';
    if (tag === 'INPUT') {
      const t = (el.getAttribute('type') || 'text').toLowerCase();
      if (['submit', 'button', 'reset', 'image'].includes(t)) return 'button';
      if (t === 'checkbox' || t === 'radio') return t;
      if (t === 'range') return 'slider';
      if (t === 'number') return 'spinbutton';
      if (t === 'search') return 'searchbox';
      return 'textbox';
    }
    if (el.isContentEditable && el.getAttribute('contenteditable') !== null) return 'textbox';
    if (el.hasAttribute('onclick')) return 'button';
    return null;
  };
  const describe = (el, r) => {
    els.push(el);
    const n = clip(name(el), 100);
    let s = '- ' + r + (n ? ' ' + q(n) : '') + ' [e' + els.length + ']';
    const tag = el.tagName;
    if (r === 'link') {
      const href = el.getAttribute('href');
      if (href && !href.startsWith('javascript:')) s += ' -> ' + clip(href, 120);
    }
    if (tag === 'INPUT' || tag === 'TEXTAREA') {
      const t = (el.getAttribute('type') || '').toLowerCase();
      if (r === 'checkbox' || r === 'radio') s += el.checked ? ' (checked)' : '';
      else if (!['submit', 'button', 'reset', 'image'].includes(t)) {
        if (t && t !== 'text') s += ' type=' + t;
        if (el.value) s += ' value=' + q(clip(t === 'password' ? '***' : el.value, 80));
      }
    }
    if (tag === 'SELECT') {
      const opts = [...el.options];
      const sel = opts.find((o) => o.selected);
      if (sel) s += ' value=' + q(clip(clean(sel.textContent), 60));
      s += ' options=' + q(opts.slice(0, 12).map((o) => clip(clean(o.textContent), 40)).join(' | ') + (opts.length > 12 ? ' | …' : ''));
    }
    if (el.disabled) s += ' (disabled)';
    return s;
  };

  const walk = (node, depth) => {
    if (cut) return;
    if (node.nodeType === 3) { line += node.data; return; }
    if (node.nodeType !== 1) return;
    const el = node;
    const tag = el.tagName;
    if (SKIP.has(tag) || hidden(el)) return;
    const r = role(el);
    if (r) {
      flush(depth);
      emit(depth, describe(el, r));
      return;
    }
    if (/^H[1-6]$/.test(tag)) {
      flush(depth);
      const t = clean(el.textContent);
      if (t) emit(depth, '- heading ' + q(clip(t, 200)) + ' [level=' + tag[1] + ']');
      return;
    }
    if (tag === 'IMG') {
      const alt = clean(el.getAttribute('alt'));
      if (alt) { flush(depth); emit(depth, '- img ' + q(clip(alt, 100))); }
      return;
    }
    const land = LANDMARK[tag] || null;
    const block = BLOCK.has(tag) || land;
    if (block) flush(depth);
    let d = depth;
    if (land) { emit(depth, '- ' + land + ':'); d = depth + 1; }
    const kids = el.shadowRoot ? el.shadowRoot.childNodes : el.childNodes;
    for (const c of kids) walk(c, d);
    if (tag === 'TD' || tag === 'TH') line += ' ';
    else if (block) flush(d);
  };

  walk(root, 0);
  flush(0);
  if (cut) out.push('[cut at ' + maxChars + ' characters: pass a larger max_chars or a selector]');
  const head = '- page ' + q(document.title) + ' ' + location.href;
  return [head + '\n' + out.join('\n'), ...els];
})
"""
