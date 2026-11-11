"""The page's main content as Markdown, for a language model to read.

Navigation, headers, footers, sidebars, scripts and hidden elements are left
out; headings, paragraphs, lists, tables, code and links are kept. Long pages
come in parts: the result says where the next part starts.
"""

# Evaluated with returnByValue=true: the result is the Markdown, or null when
# the selector matches nothing.
MARKDOWN_JS = r"""
((rootSel, maxChars, offset, linkMode) => {
  const SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'META', 'LINK', 'IFRAME', 'OBJECT', 'EMBED',
    'CANVAS', 'SVG', 'BUTTON', 'SELECT', 'OPTION', 'INPUT', 'TEXTAREA', 'DIALOG', 'NAV', 'ASIDE', 'MENU']);
  const INLINE = new Set(['A', 'ABBR', 'B', 'BDI', 'BDO', 'BR', 'CITE', 'CODE', 'DATA', 'DEL', 'DFN', 'EM', 'FONT', 'I',
    'IMG', 'INS', 'KBD', 'LABEL', 'MARK', 'Q', 'S', 'SAMP', 'SMALL', 'SPAN', 'STRIKE', 'STRONG', 'SUB', 'SUP', 'TIME',
    'TT', 'U', 'VAR', 'WBR']);
  const SKIP_ROLES = new Set(['navigation', 'complementary', 'search', 'dialog', 'alertdialog', 'menu', 'menubar', 'toolbar', 'tablist']);
  const PAGE_ROLES = new Set(['banner', 'contentinfo']);
  const NOISE = /(^|[\s_-])(cookie|consent|gdpr)([\s_-]|$)/i;

  const textLen = (e) => (e && e.textContent ? e.textContent.replace(/\s+/g, ' ').trim().length : 0);
  let root, whole = false;
  if (rootSel) {
    root = document.querySelector(rootSel);
    if (!root) return null;
  } else {
    const main = document.querySelector('main, [role="main"]');
    const arts = document.querySelectorAll('article');
    if (main && textLen(main) >= 200) root = main;
    else if (arts.length === 1 && textLen(arts[0]) >= 200) root = arts[0];
    else { root = document.body || document.documentElement; whole = true; }
  }

  const here = location.origin;
  const refs = [];
  const url = (raw) => {
    if (!raw) return '';
    let u;
    try { u = new URL(raw, document.baseURI); } catch (e) { return ''; }
    if (u.protocol === 'javascript:') return '';
    if (u.origin === here) {
      // A jump within this page carries nothing for a reader.
      if (u.pathname === location.pathname && u.search === location.search && u.hash) return '';
      return u.pathname + u.search + u.hash;
    }
    return u.href;
  };
  const skipped = (el) => {
    const tag = el.tagName;
    if (SKIP.has(tag)) return true;
    const role = (el.getAttribute('role') || '').toLowerCase();
    if (SKIP_ROLES.has(role)) return true;
    if (whole && (tag === 'HEADER' || tag === 'FOOTER' || PAGE_ROLES.has(role))) return true;
    if (el.hidden || el.getAttribute('aria-hidden') === 'true') return true;
    const id = el.id || '', cls = typeof el.className === 'string' ? el.className : '';
    if (NOISE.test(id) || NOISE.test(cls)) return true;
    const cs = getComputedStyle(el);
    return cs.display === 'none' || cs.visibility === 'hidden';
  };
  const kids = (el) => (el.shadowRoot ? el.shadowRoot.childNodes : el.childNodes);
  const squash = (s) => s.replace(/[ \t\r\f\v ]+/g, ' ');
  // Emphasis hugs the words: the spaces around them stay outside the marks.
  const wrap = (mark, s) => {
    const m = /^(\s*)([\s\S]*?)(\s*)$/.exec(s);
    return m[2] ? m[1] + mark + m[2] + mark + m[3] : s;
  };

  const inline = (node) => {
    if (node.nodeType === 3) return squash(node.data).replace(/\n/g, ' ');
    if (node.nodeType !== 1 || skipped(node)) return '';
    const el = node, tag = el.tagName;
    if (tag === 'BR') return '\n';
    if (tag === 'IMG') {
      // The words, not the address: a model reads the alt text. Icons say nothing.
      const alt = squash(el.getAttribute('alt') || '').trim();
      const w = +el.getAttribute('width') || 0, h = +el.getAttribute('height') || 0;
      if (!alt || (w && w <= 32) || (h && h <= 32)) return '';
      return '[image: ' + alt + ']';
    }
    let inner = '';
    for (const c of kids(el)) inner += inline(c);
    if (tag === 'A') {
      const text = inner.replace(/\s+/g, ' ').trim();
      const href = url(el.getAttribute('href'));
      if (!text || !href || linkMode === 'none') return inner;
      if (linkMode === 'refs') {
        refs.push(href);
        return '[' + text + '][' + refs.length + ']';
      }
      return '[' + text + '](' + href + ')';
    }
    if (tag === 'STRONG' || tag === 'B') return wrap('**', inner);
    if (tag === 'EM' || tag === 'I') return wrap('*', inner);
    if (tag === 'DEL' || tag === 'S' || tag === 'STRIKE') return wrap('~~', inner);
    if (tag === 'CODE' || tag === 'KBD' || tag === 'SAMP' || tag === 'TT') {
      const t = inner.trim();
      return t ? '`' + t.replace(/`/g, '\\`') + '`' : '';
    }
    if (!INLINE.has(tag)) return ' ' + inner + ' ';
    return inner;
  };

  let out = [];
  let buf = '';
  const push = (text, prefix) => {
    out.push(text.split('\n').map((l) => (l ? prefix + l : prefix.trimEnd())).join('\n'));
  };
  const flush = (prefix) => {
    const t = buf.split('\n').map((l) => l.replace(/\s+/g, ' ').trim()).filter(Boolean).join('\n');
    buf = '';
    if (/[\p{L}\p{N}]/u.test(t)) push(t, prefix);
  };
  const collect = (fn) => {
    const saved = out, savedBuf = buf;
    out = []; buf = '';
    fn();
    const got = out;
    out = saved; buf = savedBuf;
    return got;
  };

  const cell = (td) => {
    let s = '';
    for (const c of kids(td)) s += inline(c);
    return s.replace(/\s+/g, ' ').trim().replace(/\|/g, '\\|');
  };
  const rowsOf = (table) => [...table.querySelectorAll(':scope > tr, :scope > thead > tr, :scope > tbody > tr, :scope > tfoot > tr')];
  const table = (el, prefix) => {
    const rows = rowsOf(el);
    const grid = rows.map((r) => [...r.children].filter((c) => c.tagName === 'TD' || c.tagName === 'TH'));
    const cols = Math.max(0, ...grid.map((r) => r.length));
    // A table used for layout (nested tables, one column, a block inside a
    // cell) reads as its content, not as a grid.
    const headed = !!el.querySelector('th');
    const layout = cols < 2 || (el.getAttribute('role') || '') === 'presentation' || el.querySelector('table')
      || grid.some((r) => r.some((c) => c.querySelector('p, div, ul, ol, h1, h2, h3, h4, h5, h6, pre, blockquote')))
      || (!headed && (grid.length < 2 || grid.some((r) => r.some((c) => textLen(c) > 100))));
    if (layout) { walk(el, prefix); return; }
    const lines = grid.map((r) => {
      const cells = r.map(cell);
      while (cells.length < cols) cells.push('');
      return '| ' + cells.join(' | ') + ' |';
    }).filter((l) => /[\p{L}\p{N}]/u.test(l));
    if (!lines.length) return;
    lines.splice(1, 0, '|' + ' --- |'.repeat(cols));
    const cap = el.querySelector(':scope > caption');
    if (cap && cap.textContent.trim()) push('*' + cap.textContent.replace(/\s+/g, ' ').trim() + '*', prefix);
    push(lines.join('\n'), prefix);
  };
  const list = (el, prefix) => {
    const ordered = el.tagName === 'OL';
    let n = parseInt(el.getAttribute('start') || '1', 10) || 1;
    const items = [];
    for (const li of el.children) {
      if (li.tagName !== 'LI' || skipped(li)) continue;
      const marker = ordered ? n++ + '. ' : '- ';
      const parts = collect(() => { walk(li, ''); flush(''); });
      const text = parts.join('\n');
      if (!/[\p{L}\p{N}]/u.test(text)) continue;
      const pad = ' '.repeat(marker.length);
      items.push(text.split('\n').map((l, i) => (i ? (l ? pad + l : '') : marker + l)).join('\n'));
    }
    if (items.length) push(items.join('\n'), prefix);
  };

  const walk = (el, prefix) => {
    for (const node of kids(el)) {
      if (node.nodeType === 3) { buf += node.data; continue; }
      if (node.nodeType !== 1 || skipped(node)) continue;
      const tag = node.tagName;
      if (INLINE.has(tag)) { buf += inline(node); continue; }
      flush(prefix);
      if (/^H[1-6]$/.test(tag)) {
        let t = '';
        for (const c of kids(node)) t += inline(c);
        t = t.replace(/\s+/g, ' ').trim();
        if (t) push('#'.repeat(+tag[1]) + ' ' + t, prefix);
      } else if (tag === 'PRE') {
        const code = node.textContent.replace(/\n+$/, '');
        const m = /(?:^|\s)(?:language|lang)-([\w+#-]+)/.exec((node.className || '') + ' ' + ((node.querySelector('code') || {}).className || ''));
        if (code.trim()) push('```' + (m ? m[1] : '') + '\n' + code + '\n```', prefix);
      } else if (tag === 'UL' || tag === 'OL') {
        list(node, prefix);
      } else if (tag === 'BLOCKQUOTE') {
        walk(node, prefix + '> ');
        flush(prefix + '> ');
      } else if (tag === 'TABLE') {
        table(node, prefix);
      } else if (tag === 'TR' && ![...node.querySelectorAll('p, div, ul, ol, h1, h2, h3, h4, h5, h6, pre, blockquote, table')].some((b) => textLen(b) > 0)) {
        // A row of a layout table is one line of text.
        let t = '';
        for (const c of node.children) {
          if (skipped(c)) continue;
          for (const k of kids(c)) t += inline(k);
          t += ' ';
        }
        buf += t;
        flush(prefix);
      } else if (tag === 'HR') {
        out.push(prefix + '---');
      } else if (tag === 'DT') {
        let t = '';
        for (const c of kids(node)) t += inline(c);
        t = t.replace(/\s+/g, ' ').trim();
        if (t) push('**' + t + '**', prefix);
      } else if (tag === 'FIGCAPTION') {
        let t = '';
        for (const c of kids(node)) t += inline(c);
        t = t.replace(/\s+/g, ' ').trim();
        if (t) push('*' + t + '*', prefix);
      } else {
        walk(node, prefix);
        flush(prefix);
      }
    }
  };

  walk(root, '');
  flush('');
  let md = out.join('\n\n');
  if (refs.length) md += '\n\n' + refs.map((h, i) => '[' + (i + 1) + ']: ' + h).join('\n');

  const head = 'Title: ' + document.title.replace(/\s+/g, ' ').trim() + '\nURL: ' + location.href + '\n\n';
  const total = md.length;
  let start = Math.max(0, Math.min(offset | 0, total));
  let end = Math.min(total, start + maxChars);
  // End on a paragraph, else a line, when one is near, so a part does not stop mid-sentence.
  if (end < total) {
    const para = md.lastIndexOf('\n\n', end), line = md.lastIndexOf('\n', end);
    if (para > start + maxChars / 2) end = para;
    else if (line > start + maxChars / 2) end = line;
  }
  let body = md.slice(start, end).replace(/^\n+/, '');
  if (end < total) body += '\n\n[part: characters ' + start + '–' + end + ' of ' + total + '; the next part starts at offset=' + end + ']';
  return head + body;
})
"""
