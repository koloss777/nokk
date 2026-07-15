// Pure-JS DOM runtime for the nokk engine.
//
// Runs once per V8 context, after the stealth environment bootstrap. Defines a
// minimal but real DOM (Node/Element/Text/Comment/Document, events, selectors)
// entirely as JS objects — no native bindings. The Rust side hands over a parsed
// tree via __pt_installDocument(tree); page scripts then see a normal `document`.
//
// Scope: enough for typical page and fingerprint scripts. No layout, no
// rendering, no CSS cascade. Selector support: tag, #id, .class, [attr],
// [attr=val], *, plus descendant (space) and child (>) combinators and comma
// lists.
(() => {
  const ELEMENT_NODE = 1, TEXT_NODE = 3, COMMENT_NODE = 8,
        DOCUMENT_NODE = 9, DOCUMENT_FRAGMENT_NODE = 11;

  const VOID = new Set(['area','base','br','col','embed','hr','img','input',
    'link','meta','param','source','track','wbr']);

  // ---- Node -----------------------------------------------------------------
  class Node {
    constructor(type) {
      this.nodeType = type;
      this.childNodes = [];
      this.parentNode = null;
      this.ownerDocument = globalThis.document || null;
      this._listeners = Object.create(null);
    }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get nextSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = p.childNodes.indexOf(this); return p.childNodes[i + 1] || null;
    }
    get previousSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = p.childNodes.indexOf(this); return p.childNodes[i - 1] || null;
    }
    hasChildNodes() { return this.childNodes.length > 0; }
    contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }

    appendChild(child) { return this.insertBefore(child, null); }
    insertBefore(child, ref) {
      if (child.nodeType === DOCUMENT_FRAGMENT_NODE) {
        for (const c of child.childNodes.slice()) this.insertBefore(c, ref);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      const i = ref ? this.childNodes.indexOf(ref) : -1;
      if (i < 0) this.childNodes.push(child); else this.childNodes.splice(i, 0, child);
      child.parentNode = this;
      return child;
    }
    removeChild(child) {
      const i = this.childNodes.indexOf(child);
      if (i < 0) throw new Error('NotFoundError: removeChild');
      this.childNodes.splice(i, 1); child.parentNode = null; return child;
    }
    replaceChild(nw, old) { this.insertBefore(nw, old); return this.removeChild(old); }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    cloneNode(deep) {
      const c = this._shallowClone();
      if (deep) for (const ch of this.childNodes) c.appendChild(ch.cloneNode(true));
      return c;
    }

    get textContent() {
      let s = ''; for (const c of this.childNodes) s += c.textContent; return s;
    }
    set textContent(v) {
      this.childNodes = [];
      if (v !== '') this.appendChild(new Text(String(v)));
    }

    // EventTarget
    addEventListener(type, fn, opts) {
      if (!fn) return;
      const cap = !!(opts && (opts === true || opts.capture));
      (this._listeners[type] || (this._listeners[type] = [])).push({ fn, cap });
    }
    removeEventListener(type, fn, opts) {
      const cap = !!(opts && (opts === true || opts.capture));
      const l = this._listeners[type]; if (!l) return;
      this._listeners[type] = l.filter(e => !(e.fn === fn && e.cap === cap));
    }
    dispatchEvent(event) {
      event.target = this;
      // Build the ancestor path for capture/bubble.
      const path = []; for (let n = this; n; n = n.parentNode) path.push(n);
      // Capture phase (root -> target), then bubble (target -> root).
      const fire = (node) => {
        const l = node._listeners[event.type]; if (!l) return;
        for (const { fn } of l.slice()) {
          if (event._stopImmediate) break;
          event.currentTarget = node;
          try { fn.call(node, event); } catch (e) { /* page handler threw */ }
        }
      };
      for (let i = path.length - 1; i >= 1; i--) { if (event._stop) break; if (path[i]._listeners[event.type]) { event.eventPhase = 1; fireCapture(path[i], event); } }
      event.eventPhase = 2; if (!event._stop) fire(this);
      if (event.bubbles) for (let i = 1; i < path.length; i++) { if (event._stop) break; event.eventPhase = 3; fire(path[i]); }
      return !event.defaultPrevented;
    }
  }
  function fireCapture(node, event) {
    const l = node._listeners[event.type]; if (!l) return;
    for (const e of l.slice()) { if (!e.cap) continue; if (event._stopImmediate) break; event.currentTarget = node; try { e.fn.call(node, event); } catch (_) {} }
  }

  // ---- CharacterData: Text / Comment ---------------------------------------
  class Text extends Node {
    constructor(data) { super(TEXT_NODE); this.data = String(data); }
    get nodeName() { return '#text'; }
    get nodeValue() { return this.data; }
    set nodeValue(v) { this.data = String(v); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
    _shallowClone() { return new Text(this.data); }
  }
  class Comment extends Node {
    constructor(data) { super(COMMENT_NODE); this.data = String(data); }
    get nodeName() { return '#comment'; }
    get nodeValue() { return this.data; }
    get textContent() { return ''; }
    _shallowClone() { return new Comment(this.data); }
  }

  // ---- Element --------------------------------------------------------------
  class Element extends Node {
    constructor(tag) {
      super(ELEMENT_NODE);
      this.tagName = String(tag).toUpperCase();
      this.localName = String(tag).toLowerCase();
      this._attrs = new Map();
      this.style = makeStyle();
    }
    get nodeName() { return this.tagName; }

    // Attributes
    getAttribute(n) { const v = this._attrs.get(n.toLowerCase()); return v === undefined ? null : v; }
    setAttribute(n, v) { this._attrs.set(n.toLowerCase(), String(v)); }
    removeAttribute(n) { this._attrs.delete(n.toLowerCase()); }
    hasAttribute(n) { return this._attrs.has(n.toLowerCase()); }
    getAttributeNames() { return [...this._attrs.keys()]; }
    get attributes() { return [...this._attrs].map(([name, value]) => ({ name, value })); }

    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }
    get classList() { return makeClassList(this); }
    get dataset() { return makeDataset(this); }

    get children() { return this.childNodes.filter(n => n.nodeType === ELEMENT_NODE); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() { let n = this.nextSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.previousSibling; return n; }

    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }

    // Queries (scoped to this subtree)
    getElementById(id) { return firstMatch(this, e => e.id === id); }
    getElementsByTagName(t) { const tag = t.toUpperCase(); return collect(this, e => t === '*' || e.tagName === tag); }
    getElementsByClassName(c) { const cs = c.split(/\s+/).filter(Boolean); return collect(this, e => cs.every(x => e.classList.contains(x))); }
    querySelector(sel) { return query(this, sel)[0] || null; }
    querySelectorAll(sel) { return query(this, sel); }
    closest(sel) { for (let e = this; e; e = e.parentNode) if (e.nodeType === ELEMENT_NODE && matchesSelector(e, sel)) return e; return null; }
    matches(sel) { return matchesSelector(this, sel); }

    // Serialization
    get innerHTML() { return this.childNodes.map(serializeNode).join(''); }
    set innerHTML(html) { this.childNodes = []; for (const n of parseFragment(String(html))) this.appendChild(n); }
    get outerHTML() { return serializeNode(this); }
    insertAdjacentHTML(pos, html) {
      const nodes = parseFragment(String(html));
      if (pos === 'beforeend') for (const n of nodes) this.appendChild(n);
      else if (pos === 'afterbegin') for (const n of nodes.reverse()) this.insertBefore(n, this.firstChild);
      else if (pos === 'beforebegin') for (const n of nodes) this.parentNode.insertBefore(n, this);
      else if (pos === 'afterend') for (const n of nodes.reverse()) this.parentNode.insertBefore(n, this.nextSibling);
    }

    // Stubs — no layout engine.
    getBoundingClientRect() { return { x: 0, y: 0, top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
    focus() {} blur() {} scrollIntoView() {}
    click() { this.dispatchEvent(new Event('click', { bubbles: true, cancelable: true })); }

    _shallowClone() { const e = new Element(this.localName); e._attrs = new Map(this._attrs); return e; }
  }

  // ---- Document -------------------------------------------------------------
  class Document extends Node {
    constructor() {
      super(DOCUMENT_NODE);
      this.documentElement = null;
      this.readyState = 'loading';
      this._cookie = '';
    }
    get nodeName() { return '#document'; }
    get head() { return this.documentElement && this.documentElement.getElementsByTagName('head')[0] || null; }
    get body() { return this.documentElement && this.documentElement.getElementsByTagName('body')[0] || null; }
    get title() { const t = this.getElementsByTagName('title')[0]; return t ? t.textContent.trim() : ''; }
    set title(v) {
      let t = this.getElementsByTagName('title')[0];
      if (!t) { t = this.createElement('title'); (this.head || this.documentElement || this).appendChild(t); }
      t.textContent = String(v);
    }
    get cookie() { return this._cookie; }
    set cookie(v) {
      const pair = String(v).split(';')[0];
      const eq = pair.indexOf('=');
      if (eq < 0) return;
      const name = pair.slice(0, eq).trim();
      const jar = this._cookie ? this._cookie.split('; ') : [];
      const kept = jar.filter(c => c.split('=')[0] !== name);
      kept.push(pair.trim());
      this._cookie = kept.join('; ');
    }

    createElement(tag) { const e = new Element(tag); e.ownerDocument = this; return e; }
    createElementNS(_ns, tag) { return this.createElement(tag); }
    createTextNode(t) { const n = new Text(t); n.ownerDocument = this; return n; }
    createComment(t) { const n = new Comment(t); n.ownerDocument = this; return n; }
    createDocumentFragment() { const f = new Node(DOCUMENT_FRAGMENT_NODE); f.ownerDocument = this; return f; }
    createEvent() { return new Event(''); }

    getElementById(id) { return this.documentElement ? this.documentElement.getElementById(id) : null; }
    getElementsByTagName(t) { return this.documentElement ? this.documentElement.getElementsByTagName(t) : []; }
    getElementsByClassName(c) { return this.documentElement ? this.documentElement.getElementsByClassName(c) : []; }
    querySelector(s) { return this.documentElement ? this.documentElement.querySelector(s) : null; }
    querySelectorAll(s) { return this.documentElement ? this.documentElement.querySelectorAll(s) : []; }

    // document.write inserts parsed markup at the position of the script that
    // called it (tracked as `currentScript`), matching in-parse behaviour for the
    // common `<script>document.write(x)</script>` idiom. With no current script
    // (e.g. async), it appends to <body>. Dynamically written <script> tags are
    // inserted but not executed (our script list is fixed at parse time).
    write(...args) {
      const nodes = parseFragment(args.join(''));
      const cur = this.currentScript;
      if (cur && cur.parentNode) {
        const ref = cur.nextSibling;
        for (const n of nodes) cur.parentNode.insertBefore(n, ref);
      } else {
        const host = this.body || this.documentElement;
        if (host) for (const n of nodes) host.appendChild(n);
      }
    }
    writeln(...args) { this.write(args.join('') + '\n'); }
    open() { return this; }
    close() {}
    _shallowClone() { return new Document(); }
  }

  // ---- Event ----------------------------------------------------------------
  class Event {
    constructor(type, init) {
      init = init || {};
      this.type = type;
      this.bubbles = !!init.bubbles;
      this.cancelable = !!init.cancelable;
      this.defaultPrevented = false;
      this.target = null; this.currentTarget = null; this.eventPhase = 0;
      this.timeStamp = 0;
      this._stop = false; this._stopImmediate = false;
    }
    preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
    stopPropagation() { this._stop = true; }
    stopImmediatePropagation() { this._stop = true; this._stopImmediate = true; }
  }
  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); this.detail = (init && init.detail) || null; }
  }

  // ---- helpers: classList, dataset, style -----------------------------------
  function makeClassList(el) {
    const get = () => (el.getAttribute('class') || '').split(/\s+/).filter(Boolean);
    const set = (arr) => el.setAttribute('class', arr.join(' '));
    return {
      contains: (c) => get().includes(c),
      add: (...cs) => { const s = get(); for (const c of cs) if (!s.includes(c)) s.push(c); set(s); },
      remove: (...cs) => set(get().filter(c => !cs.includes(c))),
      toggle: (c, force) => { const s = get(); const has = s.includes(c);
        if (force === true || (force === undefined && !has)) { if (!has) s.push(c); set(s); return true; }
        set(s.filter(x => x !== c)); return false; },
      get length() { return get().length; },
      item: (i) => get()[i] || null,
      toString: () => get().join(' '),
    };
  }
  function makeDataset(el) {
    const target = {};
    for (const k of el.getAttributeNames()) if (k.startsWith('data-'))
      target[camel(k.slice(5))] = el.getAttribute(k);
    return new Proxy(target, {
      get: (t, p) => el.getAttribute('data-' + dash(String(p))) ?? undefined,
      set: (t, p, v) => { el.setAttribute('data-' + dash(String(p)), v); return true; },
      has: (t, p) => el.hasAttribute('data-' + dash(String(p))),
    });
  }
  const camel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
  const dash = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
  function makeStyle() {
    const map = new Map();
    return new Proxy({
      getPropertyValue: (p) => map.get(p) || '',
      setProperty: (p, v) => map.set(p, v),
      removeProperty: (p) => map.delete(p),
      get cssText() { return [...map].map(([k, v]) => `${k}: ${v}`).join('; '); },
    }, {
      get: (t, p) => p in t ? t[p] : (map.get(dash(String(p))) || ''),
      set: (t, p, v) => { map.set(dash(String(p)), String(v)); return true; },
    });
  }

  // ---- tree walking ---------------------------------------------------------
  function collect(root, pred) {
    const out = []; walk(root, e => { if (pred(e)) out.push(e); });
    out.item = (i) => out[i] || null; return out;
  }
  function firstMatch(root, pred) {
    let found = null; walk(root, e => { if (!found && pred(e)) found = e; }); return found;
  }
  function walk(node, visit) {
    for (const c of node.childNodes) {
      if (c.nodeType === ELEMENT_NODE) { visit(c); walk(c, visit); }
    }
  }

  // ---- selector engine ------------------------------------------------------
  // Compound selector -> predicate. Combinators handled in query().
  function parseCompound(part) {
    const tests = [];
    const re = /([#.]?[\w-]+|\[[^\]]+\]|\*)/g; let m;
    while ((m = re.exec(part))) {
      const tok = m[1];
      if (tok === '*') continue;
      else if (tok[0] === '#') tests.push(e => e.id === tok.slice(1));
      else if (tok[0] === '.') tests.push(e => e.classList.contains(tok.slice(1)));
      else if (tok[0] === '[') {
        // [name] / [name=v] / [name^=v] [name$=v] [name*=v] [name~=v] [name|=v]
        const am = /^\s*([\w-]+)\s*(?:([~^$*|]?=)\s*(.*?))?\s*$/.exec(tok.slice(1, -1));
        if (!am) { tests.push(() => false); continue; }
        const name = am[1], op = am[2];
        if (!op) { tests.push(e => e.hasAttribute(name)); continue; }
        const val = (am[3] || '').replace(/^["']|["']$/g, '');
        tests.push(e => {
          const a = e.getAttribute(name);
          if (a == null) return false;
          switch (op) {
            case '=': return a === val;
            case '^=': return val !== '' && a.slice(0, val.length) === val;
            case '$=': return val !== '' && a.slice(-val.length) === val;
            case '*=': return val !== '' && a.indexOf(val) >= 0;
            case '~=': return val !== '' && a.split(/\s+/).indexOf(val) >= 0;
            case '|=': return a === val || a.slice(0, val.length + 1) === val + '-';
            default: return false;
          }
        });
      } else tests.push(e => e.localName === tok.toLowerCase());
    }
    return (e) => tests.every(t => t(e));
  }
  // Parse one selector branch (no commas) into compound predicates plus the
  // combinators between them, e.g. `nav > ul a` -> compounds [nav, ul, a],
  // combinators ['child', 'descendant'] (combinators[k] links compound k -> k+1).
  function parseComplex(sel) {
    const steps = sel.trim().replace(/\s*>\s*/g, ' > ').split(/\s+/).filter(Boolean);
    const compounds = [], combinators = [];
    let comb = 'descendant';
    for (const s of steps) {
      if (s === '>') { comb = 'child'; continue; }
      if (compounds.length) combinators.push(comb);
      compounds.push(parseCompound(s));
      comb = 'descendant';
    }
    return { compounds, combinators };
  }
  // Match `el` against compounds[idx] then walk left through the combinators,
  // verifying an ancestor (descendant) or parent (child) for each earlier
  // compound. Descendant combinators backtrack over all ancestors.
  function matchesSteps(el, compounds, combinators, idx) {
    if (!compounds[idx](el)) return false;
    if (idx === 0) return true;
    const comb = combinators[idx - 1];
    if (comb === 'child') {
      const p = el.parentNode;
      return !!p && p.nodeType === ELEMENT_NODE && matchesSteps(p, compounds, combinators, idx - 1);
    }
    for (let p = el.parentNode; p && p.nodeType === ELEMENT_NODE; p = p.parentNode) {
      if (matchesSteps(p, compounds, combinators, idx - 1)) return true;
    }
    return false;
  }
  function matchesSelector(el, selector) {
    if (!el || el.nodeType !== ELEMENT_NODE) return false;
    return selector.split(',').some(sel => {
      const { compounds, combinators } = parseComplex(sel);
      return compounds.length > 0 && matchesSteps(el, compounds, combinators, compounds.length - 1);
    });
  }
  function query(root, selector) {
    const seen = new Set(); const results = [];
    for (const sel of selector.split(',')) {
      // Tokenize into (combinator, compound) steps.
      const raw = sel.trim().replace(/\s*>\s*/g, ' > ');
      const steps = raw.split(/\s+/).filter(Boolean);
      let current = [root];
      for (let i = 0; i < steps.length; i++) {
        let combinator = 'descendant';
        if (steps[i] === '>') { combinator = 'child'; i++; }
        const pred = parseCompound(steps[i]);
        const next = [];
        for (const ctx of current) {
          if (combinator === 'child') {
            for (const c of (ctx.children || [])) if (pred(c)) next.push(c);
          } else {
            walk(ctx, e => { if (pred(e)) next.push(e); });
          }
        }
        current = next;
      }
      for (const el of current) if (el !== root && !seen.has(el)) { seen.add(el); results.push(el); }
    }
    results.item = (i) => results[i] || null;
    return results;
  }

  // ---- HTML serialization (innerHTML getter) --------------------------------
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
  const esc = (s, attr) => s.replace(attr ? /[&<>"]/g : /[&<>]/g, c => ESC[c]);
  function serializeNode(n) {
    if (n.nodeType === TEXT_NODE) return esc(n.data, false);
    if (n.nodeType === COMMENT_NODE) return `<!--${n.data}-->`;
    if (n.nodeType !== ELEMENT_NODE) return n.childNodes.map(serializeNode).join('');
    const tag = n.localName;
    let attrs = '';
    for (const { name, value } of n.attributes) attrs += ` ${name}="${esc(value, true)}"`;
    if (VOID.has(tag)) return `<${tag}${attrs}>`;
    return `<${tag}${attrs}>${n.childNodes.map(serializeNode).join('')}</${tag}>`;
  }

  // ---- HTML fragment parser (innerHTML setter) ------------------------------
  // A forgiving tokenizer: handles tags, attributes (quoted/unquoted/bare),
  // text, comments, and void/self-closing elements. Not spec-perfect, but
  // covers the markup scripts typically inject.
  function parseFragment(html) {
    const doc = globalThis.document;
    const root = doc.createDocumentFragment();
    const stack = [root];
    const top = () => stack[stack.length - 1];
    let i = 0;
    while (i < html.length) {
      if (html[i] === '<') {
        if (html.startsWith('<!--', i)) {
          const end = html.indexOf('-->', i + 4);
          const stop = end < 0 ? html.length : end;
          top().appendChild(doc.createComment(html.slice(i + 4, stop)));
          i = end < 0 ? html.length : end + 3; continue;
        }
        const close = html[i + 1] === '/';
        const m = /^<\/?([a-zA-Z][\w-]*)((?:[^>"']|"[^"]*"|'[^']*')*)\/?>/.exec(html.slice(i));
        if (!m) { top().appendChild(doc.createTextNode('<')); i++; continue; }
        const tag = m[1].toLowerCase();
        if (close) {
          for (let s = stack.length - 1; s > 0; s--) if (stack[s].localName === tag) { stack.length = s; break; }
        } else {
          const el = doc.createElement(tag);
          for (const am of m[2].matchAll(/([\w-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g)) {
            let v = am[2] || '';
            if (v && (v[0] === '"' || v[0] === "'")) v = v.slice(1, -1);
            el.setAttribute(am[1], v);
          }
          top().appendChild(el);
          const selfClose = m[0].endsWith('/>') || VOID.has(tag);
          if (!selfClose) stack.push(el);
        }
        i += m[0].length;
      } else {
        const next = html.indexOf('<', i);
        const stop = next < 0 ? html.length : next;
        const text = html.slice(i, stop);
        if (text) top().appendChild(doc.createTextNode(unescapeEntities(text)));
        i = stop;
      }
    }
    return root.childNodes.slice();
  }
  function unescapeEntities(s) {
    return s.replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/g, (_, e) =>
      ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", apos: "'", nbsp: ' ' })[e]);
  }

  // ---- build DOM from the Rust-parsed tree ----------------------------------
  function buildNode(doc, spec) {
    if (spec.k === 't') return doc.createTextNode(spec.v);
    if (spec.k === 'c') return doc.createComment(spec.v);
    const el = doc.createElement(spec.tag);
    for (const [name, value] of spec.attrs) el.setAttribute(name, value);
    for (const child of spec.children) el.appendChild(buildNode(doc, child));
    return el;
  }

  // ---- install globals ------------------------------------------------------
  const document = new Document();
  globalThis.document = document;
  globalThis.Node = Node;
  globalThis.Element = Element;
  globalThis.HTMLElement = Element;
  globalThis.Text = Text;
  globalThis.Comment = Comment;
  globalThis.Document = Document;
  globalThis.Event = Event;
  globalThis.CustomEvent = CustomEvent;
  globalThis.DocumentFragment = Node;
  document.defaultView = globalThis;

  // <script> nodes in document order, so the loader can point `currentScript` at
  // the one it is about to run (for document.write positioning).
  let scriptNodes = [];

  // Called by the loader with the Rust-parsed <html> tree.
  globalThis.__pt_installDocument = (tree) => {
    document.childNodes = [];
    document.documentElement = null;
    document.currentScript = null;
    if (tree && tree.k === 'e') {
      const html = buildNode(document, tree);
      document.appendChild(html);
      document.documentElement = html;
    }
    scriptNodes = document.getElementsByTagName('script') || [];
    document.readyState = 'interactive';
  };

  // The loader brackets each page script with these so `document.currentScript`
  // (and therefore document.write's insertion point) is correct while it runs.
  // The index matches the loader's document-order script list.
  globalThis.__pt_beginScript = (i) => { document.currentScript = scriptNodes[i] || null; };
  globalThis.__pt_endScript = () => { document.currentScript = null; };

  // Called after all page scripts have run: fire DOMContentLoaded then load.
  globalThis.__pt_finishLoad = () => {
    document.readyState = 'complete';
    document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true }));
    if (globalThis.onload) { try { globalThis.onload(new Event('load')); } catch (_) {} }
    const l = globalThis._listeners && globalThis._listeners['load'];
    globalThis.dispatchEvent && globalThis.dispatchEvent(new Event('load'));
  };

  // window is an EventTarget too.
  if (!globalThis.addEventListener) {
    globalThis._listeners = Object.create(null);
    globalThis.addEventListener = Node.prototype.addEventListener.bind(globalThis);
    globalThis.removeEventListener = Node.prototype.removeEventListener.bind(globalThis);
    globalThis.dispatchEvent = (ev) => {
      const l = globalThis._listeners[ev.type]; if (l) for (const { fn } of l.slice()) { try { fn.call(globalThis, ev); } catch (_) {} }
      return true;
    };
  }

  // ---- CDP object registry (ElementHandle / JSHandle support) --------------
  // Non-value CDP results return an `objectId` handle instead of the value; the
  // server calls these to wrap/unwrap so Puppeteer's `$`/`$eval`/`.evaluate`
  // (which pass handles by objectId) work. Names start with `__pt` so the
  // stealth layer keeps them off `Object.keys(window)`.
  const __ptObjs = new Map();
  let __ptSeq = 1;
  globalThis.__pt_wrap = (v, byValue) => {
    const t = typeof v;
    if (v === null) return { type: 'object', subtype: 'null', value: null };
    if (t === 'undefined') return { type: 'undefined' };
    if (t === 'boolean' || t === 'number' || t === 'string') return { type: t, value: v };
    if (t === 'bigint') return { type: 'bigint', unserializableValue: String(v) };
    if (byValue) {
      try { return { type: t === 'function' ? 'object' : t, value: JSON.parse(JSON.stringify(v)) }; }
      catch (e) { return { type: 'object', value: null }; }
    }
    const id = 'obj-' + (__ptSeq++);
    __ptObjs.set(id, v);
    if (t === 'function') return { type: 'function', objectId: id, className: 'Function', description: (v.name ? 'function ' + v.name : 'function') + '() { [native code] }' };
    let subtype, className = (v.constructor && v.constructor.name) || 'Object', description = className;
    if (Array.isArray(v)) { subtype = 'array'; className = 'Array'; description = 'Array(' + v.length + ')'; }
    else if (v.nodeType === 1) { subtype = 'node'; description = v.localName || 'element'; }
    else if (v.nodeType) { subtype = 'node'; description = (v.nodeName || 'node').toLowerCase(); }
    return { type: 'object', subtype, objectId: id, className, description };
  };
  globalThis.__pt_objGet = (id) => __ptObjs.get(id);
  globalThis.__pt_release = (id) => { __ptObjs.delete(id); };

  // Stable backendNodeId per DOM node (Puppeteer's ElementHandle needs it).
  const __ptNodes = new Map();      // backendNodeId -> node
  const __ptNodeIds = new WeakMap(); // node -> backendNodeId
  let __ptNodeSeq = 1;
  globalThis.__pt_nodeId = (n) => {
    let id = __ptNodeIds.get(n);
    if (!id) { id = __ptNodeSeq++; __ptNodeIds.set(n, id); __ptNodes.set(id, n); }
    return id;
  };
  globalThis.__pt_nodeById = (id) => __ptNodes.get(id) || null;
  globalThis.__pt_describe = (n) => {
    if (n == null || !n.nodeType) return null;
    const attrs = [];
    if (n.attributes) for (const a of n.attributes) { attrs.push(a.name); attrs.push(a.value); }
    return {
      backendNodeId: globalThis.__pt_nodeId(n), nodeId: 0, nodeType: n.nodeType,
      nodeName: n.nodeName || '', localName: n.localName || '', nodeValue: n.nodeValue || '',
      childNodeCount: (n.childNodes || []).length, attributes: attrs
    };
  };
  globalThis.__pt_getProps = (id) => {
    const o = __ptObjs.get(id); const out = [];
    if (o != null) {
      for (const k of Object.getOwnPropertyNames(o)) {
        // Report the REAL descriptor flags. Reporting non-enumerable props (e.g.
        // an array's `length`) as enumerable makes Puppeteer's iterator drain
        // (which stops when getProperties returns 0 enumerable entries) loop
        // forever — the root cause of page.$/$$/$eval hanging.
        let d; try { d = Object.getOwnPropertyDescriptor(o, k); } catch (e) { continue; }
        if (!d) continue;
        let val; try { val = 'value' in d ? d.value : o[k]; } catch (e) { continue; }
        out.push({
          name: String(k), value: globalThis.__pt_wrap(val, false),
          configurable: !!d.configurable, enumerable: !!d.enumerable,
          writable: !!d.writable, isOwn: true,
        });
      }
    }
    return out;
  };
})();
