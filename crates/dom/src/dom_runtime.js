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
  // String methods taken before any page script. A page may replace them
  // (Klarna replaces `trim`); the engine must not call the page's copies.
  // Other receivers keep their own method, errors included.
  // Each wrapper is its own function literal: closures made from one literal
  // share call feedback, and one wrapper for all methods went megamorphic.
  // Passing `undefined` for a missing argument is the same as omitting it for
  // every method here. `arguments` is not read: it cost a third of the call.
  const __smCall = (f) => Function.prototype.call.bind(f);
  const __smSlow = (s, m, a, b) => (b !== undefined ? s[m](a, b) : a !== undefined ? s[m](a) : s[m]());
  const __sc_slice = __smCall(String.prototype.slice);
  const __s_slice = function (s, a, b) { return typeof s === 'string' ? __sc_slice(s, a, b) : __smSlow(s, 'slice', a, b); };
  const __sc_toLowerCase = __smCall(String.prototype.toLowerCase);
  const __s_toLowerCase = function (s, a, b) { return typeof s === 'string' ? __sc_toLowerCase(s, a, b) : __smSlow(s, 'toLowerCase', a, b); };
  const __sc_replace = __smCall(String.prototype.replace);
  const __s_replace = function (s, a, b) { return typeof s === 'string' ? __sc_replace(s, a, b) : __smSlow(s, 'replace', a, b); };
  const __sc_trim = __smCall(String.prototype.trim);
  const __s_trim = function (s, a, b) { return typeof s === 'string' ? __sc_trim(s, a, b) : __smSlow(s, 'trim', a, b); };
  const __sc_indexOf = __smCall(String.prototype.indexOf);
  const __s_indexOf = function (s, a, b) { return typeof s === 'string' ? __sc_indexOf(s, a, b) : __smSlow(s, 'indexOf', a, b); };
  const __sc_split = __smCall(String.prototype.split);
  const __s_split = function (s, a, b) { return typeof s === 'string' ? __sc_split(s, a, b) : __smSlow(s, 'split', a, b); };
  const __sc_charCodeAt = __smCall(String.prototype.charCodeAt);
  const __s_charCodeAt = function (s, a, b) { return typeof s === 'string' ? __sc_charCodeAt(s, a, b) : __smSlow(s, 'charCodeAt', a, b); };
  const __sc_endsWith = __smCall(String.prototype.endsWith);
  const __s_endsWith = function (s, a, b) { return typeof s === 'string' ? __sc_endsWith(s, a, b) : __smSlow(s, 'endsWith', a, b); };
  const __sc_toUpperCase = __smCall(String.prototype.toUpperCase);
  const __s_toUpperCase = function (s, a, b) { return typeof s === 'string' ? __sc_toUpperCase(s, a, b) : __smSlow(s, 'toUpperCase', a, b); };
  const __sc_lastIndexOf = __smCall(String.prototype.lastIndexOf);
  const __s_lastIndexOf = function (s, a, b) { return typeof s === 'string' ? __sc_lastIndexOf(s, a, b) : __smSlow(s, 'lastIndexOf', a, b); };
  const __sc_match = __smCall(String.prototype.match);
  const __s_match = function (s, a, b) { return typeof s === 'string' ? __sc_match(s, a, b) : __smSlow(s, 'match', a, b); };
  const __sc_includes = __smCall(String.prototype.includes);
  const __s_includes = function (s, a, b) { return typeof s === 'string' ? __sc_includes(s, a, b) : __smSlow(s, 'includes', a, b); };
  const __sc_charAt = __smCall(String.prototype.charAt);
  const __s_charAt = function (s, a, b) { return typeof s === 'string' ? __sc_charAt(s, a, b) : __smSlow(s, 'charAt', a, b); };
  const __sc_startsWith = __smCall(String.prototype.startsWith);
  const __s_startsWith = function (s, a, b) { return typeof s === 'string' ? __sc_startsWith(s, a, b) : __smSlow(s, 'startsWith', a, b); };
  const __sc_normalize = __smCall(String.prototype.normalize);
  const __s_normalize = function (s, a, b) { return typeof s === 'string' ? __sc_normalize(s, a, b) : __smSlow(s, 'normalize', a, b); };
  const __sc_search = __smCall(String.prototype.search);
  const __s_search = function (s, a, b) { return typeof s === 'string' ? __sc_search(s, a, b) : __smSlow(s, 'search', a, b); };
  const __sc_padStart = __smCall(String.prototype.padStart);
  const __s_padStart = function (s, a, b) { return typeof s === 'string' ? __sc_padStart(s, a, b) : __smSlow(s, 'padStart', a, b); };
  // JSON captured before any page code runs. The engine serializes its own
  // queues; using the page's `JSON.stringify` would let a page that wraps it
  // see the emulator's internals.
  const __ptJSON = globalThis.__ptJSON || { stringify: JSON.stringify, parse: JSON.parse };
  const ELEMENT_NODE = 1, TEXT_NODE = 3, COMMENT_NODE = 8,
        DOCUMENT_NODE = 9, DOCUMENT_FRAGMENT_NODE = 11;
  // Tree walks recurse this deep at most (see `walk`).
  const __WALK_DEPTH = 256;

  const __pt_soon = (f) => { try { queueMicrotask(f); } catch (e) { setTimeout(f, 0); } };
  // An engine task (load on readiness, CSP violation, script error) is not a
  // page timer: it must not consume a setTimeout id.
  const __ptLater = (f, d) => (typeof globalThis.__pt_addTask === 'function' ? __pt_addTask(f, d || 0) : setTimeout(f, d || 0));
  // Layout kept between passes and what a change dropped from it (declared
  // first: the tree is mutated before the layout code below is reached).
  let __layoutMemo = new WeakMap();
  let __layoutDirty = [], __layoutAllDirty = true;
  // Loads the document's `load` event waits for, as Chrome measured: images
  // (hidden and unattached ones too, not lazy ones), frames, stylesheets and
  // their imports, inserted scripts, CSS images of rendered elements, fonts
  // text is waiting for. Preloads, prefetches, fetch and XHR do not count.
  // A hold taken after `load` started is no hold.
  // Each hold is named by what took it, for `__pt_loadHoldList` when a load
  // never finishes.
  const __loadHold = { n: 0, live: new Set() };
  const __holdLoad = (what) => {
    const doc = globalThis.document;
    if (!doc || (doc.__ptFinishAt | 0) >= 2) return () => {};
    __loadHold.n++;
    const tag = { what };
    __loadHold.live.add(tag);
    let done = false;
    return () => { if (!done) { done = true; __loadHold.n--; __loadHold.live.delete(tag); } };
  };
  globalThis.__pt_loadHolds = () => __loadHold.n;
  Object.defineProperty(globalThis, '__pt_loadHoldsStyled', { value: () => {
    if (typeof globalThis.__pt_cssLoads !== 'function') return __loadHold.n;
    __pt_cssLoads();
    if (__loadHold.n === 0) __pt_cssLoads(true);
    return __loadHold.n;
  }, configurable: true, enumerable: false });
  // Images switched off by the engine's option: nothing is requested and
  // nothing fires, as in Chrome with `imagesEnabled=false`. A challenge's own
  // images still load; its checks need them.
  const __imageSkipped = (url) => !!globalThis.__pt_noImages
    && !/\/cdn-cgi\/challenge-platform\/|^https:\/\/challenges\.cloudflare\.com\//.test(String(url));
  // `loading="lazy"` images and frames wait until their box comes within
  // 1250px (images) or 2500px (frames) of the viewport: Chrome 151 on a
  // 4G-class connection, measured at 942px of window (an image at 2150px
  // loads, at 2250px not; a frame at 3430px loads, at 3445px not). They
  // never hold `load`; one without a box (`display: none`, not in the
  // document) never loads. The engine looks after `load`, on each turn and
  // whenever the tree, the scroll or the viewport changed.
  const __lazyPending = new Set();
  const __LAZY_MARGIN = 1250, __LAZY_FRAME_MARGIN = 2500;
  const __lazyDeferred = (el) => {
    if (el.__ptLazyGo) return false;
    if (__s_toLowerCase(__s_trim(String(__ptGetA(el, 'loading') || ''))) !== 'lazy') return false;
    __lazyPending.add(el);
    return true;
  };
  // At most every max(100 ms, 4x its last cost): it lays the page out, and a
  // page that changes itself every frame would pay a layout per turn.
  let __lazyAt = '', __lazyNext = 0, __lazyView = '';
  globalThis.__pt_lazyCheck = () => {
    if (!__lazyPending.size) return;
    const doc = globalThis.document;
    if (!doc || (doc.__ptFinishAt | 0) < 2) return;
    const vw = globalThis.innerWidth || LAYOUT.W, vh = globalThis.innerHeight || LAYOUT.H;
    const sx = __scrollPos[0], sy = __scrollPos[1];
    const view = sx + ',' + sy + ':' + vw + 'x' + vh;
    const at = __layoutSeq + ':' + view;
    if (at === __lazyAt) return;
    const t0 = __perfNow();
    // A scroll or a resize is looked at at once; only tree changes wait.
    if (t0 < __lazyNext && view === __lazyView) return;
    __lazyAt = at;
    __lazyView = view;
    __lstats.lazyRuns++;
    try { __lazyRun(sx, sy, vw, vh); } finally { __lstats.lazyMs += __perfNow() - t0; __lazyNext = __perfNow() + Math.max(100, 4 * (__perfNow() - t0)); }
  };
  function __lazyRun(sx, sy, vw, vh) {
    const go = [];
    for (const el of __lazyPending) {
      if (!el.isConnected) { __lazyPending.delete(el); continue; }
      const eager = __s_toLowerCase(__s_trim(String(__ptGetA(el, 'loading') || ''))) !== 'lazy';
      const b = eager ? null : __boxOf(el);
      if (!eager) {
        if (!b) continue;
        const m = el.__ptLocal === 'iframe' ? __LAZY_FRAME_MARGIN : __LAZY_MARGIN;
        if (b.y > sy + vh + m || b.y + b.h < sy - m) continue;
        if (b.x > sx + vw + m || b.x + b.w < sx - m) continue;
      }
      go.push(el);
    }
    for (const el of go) {
      __lazyPending.delete(el);
      Object.defineProperty(el, '__ptLazyGo', { value: true, configurable: true, enumerable: false });
      try {
        if (el.__ptLocal === 'img') el.__ptLoadImage();
        else if (el.__ptLocal === 'iframe') el.__ptConnectFrame();
      } catch (e) {}
    }
  }
  Object.defineProperty(globalThis, '__pt_loadHoldList', { value: () => [...__loadHold.live].map((t) => String(t.what)), configurable: true, enumerable: false });
  Object.defineProperty(globalThis, '__pt_holdLoad', { value: __holdLoad, configurable: true, enumerable: false });
  // A stylesheet in the body, with its imports, holds the parser and so
  // `DOMContentLoaded` (one in the head does not, unless a script follows).
  const __dclHold = { n: 0 };
  const __holdDcl = (el) => {
    const doc = globalThis.document;
    if (!doc || (doc.__ptFinishAt | 0) >= 1 || !el || el.ownerDocument !== doc || !doc.body || !doc.body.contains(el)) return () => {};
    __dclHold.n++;
    let done = false;
    return () => { if (!done) { done = true; __dclHold.n--; } };
  };
  globalThis.__pt_dclHolds = () => __dclHold.n;
  const VOID = new Set(['area','base','br','col','embed','hr','img','input',
    'link','meta','param','source','track','wbr']);

  // Every node in a subtree, shadow trees included. Frames and scripts come to
  // life as part of whatever tree they are inserted with — a widget hands the DOM
  // a finished tree, not a bare element.
  function __attrName(el, n) {
    const s = String(n);
    return el.__ptNS === undefined || el.__ptNS === 'http://www.w3.org/1999/xhtml' ? __s_toLowerCase(s) : s;
  }
  // Attributes are kept by qualified name; one in a namespace has
  // [namespace, prefix, local name] beside it, by the same name.
  const __XMLNS_NS = 'http://www.w3.org/2000/xmlns/', __XML_NS = 'http://www.w3.org/XML/1998/namespace';
  const __attrNsOf = (el, q) => (el.__ptAttrNS && el.__ptAttrNS.get(q)) || null;
  const __attrNsMap = (el) => {
    if (!el.__ptAttrNS) Object.defineProperty(el, '__ptAttrNS', { value: new Map(), enumerable: false, configurable: true });
    return el.__ptAttrNS;
  };
  const __nsArg = (ns) => (ns === null || ns === undefined || ns === '' ? null : String(ns));
  // The qualified name of the attribute with this namespace and local name.
  function __attrNsFind(el, ns, local) {
    const N = __nsArg(ns), L = String(local);
    for (const q of el.__ptAttrs.keys()) {
      const info = __attrNsOf(el, q);
      if (info ? info[0] === N && info[2] === L : N === null && q === L) return q;
    }
    return null;
  }
  // DOM "validate and extract", with Chrome 151's messages.
  function __attrNsExtract(ns, qname, method) {
    const N = __nsArg(ns), q = String(qname);
    const fail = (what, kind) => __pt_mkErr(globalThis.DOMException || Error, "Failed to execute '" + method + "' on 'Element': " + what, kind);
    const bad = /[\t\n\f\r \0\/>]/.exec(q);
    if (bad) throw fail("The qualified name provided ('" + q + "') contains the invalid character '" + bad[0] + "'.", 'InvalidCharacterError');
    const c = __s_indexOf(q, ':');
    const prefix = c < 0 ? null : __s_slice(q, 0, c), local = c < 0 ? q : __s_slice(q, c + 1);
    if (!local) throw fail("The qualified name provided ('" + q + "') has an empty local name.", 'InvalidCharacterError');
    if (prefix === '') throw fail("The qualified name provided ('" + q + "') has an empty namespace prefix.", 'InvalidCharacterError');
    const nsBad = () => fail("'" + (N || '') + "' is an invalid namespace for attributes.", 'NamespaceError');
    if (prefix !== null && N === null) throw nsBad();
    if (prefix === 'xml' && N !== __XML_NS) throw nsBad();
    if ((q === 'xmlns' || prefix === 'xmlns') && N !== __XMLNS_NS) throw nsBad();
    if (N === __XMLNS_NS && q !== 'xmlns' && prefix !== 'xmlns') throw nsBad();
    return [N, prefix, local];
  }
  // Depth first without a stack frame per level; a node's children as they
  // were right after `fn` saw it, then its shadow tree.
  // ---- slots ----------------------------------------------------------------
  const __slotRoot = (slot) => { let r = slot; while (r.__ptParent) r = r.__ptParent; return r.__ptHost && r.__ptType === 11 ? r : null; };
  const __slotsIn = (root) => { const out = []; __walkTree(root, (n) => { if (n.__ptType === ELEMENT_NODE && n.__ptLocal === 'slot' && !n.__ptNS) out.push(n); }); return out; };
  // The slot a host's child is assigned to; with `openOnly`, none behind a
  // closed root (`assignedSlot` does not reveal it).
  function __slotFor(node, openOnly) {
    const host = node.__ptParent, root = host && host.__ptShadow;
    if (!root || (openOnly && root.mode !== 'open')) return null;
    if (node.__ptType !== ELEMENT_NODE && node.__ptType !== TEXT_NODE) return null;
    const slots = __slotsIn(root);
    if (root.__ptSlotAssignment === 'manual') { for (const sl of slots) if (sl.__ptManual && __s_includes(sl.__ptManual, node)) return sl; return null; }
    const name = node.__ptType === ELEMENT_NODE ? (__ptGetA(node, 'slot') || '') : '';
    for (const sl of slots) if ((__ptGetA(sl, 'name') || '') === name) return sl;
    return null;
  }
  function __slotAssigned(slot) {
    const root = __slotRoot(slot);
    if (!root) return [];
    const kids = root.__ptHost.__ptKids;
    if (root.__ptSlotAssignment === 'manual') return (slot.__ptManual || []).filter((n) => __s_includes(kids, n) && __slotFor(n, false) === slot);
    return kids.filter((n) => __slotFor(n, false) === slot);
  }
  // Assigned nodes with slots inside expanded, the slot's own children when
  // nothing is assigned.
  function __slotFlat(slot) {
    const out = [];
    const assigned = __slotAssigned(slot);
    const src = assigned.length ? assigned : (__slotRoot(slot) ? slot.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE || n.__ptType === TEXT_NODE) : []);
    for (const n of src) {
      if (n.__ptType === ELEMENT_NODE && n.__ptLocal === 'slot' && !n.__ptNS && __slotRoot(n)) for (const m of __slotFlat(n)) out.push(m);
      else out.push(n);
    }
    return out;
  }
  function __walkTree(node, fn) {
    if (!node) return;
    const st = [node];
    while (st.length) {
      const n = st.pop();
      fn(n);
      if (n.__ptShadow) st.push(n.__ptShadow);
      const kids = n.__ptKids;
      if (kids) for (let i = kids.length - 1; i >= 0; i--) st.push(kids[i]);
    }
  }

  // What connecting a subtree means for the elements that *do* something: a frame
  // opens a browsing context, a script runs. Both were inert before — a page that
  // builds `<script src=…>` and appends it (which is how every tag loader, widget
  // bootstrap and anti-bot orchestrator works, Cloudflare's interstitial included)
  // got a DOM node and nothing else: no fetch, no execution, no `onload`.
  // Frames in the tree change only when a frame element connects or leaves:
  // `window.length` and `window[i]` are recomputed then, not on every DOM
  // mutation (a text change walked the whole tree twice).
  let __framesSeq = 0;
  const __framesChanged = () => {
    __framesSeq++;
    if (globalThis.__pt_syncFrameSlots) { try { __pt_syncFrameSlots(); } catch (e) {} }
  };
  const __isFrameEl = (n) => n.__ptLocal === 'iframe' || n.__ptLocal === 'frame';
  const __connectSubtree = (node) => {
    const before = __framesSeq;
    __connectWalk(node);
    if (__framesSeq !== before && globalThis.__pt_syncFrameSlots) { try { __pt_syncFrameSlots(); } catch (e) {} }
  };
  // `<meta http-equiv="Accept-CH">` values as they connect, for the engine
  // to put on the document's subresources (the engine keeps only the top
  // document's).
  const __metaHints = [];
  const __metaSeen = new WeakSet();
  const __noteMeta = (n) => {
    if (__metaSeen.has(n) || __s_toLowerCase(String(__ptGetA(n, 'http-equiv') || '')) !== 'accept-ch') return;
    __metaSeen.add(n);
    const v = __ptGetA(n, 'content');
    if (v) __metaHints.push(String(v));
  };
  // The parser builds the document without the connect path: the first
  // look takes the metas already there.
  let __metaScanned = null;
  Object.defineProperty(globalThis, '__pt_drainHints', { value: () => {
    const doc = globalThis.document;
    if (doc && __metaScanned !== doc && doc.documentElement) {
      __metaScanned = doc;
      __walkTree(doc.documentElement, (n) => { if (n.__ptLocal === 'meta') __noteMeta(n); });
    }
    return __metaHints.splice(0);
  }, configurable: true, enumerable: false });
  const __connectWalk = (node) => __walkTree(node, (n) => {
    if (__isFrameEl(n)) __framesSeq++;
    if (n.__ptLocal === 'meta') __noteMeta(n);
    if (n.__ptLocal === 'iframe') n.__ptConnectFrame();
    else if (n.__ptLocal === 'script') n.__ptRunScript();
    // Stylesheets and preloads start loading on insertion, not on `href`
    // assignment: the order can be either.
    else if (n.__ptLocal === 'link' && n.__ptLoadLink) n.__ptLoadLink();
    else if (n.__ptLocal === 'img' && n.__ptLoadImage) n.__ptLoadImage();
    else if ((n.__ptLocal === 'video' || n.__ptLocal === 'audio') && globalThis.__pt_mediaLoad) __pt_mediaLoad(n, true);
    if (n.__ptType === ELEMENT_NODE && __customs.has(n.__ptLocal)) {
      if (!n.__ptUpgraded) __customUpgrade(n, __customs.get(n.__ptLocal));
      else __customCallback(n, 'connectedCallback');
    }
  });

  // An array wrapped as HTMLCollection: length/item/namedItem/iterator, not an
  // Array (`Array.isArray` is false on a real collection).
  function __collection(arr, named) {
    const list = Object.create(__link('HTMLCollection', __collectionProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    // Named members, as `document.forms.login`: each element's id, then the
    // name of an HTML element; the first element wins. Hidden from for-in,
    // and never over the prototype's members (`length`, `item`). Only for
    // the lists pages read by name: on `children` of a long list the names
    // cost five times the list.
    if (named) for (let i = 0; i < arr.length; i++) {
      const e = arr[i];
      if (!e || e.__ptType !== ELEMENT_NODE) continue;
      const id = __ptGetA(e, 'id');
      if (id) __collectionName(list, id, e);
      if (e.__ptNS === undefined || e.__ptNS === 'http://www.w3.org/1999/xhtml') {
        const name = __ptGetA(e, 'name');
        if (name) __collectionName(list, name, e);
      }
    }
    return list;
  }
  function __collectionName(list, k, e) {
    if (k in list || __arrayIndex(k) >= 0) return;
    Object.defineProperty(list, k, { value: e, writable: false, enumerable: false, configurable: true });
  }
  // The array index a property key names, or -1.
  function __arrayIndex(k) {
    const n = k.length;
    if (n === 0 || n > 10) return -1;
    let v = 0;
    for (let i = 0; i < n; i++) {
      const d = __s_charCodeAt(k, i) - 48;
      if (d < 0 || d > 9 || (i === 0 && d === 0 && n > 1)) return -1;
      v = v * 10 + d;
    }
    return v < 4294967295 ? v : -1;
  }
  // `querySelectorAll` returns a static NodeList, unlike live childNodes; they
  // answer `Object.prototype.toString` differently.
  function __staticNodeList(arr) {
    const list = Object.create(__link('NodeList', __nodeListProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // childNodes is a NodeList, not an array: Turnstile's fingerprinter buckets
  // arrays separately. The list is live and identical to itself (widgets
  // compare `a.childNodes === a.childNodes`), so it is cached on the node and
  // indices are rebuilt on each access.
  function __nodeList(node) {
    const proto = __link('NodeList', __nodeListProto);
    let list = node.__ptList;
    if (!list) {
      list = Object.create(proto);
      Object.defineProperty(node, '__ptList', { value: list, enumerable: false, writable: true });
    }
    if (list.__ptNode !== node) Object.defineProperty(list, '__ptNode', { value: node, enumerable: false });
    __nodeListFill(list, node);
    return list;
  }
  function __nodeListFill(list, node) {
    const kids = node.__ptKids, prev = list.__ptLen | 0;
    // Unchanged since the last fill: every change to a tree bumps the
    // layout sequence.
    if (list.__ptSeq === __layoutSeq && prev === kids.length) return;
    for (let i = 0; i < kids.length; i++) list[i] = kids[i];
    for (let i = kids.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptLen', { value: kids.length, enumerable: false, configurable: true });
    Object.defineProperty(list, '__ptSeq', { value: __layoutSeq, enumerable: false, configurable: true });
  }
  // A prototype is linked to its interface on first use: interfaces are
  // declared after this file, lists are created later by the page. Members move
  // to `Iface.prototype` and our object inherits from it, so
  // `list instanceof NodeList` holds and `constructor` is right. Returns the
  // prototype to build the list on: in Chrome
  // `Object.getPrototypeOf(document.querySelectorAll('*'))` is
  // `NodeList.prototype` itself, with no empty level in between.
  const __ptHiddenFrame = () => {
    if (!globalThis.__pt_crossSite) return false;
    let w = globalThis;
    for (let i = 0; i < 8 && w; i++) {
      if (typeof w.innerWidth !== 'number') break;
      if ((w.innerWidth | 0) === 0 && (w.innerHeight | 0) === 0) return true;
      let p = null;
      try { p = w.parent; } catch (e) { break; }
      if (!p || p === w) break;
      w = p;
    }
    return false;
  };
  // Proxy with a prototype-cycle check (see __pt_proxy in the prologue).
  const __ptProxy = (target, handler) => {
    if (typeof globalThis.__pt_proxy === 'function') return globalThis.__pt_proxy(target, handler);
    const px = new Proxy(target, handler);
    handler.setPrototypeOf = (t, proto) => {
      for (let q = proto, i = 0; q !== null && q !== undefined && i < 100000; i++) {
        if (q === t || q === px) throw __pt_mkErr(TypeError, 'Cyclic __proto__ value');
        q = Object.getPrototypeOf(q);
      }
      return Reflect.setPrototypeOf(t, proto);
    };
    return px;
  };
  const __link = (name, proto) => {
    const I = globalThis[name];
    if (!I || !I.prototype) return proto;
    if (proto.__ptLinked) return I.prototype;
    proto.__ptLinked = true;
    // Linking happens after bootstrap naturalisation, so moved members are
    // masked here, or `HTMLCollection.prototype.item` would show its source.
    const nat = globalThis.__pt_native || ((f) => f);
    const named = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return nat(f); };
    for (const k of Reflect.ownKeys(proto)) {
      if (k === '__ptLinked') continue;
      const d = Object.getOwnPropertyDescriptor(proto, k);
      const label = typeof k === 'symbol' ? '[' + (k.description || '') + ']' : k;
      // A symbol often holds another builtin (the list iterator is
      // Array.prototype.values itself); Chrome keeps its name "values".
      if (typeof d.value === 'function' && !(typeof k === 'symbol' && d.value.name && __s_charCodeAt(d.value.name, 0) !== 91)) d.value = named(d.value, label);
      if (typeof d.get === 'function') d.get = named(d.get, 'get ' + label);
      if (typeof d.set === 'function') d.set = named(d.set, 'set ' + label);
      Object.defineProperty(I.prototype, k, d);
    }
    Object.setPrototypeOf(proto, I.prototype);
    for (const k of Reflect.ownKeys(proto)) {
      if (k !== '__ptLinked') delete proto[k];
    }
    return I.prototype;
  };
  const __nodeListProto = {
    get [Symbol.toStringTag]() { return 'NodeList'; },
    // `length` is on the prototype: a list's own properties are indices only,
    // as getOwnPropertyNames shows.
    // A live list (childNodes) reads its node's children again: an array
    // iterator reads `length` at each step.
    get length() { const n = this.__ptNode; if (n) __nodeListFill(this, n); return this.__ptLen | 0; },
    item(i) { const n = this.__ptNode; if (n) __nodeListFill(this, n); return this[i] != null ? this[i] : null; },
  };
  // As in Chrome, a value iterator is Array.prototype's: `entries`, `keys`,
  // `values` and `forEach` are those functions, the iterator `values`.
  const __arrayIterable = (proto) => {
    for (const k of ['entries', 'keys', 'values', 'forEach']) Object.defineProperty(proto, k, { value: Array.prototype[k], writable: true, enumerable: true, configurable: true });
    Object.defineProperty(proto, Symbol.iterator, { value: Array.prototype.values, writable: true, enumerable: false, configurable: true });
  };
  __arrayIterable(__nodeListProto);

  const __collectionProto = {
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    namedItem(n) {
      for (let i = 0; i < this.length; i++) {
        const e = this[i];
        if (e && (e.id === n || (e.getAttribute && __ptGetA(e, 'name') === n))) return e;
      }
      return null;
    },
  };  // As in Chrome: the tag is a data property, the iterator Array.prototype.values, both non-enumerable.
  Object.defineProperty(__collectionProto, Symbol.toStringTag, { value: 'HTMLCollection', configurable: true });
  Object.defineProperty(__collectionProto, Symbol.iterator, { value: Array.prototype.values, writable: true, configurable: true });


  // `document.all` is an HTMLAllCollection: HTMLCollection's members on its
  // own interface (swapping the prototype afterwards lost `length` and `item`).
  const __allProto = {
    get length() { return this.__ptLen | 0; },
    item(i) {
      if (i === undefined) return null;
      const n = String(i);
      if (/^\d+$/.test(n)) return this[+n] != null ? this[+n] : null;
      return this.namedItem(n);
    },
    namedItem(n) {
      const found = [];
      for (let i = 0; i < this.length; i++) {
        const e = this[i];
        if (e && (e.id === n || (e.getAttribute && __ptGetA(e, 'name') === n))) found.push(e);
      }
      if (!found.length) return null;
      return found.length === 1 ? found[0] : __collection(found);
    },
  };  // As in Chrome: the tag is a data property, the iterator Array.prototype.values, both non-enumerable.
  Object.defineProperty(__allProto, Symbol.toStringTag, { value: 'HTMLAllCollection', configurable: true });
  Object.defineProperty(__allProto, Symbol.iterator, { value: Array.prototype.values, writable: true, configurable: true });

  function __allCollection(arr) {
    const list = Object.create(__link('HTMLAllCollection', __allProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }

  // `el.attributes` is a NamedNodeMap of Attr, not an array: fingerprinters
  // read `Object.prototype.toString` and the prototype chain.
  const __attrProto = {
    get [Symbol.toStringTag]() { return 'Attr'; },
    get localName() { const i = __attrNsOf(this.__ptOwner, this.__ptName); return i ? i[2] : this.__ptName; },
    get name() { return this.__ptName; },
    get nodeName() { return this.__ptName; },
    get value() { return __attrValue(this); },
    get nodeValue() { return __attrValue(this); },
    get textContent() { return __attrValue(this); },
    get namespaceURI() { const i = __attrNsOf(this.__ptOwner, this.__ptName); return i ? i[0] : null; },
    get prefix() { const i = __attrNsOf(this.__ptOwner, this.__ptName); return i ? i[1] : null; },
    get specified() { return true; },
    get ownerElement() { return this.__ptOwner; },
  };
  // The image a browser at this device pixel ratio picks: from srcset (density
  // `x`, or width `w` against the viewport width as `sizes` defaults to
  // 100vw), the smallest density not below the ratio, else the largest; src
  // counts as 1x when srcset has no 1x.
  function __imgSource(el) {
    const src = __ptGetA(el, 'src') || '';
    const set = __ptGetA(el, 'srcset');
    if (!set) return src;
    const vw = (globalThis.innerWidth | 0) || 1, dpr = globalThis.devicePixelRatio || 1;
    const cands = [];
    let i = 0;
    const n = set.length;
    while (i < n) {
      while (i < n && /[\s,]/.test(set[i])) i++;
      if (i >= n) break;
      let j = i;
      while (j < n && !/\s/.test(set[j])) j++;
      let url = __s_slice(set, i, j), desc = '';
      if (/,$/.test(url)) url = __s_replace(url, /,+$/, '');
      else {
        let k = j;
        while (k < n && set[k] !== ',') k++;
        desc = __s_trim(__s_slice(set, j, k));
        j = k;
      }
      i = j;
      const m = /^(\d*\.?\d+)([xw])$/i.exec(desc);
      const d = !desc ? 1 : m ? (__s_toLowerCase(m[2]) === 'x' ? +m[1] : +m[1] / vw) : NaN;
      if (url && d > 0) cands.push([url, d]);
    }
    if (src && !cands.some((c) => c[1] === 1)) cands.push([src, 1]);
    if (!cands.length) return src;
    let best = null;
    for (const c of cands) if (c[1] >= dpr && (!best || c[1] < best[1])) best = c;
    if (!best) for (const c of cands) if (!best || c[1] > best[1]) best = c;
    return best[0];
  }
  function __imgCurrent(el, url, later) {
    Object.defineProperty(el, '__ptCurWant', { value: url, writable: true, configurable: true, enumerable: false });
    const put = () => { if (el.__ptCurWant === url) Object.defineProperty(el, '__ptCurSrc', { value: url, writable: true, configurable: true, enumerable: false }); };
    if (later) __ptLater(put, 0); else put();
  }
  // An attached Attr reads its element's current value; a removed one keeps
  // the last value it had.
  const __attrValue = (a) => {
    const o = a.__ptOwner;
    if (o && o.__ptAttrs.has(a.__ptName)) return o.__ptAttrs.get(a.__ptName);
    return a.__ptValue;
  };
  function __attr(el, name, value) {
    const a = Object.create(__link('Attr', __attrProto));
    Object.defineProperty(a, '__ptName', { value: name });
    Object.defineProperty(a, '__ptValue', { value: value, writable: true });
    Object.defineProperty(a, '__ptOwner', { value: el, writable: true });
    return a;
  }
  // One Attr per attribute while it is on its element, as in Chrome:
  // `el.attributes.src === el.getAttributeNode('src')`.
  function __attrNode(el, name) {
    let m = el.__ptAttrNodes;
    if (!m) { m = new Map(); Object.defineProperty(el, '__ptAttrNodes', { value: m }); }
    let a = m.get(name);
    if (!a) { a = __attr(el, name, el.__ptAttrs.get(name)); m.set(name, a); }
    return a;
  }
  // An attribute went away: its Attr is detached with its last value.
  function __attrDetach(el, name, old) {
    const m = el.__ptAttrNodes, a = m && m.get(name);
    if (!a) return null;
    m.delete(name);
    a.__ptValue = old;
    a.__ptOwner = null;
    return a;
  }
  const __namedNodeMapProto = {
    get [Symbol.toStringTag]() { return 'NamedNodeMap'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    getNamedItem(n) { const el = this.__ptOwner, k = __attrName(el, n);
      return el.__ptAttrs.has(k) ? __attrNode(el, k) : null; },
    getNamedItemNS(_ns, n) { return this.getNamedItem(n); },
    setNamedItem(a) { if (a && this.__ptOwner) __ptSetA(this.__ptOwner, a.name, a.value); return null; },
    setNamedItemNS(a) { return this.setNamedItem(a); },
    removeNamedItem(n) { const a = this.getNamedItem(n);
      if (!a) throw new Error("Failed to execute 'removeNamedItem' on 'NamedNodeMap': No item with name '" + n + "' was found.");
      __ptDelA(this.__ptOwner, a.name); return a; },
    removeNamedItemNS(_ns, n) { return this.removeNamedItem(n); },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  // `el.attributes` is one live map per element. Chrome's has an index per
  // attribute (enumerable) and a property per name (not enumerable; skipped
  // where the prototype has a member of that name, and for an HTML element
  // names with capitals); all read-only. Pages read `img.attributes.src`.
  function __namedNodeMap(el) {
    let map = el.__ptAttrMap;
    if (!map) {
      map = Object.create(__link('NamedNodeMap', __namedNodeMapProto));
      Object.defineProperty(map, '__ptOwner', { value: el });
      Object.defineProperty(el, '__ptAttrMap', { value: map });
    }
    __attrMapSync(el);
    return map;
  }
  function __attrMapSync(el) {
    const map = el.__ptAttrMap;
    if (!map) return;
    const prev = map.__ptLen | 0, names = map.__ptNames || [];
    const proto = Object.getPrototypeOf(map), html = !el.__ptNS;
    let i = 0;
    const now = [];
    for (const name of el.__ptAttrs.keys()) {
      const a = __attrNode(el, name);
      Object.defineProperty(map, i++, { value: a, writable: false, enumerable: true, configurable: true });
      if (name in proto || (html && __s_toLowerCase(name) !== name)) continue;
      Object.defineProperty(map, name, { value: a, writable: false, enumerable: false, configurable: true });
      now.push(name);
    }
    for (let k = i; k < prev; k++) delete map[k];
    for (const name of names) if (!__s_includes(now, name)) delete map[name];
    Object.defineProperty(map, '__ptLen', { value: i, enumerable: false, configurable: true });
    Object.defineProperty(map, '__ptNames', { value: now, enumerable: false, configurable: true });
  }

  // `classList` is a live DOMTokenList that writes back to the attribute; an
  // interface, not a literal with methods.
  const __tokenListProto = {
    get [Symbol.toStringTag]() { return 'DOMTokenList'; },
    get value() { return __ptGetA(this.__ptEl, 'class') || ''; },
    set value(v) { __ptSetA(this.__ptEl, 'class', String(v)); },
    // Indices follow the attribute: an array iterator reads `length` at
    // each step.
    get length() { return __tokenFill(this).length; },
    item(i) { const t = this.__ptTokens(); return i >= 0 && i < t.length ? t[i] : null; },
    contains(c) { return __s_includes(this.__ptTokens(), String(c)); },
    add(...cs) { const t = this.__ptTokens();
      for (const c of cs) if (!__s_includes(t, String(c))) t.push(String(c));
      __ptSetA(this.__ptEl, 'class', t.join(' ')); },
    remove(...cs) { const drop = cs.map(String);
      __ptSetA(this.__ptEl, 'class', this.__ptTokens().filter((c) => !__s_includes(drop, c)).join(' ')); },
    toggle(c, force) { const t = this.__ptTokens(), has = __s_includes(t, String(c));
      if (force === true || (force === undefined && !has)) {
        if (!has) t.push(String(c));
        __ptSetA(this.__ptEl, 'class', t.join(' '));
        return true;
      }
      __ptSetA(this.__ptEl, 'class', t.filter((x) => x !== String(c)).join(' '));
      return false; },
    replace(from, to) { const t = this.__ptTokens(), i = __s_indexOf(t, String(from));
      if (i < 0) return false;
      t[i] = String(to); __ptSetA(this.__ptEl, 'class', t.join(' ')); return true; },
    supports() { throw __pt_mkErr(TypeError, "Failed to execute 'supports' on 'DOMTokenList': DOMTokenList has no supported tokens."); },
    toString() { return this.value; },
  };
  __arrayIterable(__tokenListProto);
  // Refilled only when the attribute changed since the last fill.
  const __tokenSeen = new WeakMap();
  function __tokenFill(list) {
    const raw = __ptGetA(list.__ptEl, 'class') || '';
    const seen = __tokenSeen.get(list);
    if (seen && seen.raw === raw) return seen.t;
    const t = list.__ptTokens(), prev = seen ? seen.t.length : 0;
    for (let i = 0; i < t.length; i++) list[i] = t[i];
    for (let i = t.length; i < prev; i++) delete list[i];
    __tokenSeen.set(list, { raw, t });
    return t;
  }
  function __tokenList(el) {
    const proto = __link('DOMTokenList', __tokenListProto);
    let list = el.__ptTokenList;
    if (!list) {
      list = Object.create(proto);
      Object.defineProperty(list, '__ptEl', { value: el });
      Object.defineProperty(list, '__ptTokens', {
        value: () => __s_split(__ptGetA(el, 'class') || '', /\s+/).filter(Boolean),
      });
      Object.defineProperty(el, '__ptTokenList', { value: list, enumerable: false, writable: true });
    }
    // Indices are own properties, as in Chrome: `list[0]` works.
    __tokenFill(list);
    return list;
  }

  // ---- Node -----------------------------------------------------------------
  // Listener bookkeeping as the DOM spec has it, for nodes and other targets:
  // one entry per (callback, capture); `once` removes it before the call;
  // `passive` makes `preventDefault` a no-op; an aborted `signal` removes it;
  // a listener removed during a dispatch is not called; an object listener
  // gets its `handleEvent` called with itself as `this`.
  const __ptListenOpts = (opts) => {
    if (opts === true || opts === false || opts == null || typeof opts !== 'object') return { cap: opts === true, once: false, passive: false, signal: null };
    return { cap: !!opts.capture, once: !!opts.once, passive: !!opts.passive, signal: opts.signal || null };
  };
  function __ptAddListener(t, store, type, fn, opts) {
    if (!fn) return;
    const o = __ptListenOpts(opts);
    if (o.signal && o.signal.aborted) return;
    const l = store[type] || (store[type] = []);
    for (const e of l) if (e.fn === fn && e.cap === o.cap) return;
    const entry = { fn, cap: o.cap, once: o.once, passive: o.passive, removed: false };
    l.push(entry);
    if (o.signal && typeof o.signal.addEventListener === 'function') {
      o.signal.addEventListener('abort', () => __ptDropListener(store, type, entry));
    }
  }
  function __ptDropListener(store, type, entry) {
    entry.removed = true;
    const l = store[type];
    if (l) store[type] = l.filter((e) => e !== entry);
  }
  function __ptRemoveListener(store, type, fn, opts) {
    const cap = __ptListenOpts(opts).cap;
    const l = store && store[type]; if (!l) return;
    for (const e of l) if (e.fn === fn && e.cap === cap) { __ptDropListener(store, type, e); return; }
  }
  function __ptCallListener(node, e, event, label) {
    if (e.removed) return;
    if (e.once) __ptDropListener(node.__ptLis, event.type, e);
    __ptEvSet(event, 'currentTarget', node);
    if (e.passive) __ptEvSet(event, '__ptPassive', true);
    try {
      if (typeof e.fn === 'function') e.fn.call(node, event);
      else if (e.fn && typeof e.fn.handleEvent === 'function') e.fn.handleEvent(event);
      else if (e.fn) throw __pt_mkErr(TypeError, "The 'handleEvent' property of the event listener is not callable.");
    } catch (x) {
      __pt_reportError(x, label + ' ' + event.type);
    } finally {
      if (e.passive) __ptEvSet(event, '__ptPassive', false);
    }
  }

  const __NO_NODES = [];
  // Whether a node is in a document, remembered for the last few nodes
  // asked or inserted: a page building a chain appends under the node it
  // appended before (after giving that node its text), and a walk to the
  // root per insert made a deep tree quadratic. "In" holds until a removal,
  // "out" until an insert into a document. Runs of (node, in, stamp), most
  // recent first.
  let __connRemovals = 0, __connInserts = 0;
  const __CONN_SLOTS = 4;
  const __connSlots = [];
  for (let i = 0; i < __CONN_SLOTS; i++) __connSlots.push(null, false, -1);
  function __connectedFast(node) {
    const c = __connSlots;
    for (let i = 0; i < c.length; i += 3) {
      if (c[i] === node && c[i + 2] === (c[i + 1] ? __connRemovals : __connInserts)) return c[i + 1];
    }
    let yes = false;
    for (let n = node; n; n = n.__ptParent || n.__ptHost) if (n.__ptType === DOCUMENT_NODE) { yes = true; break; }
    __connRemember(node, yes);
    return yes;
  }
  function __connRemember(node, yes) {
    const c = __connSlots;
    let at = c.length - 3;
    for (let i = 0; i < c.length; i += 3) if (c[i] === node) { at = i; break; }
    for (let i = at; i > 0; i -= 3) { c[i] = c[i - 3]; c[i + 1] = c[i - 2]; c[i + 2] = c[i - 1]; }
    c[0] = node;
    c[1] = yes;
    c[2] = yes ? __connRemovals : __connInserts;
  }

  // Pre-insert validity, the check Chrome makes first: the node may not be
  // the parent or a host-including ancestor of it (a cycle hung every walk
  // over the tree). A node with no children and no shadow tree is nobody's
  // ancestor, so a fresh node costs no walk.
  function __needNotAncestor(parent, node, method, iface) {
    if (!node || node.__ptType === undefined) return;
    if (node !== parent && !(node.__ptKids && node.__ptKids.length) && !node.__ptShadow) return;
    // Up from the parent; past 64 levels a small subtree (a fresh node with
    // its text) is searched for the parent instead of walking up a deep tree.
    let steps = 0;
    for (let p = parent; p; p = p.__ptParent || p.__ptHost) {
      if (++steps === 64 && !__subtreeHolds(node, parent, 64)) return;
      if (p === node) {
        throw __pt_mkErr(globalThis.DOMException || Error,
          "Failed to execute '" + method + "' on '" + iface + "': The new child element contains the parent.",
          'HierarchyRequestError');
      }
    }
  }
  // Whether `target` is below `root` (shadow trees included), or true when
  // the subtree is larger than `budget` and the answer was not reached.
  function __subtreeHolds(root, target, budget) {
    const st = [root];
    while (st.length) {
      const n = st.pop();
      if (n === target) return true;
      if (--budget < 0) return true;
      if (n.__ptShadow) st.push(n.__ptShadow);
      const kids = n.__ptKids;
      if (kids) for (let i = 0; i < kids.length; i++) st.push(kids[i]);
    }
    return false;
  }
  // A move (`moveBefore`) in progress: the insertion keeps the subtree as it
  // was, frames and scripts included.
  let __moving = false;
  function __shadowIncludingRoot(n) {
    while (n.__ptParent || n.__ptHost) n = n.__ptParent || n.__ptHost;
    return n;
  }
  // `moveBefore`: Chrome 151 checks the arguments, then that both nodes share
  // a shadow-including root, then the ancestor, then the reference child, then
  // the kind of node; the move keeps frames, scripts and focus as they are,
  // and custom elements get `connectedMoveCallback` or, without one,
  // `disconnectedCallback` and `connectedCallback`. Observers see a removal
  // and an insertion.
  function __moveBefore(parent, args, iface) {
    __needArgs(args.length, 2, 'moveBefore', iface);
    const node = args[0];
    let ref = args[1];
    __needNode(node, 1, 'moveBefore', iface);
    if (ref !== null && ref !== undefined) __needNode(ref, 2, 'moveBefore', iface);
    else ref = null;
    const invalid = () => __pt_mkErr(globalThis.DOMException || Error,
      "Failed to execute 'moveBefore' on '" + iface + "': State-preserving atomic move cannot be performed on nodes participating in an invalid hierarchy.",
      'HierarchyRequestError');
    if (__shadowIncludingRoot(parent) !== __shadowIncludingRoot(node)) throw invalid();
    __needNotAncestor(parent, node, 'moveBefore', iface);
    if (ref !== null && ref.__ptParent !== parent) {
      throw __pt_mkErr(globalThis.DOMException || Error,
        "Failed to execute 'moveBefore' on '" + iface + "': The node before which the new node is to be inserted is not a child of this node.",
        'NotFoundError');
    }
    const t = node.__ptType;
    if (t !== ELEMENT_NODE && t !== TEXT_NODE && t !== COMMENT_NODE && t !== 4 && t !== 7) throw invalid();
    if (ref === node) {
      const kids = parent.__ptKids, i = __s_indexOf(kids, node);
      ref = kids[i + 1] || null;
    }
    const connected = __connectedFast(parent);
    const customs = [];
    if (connected) __walkTree(node, (n) => { if (n.__ptUpgraded) customs.push(n); });
    const moveCb = (n) => typeof n.connectedMoveCallback === 'function';
    for (const n of customs) if (!moveCb(n)) __customCallback(n, 'disconnectedCallback');
    const old = node.__ptParent;
    if (old) {
      const kids = old.__ptKids, i = __s_indexOf(kids, node);
      const prev = kids[i - 1] || null, next = kids[i + 1] || null;
      __moNodeWillDetach(old, node);
      kids.splice(i, 1); node.__ptParent = null; __connRemovals++; __markDirty(old); __styleTouchKids(old, null, i); __hasNoteTree(node);
      __mutation(__childListRecord(old, [], [node], prev, next));
    }
    __moving = true;
    try { __ptInsert.call(parent, node, ref); } finally { __moving = false; }
    let frames = false;
    __walkTree(node, (n) => { if (__isFrameEl(n)) frames = true; });
    if (frames) __framesChanged();
    for (const n of customs) __customCallback(n, moveCb(n) ? 'connectedMoveCallback' : 'connectedCallback');
  }
  // The same over a variadic call's nodes, all before any is inserted.
  function __needNoneAncestor(parent, nodes, method, iface) {
    for (const n of nodes) if (typeof n !== 'string') __needNotAncestor(parent, n, method, iface);
  }
  // One node copied as `cloneNode(false)` copies it.
  function __cloneOne(n) {
    const c = n.__ptShallowClone();
    // A clonable shadow root is copied with its host, its children deep.
    const sr = n.__ptType === ELEMENT_NODE && n.__ptShadow;
    if (sr && sr.__ptClonable) {
      const copy = __ptAttachShadow.call(c, { mode: sr.mode, delegatesFocus: !!sr.__ptDelegatesFocus, clonable: true, serializable: !!sr.__ptSerializable, slotAssignment: sr.__ptSlotAssignment });
      for (const k of sr.__ptKids) __ptAdd.call(copy, __ptCloneNode.call(k, true));
    }
    // A clone carries the exact inline style numbers, not the six-digit
    // printed ones: Chrome clones the parsed declaration, so
    // `scale(1.000998)` stays 1.000998 though the attribute says 1.001.
    try {
      if (n.__ptStyle && c.style) {
        const sr = __declRaw.get(n.__ptStyle), sm = sr && sr();
        if (sm && sm.__ptPrecise && sm.__ptPrecise.size) {
          const dr = __declRaw.get(c.style), dm = dr && dr();
          if (dm) { const pm = __cssPrecise(dm); for (const [k, v] of sm.__ptPrecise) if (dm.has(k)) pm.set(k, v); }
        }
      }
    } catch (e) {}
    return c;
  }
  // The data of the Text (and CDATA) descendants in tree order, as
  // `textContent` reads it: comments and processing instructions do not
  // count, nothing a page defines on a child is asked, and depth costs no
  // stack.
  function __descText(node) {
    let s = '';
    const st = [node.__ptKids || __NO_NODES, 0];
    while (st.length) {
      const top = st.length - 2;
      const kids = st[top], i = st[top + 1];
      if (i >= kids.length) { st.length = top; continue; }
      st[top + 1] = i + 1;
      const c = kids[i], t = c.__ptType;
      if (t === TEXT_NODE || t === 4) s += c.__ptData !== undefined ? c.__ptData : c.data;
      else if (c.__ptKids && c.__ptKids.length) st.push(c.__ptKids, 0);
    }
    return s;
  }
  class Node {
    constructor(type) {
      // Backing fields are __pt-prefixed (and therefore filtered out of every
      // introspection route by the stealth layer); the standard names are
      // prototype accessors defined below. A real DOM node has *no* own
      // properties — `Object.getOwnPropertyNames(document.body)` is `[]` — so
      // storing these directly on the instance would be an instant tell.
      this.__ptType = type;
      this.__ptKids = [];
      this.__ptParent = null;
      this.__ptDoc = globalThis.document || null;
      this.__ptLis = Object.create(null);
    }
    get firstChild() { return this.__ptKids[0] || null; }
    get lastChild() { return this.__ptKids[this.__ptKids.length - 1] || null; }
    get nextSibling() {
      const p = this.__ptParent; if (!p) return null;
      const i = __s_indexOf(p.__ptKids, this); return p.__ptKids[i + 1] || null;
    }
    get previousSibling() {
      const p = this.__ptParent; if (!p) return null;
      const i = __s_indexOf(p.__ptKids, this); return p.__ptKids[i - 1] || null;
    }
    hasChildNodes() { return this.__ptKids.length > 0; }
    contains(n) { for (; n; n = n.__ptParent) if (n === this) return true; return false; }
    // Walks out through a shadow host too: a node inside an attached shadow tree
    // is connected, even though the root itself has no parent.
    // The base URL is the document's; for `about:blank` it is the creator's.
    get baseURI() {
      const d = this.__ptType === 9 ? this : (this.ownerDocument || null);
      if (d && typeof d.__ptBaseURI === 'function') return d.__ptBaseURI();
      const href = (globalThis.location && globalThis.location.href) || 'about:blank';
      return href === 'about:blank' && typeof globalThis.__pt_inheritedBase === 'string' ? globalThis.__pt_inheritedBase : href;
    }
    get isConnected() {
      for (let n = this; n; n = n.__ptParent || n.__ptHost) {
        if (n.__ptType === DOCUMENT_NODE) return true;
      }
      return false;
    }
    getRootNode(opts) {
      let n = this;
      while (n.__ptParent || (n.__ptHost && opts && opts.composed)) n = n.__ptParent || n.__ptHost;
      return n;
    }

    appendChild(child) {
      __needArgs(arguments.length, 1, 'appendChild', 'Node');
      __needNode(child, 1, 'appendChild');
      __needNotAncestor(this, child, 'appendChild', 'Node');
      return __ptInsert.call(this, child, null);
    }
    insertBefore(child, ref) {
      __needArgs(arguments.length, 2, 'insertBefore', 'Node');
      __needNode(child, 1, 'insertBefore');
      __needNotAncestor(this, child, 'insertBefore', 'Node');
      // The second parameter is `Node?`: `undefined` is the same as `null`,
      // meaning "append".
      if (ref !== null && ref !== undefined) {
        __needNode(ref, 2, 'insertBefore');
        __needChild(this, ref, 'insertBefore',
          'The node before which the new node is to be inserted is not a child of this node.');
      }
      if (child.__ptType === DOCUMENT_FRAGMENT_NODE) {
        for (const c of __s_slice(child.__ptKids)) this.insertBefore(c, ref);
        return child;
      }
      if (child.__ptParent) __ptDrop.call(child.__ptParent, child);
      // A node from another document is adopted: it and its subtree get the
      // new parent's ownerDocument, as in Chrome.
      try {
        const doc = this.__ptType === 9 ? this : this.__ptDoc;
        if (doc && child.__ptDoc !== doc) __walkTree(child, (n) => { if (n.__ptDoc !== doc) n.__ptDoc = doc; });
      } catch (e) {}
      const i = (ref === null || ref === undefined) ? -1 : __s_indexOf(this.__ptKids, ref);
      if (i < 0) this.__ptKids.push(child); else this.__ptKids.splice(i, 0, child);
      child.__ptParent = this;
      if ((this.__ptTag === 'SELECT' || this.__ptTag === 'OPTGROUP') && child.__ptType === ELEMENT_NODE) __ptSelReset(this);
      __markDirty(this);
      __styleTouchKids(this, child, __s_indexOf(this.__ptKids, child));
      __hasNoteTree(child);
      __mutation(__childListRecord(this, [child], [], child.previousSibling, child.nextSibling));
      // A frame only becomes a browsing context once it is in the document — and
      // the frame is rarely the node being inserted. A widget builds its tree
      // detached and inserts the root of it: Turnstile puts its iframe in a closed
      // shadow root and then connects the host, so checking only `child` left the
      // iframe sitting there, connected and inert, and the widget waiting forever
      // for a frame that never opened.
      // The child is where its parent is; remembered before scripts in the
      // subtree run (a removal they make forgets it).
      const connected = __connectedFast(this);
      __connRemember(child, connected);
      if (connected) { __connInserts++; if (!__moving) __connectSubtree(child); }
      return child;
    }
    removeChild(child) {
      __needArgs(arguments.length, 1, 'removeChild', 'Node');
      __needNode(child, 1, 'removeChild');
      const i = __s_indexOf(this.__ptKids, child);
      if (i < 0) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'removeChild' on 'Node': The node to be removed is not a child of this node.",
          'NotFoundError');
      }
      const prev = this.__ptKids[i - 1] || null, next = this.__ptKids[i + 1] || null;
      __moNodeWillDetach(this, child);
      this.__ptKids.splice(i, 1); child.__ptParent = null; __connRemovals++; __markDirty(this); __styleTouchKids(this, null, i); __hasNoteTree(child);
      __mutation(__childListRecord(this, [], [child], prev, next));
      // A removed frame is a closed browsing context. Without this its V8 context
      // outlives the element forever — a widget that replaces its iframe on a
      // retry (Turnstile does, repeatedly) would pile them up until the cap. The
      // whole subtree goes, for the same reason it connects as a whole.
      let frameLeft = false;
      __walkTree(child, (f) => {
        if (__isFrameEl(f)) frameLeft = true;
        if (f.__ptFrameId) __ptDisconnectFrame(f);
        // A sandboxed frame: the page keeps its window, but the context is
        // closed (zero sizes, `closed`, no `frameElement`).
        if (f.__ptRealm) { try { if (typeof f.__ptRealm.__pt_detach === 'function') f.__ptRealm.__pt_detach(); } catch (e) {} try { __realmFrames.delete(f); } catch (e) {} }
        if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
      });
      if (frameLeft) __framesChanged();
      return child;
    }
    replaceChild(nw, old) {
      __needArgs(arguments.length, 2, 'replaceChild', 'Node');
      __needNode(nw, 1, 'replaceChild');
      __needNode(old, 2, 'replaceChild');
      __needNotAncestor(this, nw, 'replaceChild', 'Node');
      __needChild(this, old, 'replaceChild',
        'The node to be replaced is not a child of this node.');
      // Replacing a node with itself leaves it in place (Turnstile probes the
      // root this way); insert-then-remove would drop it.
      if (nw === old) return old;
      this.insertBefore(nw, old);
      return this.removeChild(old);
    }
    cloneNode(deep) {
      const c = __cloneOne(this);
      if (!deep) return c;
      // Depth first in tree order, without a stack frame per level (Chrome
      // clones trees thousands deep) and without asking the page's own
      // `cloneNode` on the children: (source children, next index, copy,
      // source) runs; a template's content follows its children.
      const st = [this.__ptKids, 0, c, this];
      while (st.length) {
        const top = st.length - 4;
        const kids = st[top], i = st[top + 1], dst = st[top + 2];
        if (i < kids.length) {
          st[top + 1] = i + 1;
          const ch = kids[i], cc = __cloneOne(ch);
          dst.appendChild(cc);
          st.push(ch.__ptKids || __NO_NODES, 0, cc, ch);
          continue;
        }
        const src = st[top + 3];
        st.length = top;
        if (src && src.__ptLocal === 'template' && src.__ptContent) {
          st.push(src.__ptContent.__ptKids, 0, __templateContent(dst), null);
        }
      }
      return c;
    }

    get textContent() {
      // A document and doctype have none: null, not the page's joined text.
      if (this.__ptType === 9 || this.__ptType === 10) return null;
      // Text, comment, processing instruction: their data (Chrome's Node.textContent).
      if (this.__ptType === 3 || this.__ptType === 4 || this.__ptType === 7 || this.__ptType === 8) return this.__ptData;
      return __descText(this);
    }
    set textContent(v) {
      if (this.__ptType === 9 || this.__ptType === 10) return;
      // [LegacyNullToEmptyString]
      if (this.__ptType === 3 || this.__ptType === 4 || this.__ptType === 7 || this.__ptType === 8) { __cdSetAll(this, v === null ? '' : String(v)); return; }
      if (this.__ptLocal === 'script') v = __pt_ttSink('TrustedScript', 'HTMLScriptElement textContent', v, "Failed to set the 'textContent' property on 'HTMLScriptElement'");
      __ptDropKids(this);
      if (v !== '') __ptAdd.call(this, new Text(String(v)));
    }

    // EventTarget
    addEventListener(type, fn, opts) {
      __needArgs(arguments.length, 2, 'addEventListener', 'EventTarget');
      if (!fn) return;
      // A handler property is queued where it was assigned: if `onload` was
      // set before the first listener, Chrome calls it first. The assignment
      // cannot be intercepted (`on…` is a plain property), but here we can see
      // whether it was already set.
      if (!this.__ptOnFirst) {
        Object.defineProperty(this, '__ptOnFirst', { value: {}, enumerable: false, configurable: true });
      }
      if (this.__ptOnFirst[type] === undefined) {
        this.__ptOnFirst[type] = typeof this['on' + type] === 'function';
      }
      __ptAddListener(this, this.__ptLis, type, fn, opts);
    }
    removeEventListener(type, fn, opts) {
      __ptRemoveListener(this.__ptLis, type, fn, opts);
    }
    __ptDispatch(event) {
      __ptEvSet(event, 'target', this);
      // `window.event` is the event being handled right now; inside a handler
      // Chrome has the event there.
      const savedEvent = __ptTakeEvent(event);
      // Event path as in Chrome: up parentNode, out of a shadow tree through
      // the host (for composed), from the document to the window (except
      // load). For nodes outside the shadow the target is retargeted to the
      // host. Widgets listen for mouse events on window and document.
      const path = [], targets = [];
      let tgt = this;
      // In Chrome ancestor (and window) listeners never hear enter/leave.
      const local = event.type === 'mouseenter' || event.type === 'mouseleave' || event.type === 'pointerenter' || event.type === 'pointerleave';
      for (let n = this; n; ) {
        if (local && n !== this) break;
        path.push(n); targets.push(tgt);
        if (n.__ptType === 11 && n.host) {
          if (!event.composed) break;
          n = n.host; tgt = n; continue;
        }
        if (n.__ptType === 9) {
          const w = n.defaultView;
          if (w && event.type !== 'load') { path.push(w); targets.push(tgt); }
          break;
        }
        // Not a node: an IndexedDB request bubbles to its transaction, then
        // to the database.
        n = n.__ptType === undefined ? (__ptEventParents.get(n) || null) : n.__ptParent;
      }
      __ptEvSet(event, '__ptPathNow', path);
      const fireAt = (i, phase) => {
        const node = path[i];
        const l = node.__ptLis && node.__ptLis[event.type];
        __ptEvSet(event, 'target', targets[i]);
        // After retargeting the shadow host is the target: the at-target phase.
        __ptEvSet(event, 'eventPhase', targets[i] === node ? 2 : phase);
        if (l) {
          for (const e of __s_slice(l)) {
            if (event.__ptStopImm) break;
            if (phase === 1 && !e.cap) continue;
            if (phase === 3 && e.cap) continue;
            __ptCallListener(node, e, event, 'listener');
          }
        }
        // An ancestor's handler property (`document.onmousemove`,
        // `window.onclick`) is a bubbling listener too.
        if (phase === 3 && !event.__ptStopImm) {
          let on; try { on = node['on' + event.type]; } catch (x) {}
          if (typeof on === 'function') {
            __ptEvSet(event, 'currentTarget', node);
            try { __ptCallOn(node, on, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
          }
        }
      };
      for (let i = path.length - 1; i >= 1; i--) { if (event.__ptStop) break; fireAt(i, 1); }
      __ptEvSet(event, 'target', this);
      __ptEvSet(event, 'eventPhase', 2);
      // A handler property (`onclick`, `onload`, `onmessage`) is a target
      // listener called by the same dispatch, in the order it was set relative
      // to the listeners.
      const onFirst = !!(this.__ptOnFirst && this.__ptOnFirst[event.type]);
      const callOn = () => {
        if (event.__ptStopImm) return;
        const on = this['on' + event.type];
        if (typeof on === 'function') {
          __ptEvSet(event, 'currentTarget', this);
          try { __ptCallOn(this, on, event); } catch (e) { __pt_reportError(e, 'listener ' + event.type); }
        }
      };
      // At the target, capture listeners first, then the rest (Chrome >= 89).
      const atTarget = (capture) => {
        const l = this.__ptLis && this.__ptLis[event.type]; if (!l) return;
        for (const e of __s_slice(l)) {
          if (event.__ptStopImm) break;
          if (!!e.cap !== capture) continue;
          __ptCallListener(this, e, event, 'listener');
        }
      };
      if (!event.__ptStop) atTarget(true);
      if (!event.__ptStop && onFirst) callOn();
      if (!event.__ptStop) atTarget(false);
      if (!onFirst) callOn();
      if (event.bubbles) for (let i = 1; i < path.length; i++) { if (event.__ptStop) break; fireAt(i, 3); }
      __ptEvSet(event, 'eventPhase', 0);
      __ptEvSet(event, 'currentTarget', null);
      // After dispatch the target as seen from the document (the shadow host).
      __ptEvSet(event, 'target', targets[targets.length - 1]);
      __ptEvSet(event, '__ptPathNow', null);
      // Restore `window.event`: outside handling it is absent.
      __ptDropEvent(savedEvent);
      return !event.defaultPrevented;
    }
  }
  // A handler exception is not lost: it goes to `window.onerror`, fires
  // `error` on the window and is printed to the console.
  // How many handler exceptions were reported: IndexedDB aborts a
  // transaction whose event handler threw.
  let __reported = 0;
  Object.defineProperty(globalThis, '__pt_reportedErrors', { value: () => __reported, configurable: true, enumerable: false });
  globalThis.__pt_reportError = (e, where) => {
    __reported++;
    const msg = 'Uncaught ' + String((e && e.name ? e.name + ': ' + e.message : e));
    // One trusted `error` event on the window; its `onerror` gets the five
    // arguments (see `__ptCallOn`).
    try {
      if (globalThis.ErrorEvent && globalThis.dispatchEvent) {
        const ev = __ptTrust(new ErrorEvent('error', {
          message: msg, error: e, cancelable: true,
          filename: (e && e.fileName) || (globalThis.location && location.href) || '',
          lineno: (e && e.lineNumber) || 0, colno: (e && e.columnNumber) || 0,
        }));
        globalThis.dispatchEvent(ev);
      }
    } catch (x) {}
    try { console.error(msg + (where ? ' (' + where + ')' : ''), (e && e.stack) || ''); } catch (x) {}
  };

  // An event handler property. The window's `onerror` is called with
  // (message, source, line, column, error) for an ErrorEvent, and `true`
  // from it cancels the event; any other handler gets the event, and
  // `false` from it cancels.
  function __ptCallOn(t, on, event) {
    if (event.type === 'error' && t === globalThis && globalThis.ErrorEvent && event instanceof globalThis.ErrorEvent) {
      const r = on.call(t, event.message, event.filename, event.lineno, event.colno, event.error);
      if (r === true) event.preventDefault();
      return;
    }
    const r = on.call(t, event);
    if (r === false && event.cancelable) event.preventDefault();
  }
  // Event handler content attributes (`onclick="…"`, `<body onload="…">`),
  // compiled when first asked for, as Chrome does: `function onclick(event)
  // {\n…\n}` with the document, the form and the element on its scope
  // chain, compiled as page script (not eval: a CSP without 'unsafe-eval'
  // still runs them; script-src-attr decides). The handler properties ask
  // here unless the page assigned one since the attribute last changed
  // (`__ptOnSet`, kept by the accessors). A body's window handlers (load,
  // resize, …) are the window's.
  const __WIN_HANDLERS = new Set(['afterprint', 'beforeprint', 'beforeunload', 'hashchange', 'languagechange',
    'message', 'messageerror', 'offline', 'online', 'pagehide', 'pageshow', 'popstate', 'rejectionhandled',
    'storage', 'unhandledrejection', 'unload', 'blur', 'error', 'focus', 'load', 'resize', 'scroll']);
  function __ptAttrHandler(target, type) {
    let host = target;
    if (target === globalThis) {
      const d = globalThis.document, b = d && d.body;
      if (!b || (b.__ptLocal !== 'body' && b.__ptLocal !== 'frameset') || !__WIN_HANDLERS.has(type)) return null;
      host = b;
    } else if (!target || target.__ptType !== ELEMENT_NODE) return null;
    else if ((target.__ptLocal === 'body' || target.__ptLocal === 'frameset') && __WIN_HANDLERS.has(type)) return null;
    const attrs = host.__ptAttrs;
    const src = attrs ? attrs.get('on' + type) : undefined;
    if (src === undefined) return null;
    let cache = host.__ptOnCache;
    if (!cache) {
      cache = new Map();
      try { Object.defineProperty(host, '__ptOnCache', { value: cache, configurable: true }); } catch (e) { return null; }
    }
    const hit = cache.get(type);
    if (hit && hit[0] === src) return hit[1];
    let fn = null;
    if (!(typeof globalThis.__pt_cspBlocksHandler === 'function' && globalThis.__pt_cspBlocksHandler(host, 'on' + type, src))
        && typeof __pt_evalScript === 'function') {
      const params = target === globalThis && type === 'error' ? 'event, source, lineno, colno, error'
        : host.__ptNS === 'http://www.w3.org/2000/svg' ? 'evt' : 'event';
      try {
        // Names no object has: a `with` scope looks every name up on its object
        // first (`__ptE` is an engine field every event carries).
        const make = __pt_evalScript('(function (__ptScopeDoc, __ptScopeForm, __ptScopeEl) { with (__ptScopeDoc) { with (__ptScopeForm) { with (__ptScopeEl) { return function on'
          + type + '(' + params + ') {\n' + src + '\n}; } } } })', String((globalThis.location && location.href) || ''), 0);
        const doc = host.ownerDocument || globalThis.document;
        const form = host.form && typeof host.form === 'object' ? host.form : {};
        if (typeof make === 'function') fn = make(doc, form, host);
      } catch (e) { __pt_reportError(e, 'on' + type); fn = null; }
    }
    cache.set(type, [src, fn]);
    return fn;
  }
  Object.defineProperty(globalThis, '__pt_attrHandler', { value: __ptAttrHandler, configurable: true, enumerable: false });
  // A changed `on…` attribute replaces what the page assigned.
  const __ptOnTouched = (el, name) => {
    if (__s_charCodeAt(name, 0) !== 111 || __s_charCodeAt(name, 1) !== 110) return;
    const type = __s_slice(name, 2);
    // Kept as false, not deleted: the assignment is gone, not just unmarked.
    if (el.__ptOnSet && el.__ptOnSet[type]) el.__ptOnSet[type] = false;
    if ((el.__ptLocal === 'body' || el.__ptLocal === 'frameset') && __WIN_HANDLERS.has(type) && globalThis.__ptOnSet && globalThis.__ptOnSet[type]) globalThis.__ptOnSet[type] = false;
  };
  function fireCapture(node, event) {
    const l = node.__ptLis && node.__ptLis[event.type]; if (!l) return;
    for (const e of __s_slice(l)) { if (!e.cap) continue; if (event.__ptStopImm) break; __ptCallListener(node, e, event, 'capture'); }
  }

  // These three methods live on `EventTarget.prototype`, once for all targets,
  // and also propagate events through the tree when the target is in one.
  // One implementation, names where Chrome has them.
  {
    const ET = globalThis.EventTarget;
    if (ET && ET.prototype) {
      const store = (t) => {
        if (!t.__ptLis) {
          try { Object.defineProperty(t, '__ptLis', { value: Object.create(null), enumerable: false, writable: true }); }
          catch (e) { return Object.create(null); }
        }
        return t.__ptLis;
      };
      // With no receiver the target is the window: a bare
      // `addEventListener(...)` has `this === undefined`, and Chrome uses the global.
      const self_ = (t) => (t === undefined || t === null ? globalThis : t);
      const proto = ET.prototype;
      for (const [name, fn] of [
        ['addEventListener', function addEventListener(type, fn, opts) {
          __needArgs(arguments.length, 2, 'addEventListener', 'EventTarget');
          const t = self_(this); if (!fn) return;
          // Same ordering bookkeeping as for nodes: was `on…` set before the
          // first listener.
          try {
            if (!t.__ptOnFirst) {
              Object.defineProperty(t, '__ptOnFirst', { value: {}, enumerable: false, configurable: true });
            }
            if (t.__ptOnFirst[type] === undefined) {
              t.__ptOnFirst[type] = typeof t['on' + type] === 'function';
            }
          } catch (e) {}
          __ptAddListener(t, store(t), type, fn, opts);
        }],
        ['removeEventListener', function removeEventListener(type, fn, opts) {
          __needArgs(arguments.length, 2, 'removeEventListener', 'EventTarget');
          const t = self_(this);
          __ptRemoveListener(t.__ptLis, type, fn, opts);
        }],
        ['dispatchEvent', function dispatchEvent(event) {
          const t = self_(this);
          return Node.prototype.__ptDispatch.call(t, event);
        }],
      ]) {
        try {
          Object.defineProperty(proto, name, { value: globalThis.__pt_native ? __pt_native(fn) : fn,
                                               writable: true, enumerable: true, configurable: true });
        } catch (e) {}
      }
      // Node inherits them from the same place as in Chrome.
      try { Object.setPrototypeOf(Node.prototype, proto); } catch (e) {}
      for (const name of ['addEventListener', 'removeEventListener', 'dispatchEvent']) {
        try { delete Node.prototype[name]; } catch (e) {}
      }
    }
  }

  // Expose the standard node properties as prototype accessors over the hidden
  // backing fields, so instances stay free of own properties (see constructor).
  const accessor = (name, get, set) => {
    // Real accessors report `function get <name>() { [native code] }`; an
    // anonymous function would read `function ()` and stand out.
    try { Object.defineProperty(get, 'name', { value: 'get ' + name, configurable: true }); } catch (e) {}
    try { Object.defineProperty(set, 'name', { value: 'set ' + name, configurable: true }); } catch (e) {}
    return { get, set, configurable: true, enumerable: false };
  };
  // Chrome returns canonical encoding names: utf-8 -> UTF-8, latin1 ->
  // windows-1252. Others pass through lowercased.
  const __ENCODINGS = {
    'utf-8': 'UTF-8', 'utf8': 'UTF-8', 'unicode-1-1-utf-8': 'UTF-8',
    'iso-8859-1': 'windows-1252', 'latin1': 'windows-1252', 'ascii': 'windows-1252',
    'us-ascii': 'windows-1252', 'windows-1252': 'windows-1252', 'cp1252': 'windows-1252',
    'utf-16': 'UTF-16LE', 'utf-16le': 'UTF-16LE', 'utf-16be': 'UTF-16BE',
  };
  const __normEncoding = (name) => {
    const k = __s_toLowerCase(__s_trim(String(name)));
    return __ENCODINGS[k] || k;
  };

  // ChildNode.remove lives on elements and text nodes, not on the document;
  // an extra name on `document` is as visible as a missing one.
  // The engine sets target, currentTarget and phase itself: pages read them
  // but have no setters. Own events keep them in `__ptE`, events from another
  // realm as an own property.
  // `window.event` is the event currently being handled. Workers have no such
  // name, and restoring must not create it (assigning `undefined` creates an
  // own property). The window marker is `importScripts` (worker only), not
  // `document`, which the engine builds in workers too and hides.
  const __ptEventSlot = () => typeof importScripts === 'undefined';
  // Event parents of targets that are not nodes (IndexedDB: request ->
  // transaction -> database). Weak: the parent link dies with the child.
  const __ptEventParents = new WeakMap();
  Object.defineProperty(globalThis, '__pt_eventParents', { value: __ptEventParents, configurable: true, enumerable: false });
  const __ptTakeEvent = (ev) => {
    const hadEvent = Object.prototype.hasOwnProperty.call(globalThis, 'event');
    const prevEvent = hadEvent ? globalThis.event : undefined;
    if (__ptEventSlot()) { try { globalThis.event = ev; } catch (e) {} }
    return { hadEvent, prevEvent };
  };
  const __ptDropEvent = (savedEvent) => {
    try {
      if (savedEvent.hadEvent) globalThis.event = savedEvent.prevEvent;
      else delete globalThis.event;
    } catch (e) {}
  };

  // Focus event: a trusted `FocusEvent` with a related target, sent by the
  // browser even when a script requested focus.
  const __ptFocusEvent = (type, related, bubbles) => {
    const C = globalThis.FocusEvent || globalThis.Event;
    let ev;
    // focus/blur/focusin/focusout are composed: they cross shadow boundaries.
    try { ev = new C(type, { bubbles: !!bubbles, cancelable: false, composed: true, relatedTarget: related || null }); }
    catch (e) { ev = new Event(type, { bubbles: !!bubbles }); }
    if (!('relatedTarget' in ev)) {
      try { Object.defineProperty(ev, 'relatedTarget', { value: related || null, enumerable: true, configurable: true }); }
      catch (e) {}
    }
    // Focus from a mouse press carries the input device, as in Chrome.
    if (globalThis.__ptFocusCaps && ev.__ptE) ev.__ptE.sourceCapabilities = globalThis.__ptFocusCaps;
    return __ptTrust(ev);
  };

  const __ptEvSet = (ev, key, value) => {
    if (!ev) return;
    if (ev.__ptE) { ev.__ptE[key] = value; return; }
    try { Object.defineProperty(ev, key, { value, configurable: true, writable: true }); } catch (e) {}
  };

  const __removeSelf = function remove() { if (this.__ptParent) this.__ptParent.removeChild(this); };

  Object.defineProperties(Node.prototype, {
    nodeType: accessor('nodeType', function () { return this.__ptType; }, function (v) { this.__ptType = v; }),
    childNodes: accessor('childNodes',
      function () { return __nodeList(this); },
      function (v) { this.__ptKids = Array.from(v); }),
    parentNode: accessor('parentNode', function () { return this.__ptParent; }, function (v) { this.__ptParent = v; }),
    ownerDocument: accessor('ownerDocument', function () { return this.__ptDoc; }, function (v) { this.__ptDoc = v; }),
  });

  // ---- CharacterData: Text / Comment / ProcessingInstruction --------------
  // Offsets and counts are WebIDL `unsigned long`: -1 is 4294967295.
  const __u32 = (v) => Number(v) >>> 0;
  const __cdIndexError = (method, iface, off, len) => __pt_mkErr(globalThis.DOMException || Error,
    "Failed to execute '" + method + "' on '" + iface + "': The offset " + off + " is greater than the node's length (" + len + ").",
    'IndexSizeError');
  // Replace data (DOM standard): the record carries the old value; a text
  // change is layout work for the parent.
  function __cdReplace(node, offset, count, data) {
    const old = node.__ptData;
    if (offset + count > old.length) count = old.length - offset;
    node.__ptData = __s_slice(old, 0, offset) + data + __s_slice(old, offset + count);
    __mutation({ type: 'characterData', target: node, attributeName: null, attributeNamespace: null,
      oldValue: old, addedNodes: __NO_NODES, removedNodes: __NO_NODES, previousSibling: null, nextSibling: null });
    if (node.__ptType === TEXT_NODE && node.__ptParent) __markDirty(node.__ptParent);
  }
  const __cdSetAll = (node, v) => __cdReplace(node, 0, node.__ptData.length, v);
  class CharacterData extends Node {
    constructor(...a) {
      if (new.target === CharacterData) throw __pt_mkErr(TypeError, "Failed to construct 'CharacterData': Illegal constructor");
      super(a[0]);
      this.__ptData = '';
    }
    get data() { return this.__ptData; }
    // [LegacyNullToEmptyString]
    set data(v) { __cdSetAll(this, v === null ? '' : String(v)); }
    // NonDocumentTypeChildNode: text and comments have element siblings too
    // (Lit finds the element after its `<!--lit-node-->` marker this way).
    get nextElementSibling() { let n = this.nextSibling; while (n && n.__ptType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.__ptType !== ELEMENT_NODE) n = n.previousSibling; return n; }
    get length() { return this.__ptData.length; }
    appendData(data) {
      __needArgs(arguments.length, 1, 'appendData', 'CharacterData');
      __cdReplace(this, this.__ptData.length, 0, String(data));
    }
    insertData(offset, data) {
      __needArgs(arguments.length, 2, 'insertData', 'CharacterData');
      const off = __u32(offset), str = String(data), len = this.__ptData.length;
      if (off > len) throw __cdIndexError('insertData', 'CharacterData', off, len);
      __cdReplace(this, off, 0, str);
    }
    deleteData(offset, count) {
      __needArgs(arguments.length, 2, 'deleteData', 'CharacterData');
      const off = __u32(offset), n = __u32(count), len = this.__ptData.length;
      if (off > len) throw __cdIndexError('deleteData', 'CharacterData', off, len);
      __cdReplace(this, off, n, '');
    }
    replaceData(offset, count, data) {
      __needArgs(arguments.length, 3, 'replaceData', 'CharacterData');
      const off = __u32(offset), n = __u32(count), str = String(data), len = this.__ptData.length;
      if (off > len) throw __cdIndexError('replaceData', 'CharacterData', off, len);
      __cdReplace(this, off, n, str);
    }
    substringData(offset, count) {
      __needArgs(arguments.length, 2, 'substringData', 'CharacterData');
      const off = __u32(offset), n = __u32(count), d = this.__ptData;
      if (off > d.length) throw __cdIndexError('substringData', 'CharacterData', off, d.length);
      return __s_slice(d, off, off + Math.min(n, d.length - off));
    }
  }
  class Text extends CharacterData {
    constructor(data) { super(TEXT_NODE); this.__ptData = data === undefined ? '' : String(data); }
    get assignedSlot() { return __slotFor(this, true); }
    // The data of this node and the Text nodes next to it.
    get wholeText() {
      const p = this.__ptParent;
      if (!p) return this.__ptData;
      const kids = p.__ptKids, i = __s_indexOf(kids, this);
      let a = i, b = i;
      while (a > 0 && (kids[a - 1].__ptType === TEXT_NODE || kids[a - 1].__ptType === 4)) a--;
      while (b < kids.length - 1 && (kids[b + 1].__ptType === TEXT_NODE || kids[b + 1].__ptType === 4)) b++;
      let s = '';
      for (let k = a; k <= b; k++) s += kids[k].__ptData;
      return s;
    }
    // As Blink: the data is cut first (a characterData record), then the new
    // node goes in after this one.
    splitText(offset) {
      __needArgs(arguments.length, 1, 'splitText', 'Text');
      const off = __u32(offset), d = this.__ptData;
      if (off > d.length) {
        throw __pt_mkErr(globalThis.DOMException || Error,
          "Failed to execute 'splitText' on 'Text': The offset " + off + " is larger than the Text node's length.", 'IndexSizeError');
      }
      const nw = new Text(__s_slice(d, off));
      nw.__ptDoc = this.__ptDoc;
      __cdReplace(this, off, d.length - off, '');
      const p = this.__ptParent;
      if (p) {
        const kids = p.__ptKids;
        __ptInsert.call(p, nw, kids[__s_indexOf(kids, this) + 1] || null);
      }
      return nw;
    }
    __ptShallowClone() { return new Text(this.__ptData); }
  }
  class Comment extends CharacterData {
    constructor(data) { super(COMMENT_NODE); this.__ptData = data === undefined ? '' : String(data); }
    __ptShallowClone() { return new Comment(this.__ptData); }
  }
  // Processing instructions: from `createProcessingInstruction` and, as in
  // Chrome 151, from `<?target data?>` in HTML. Their attributes are the
  // data read as XML attributes (processing_instruction.cc); a data that
  // does not parse has none.
  const __PI_MAKE = {};
  const __XML_NAME_START = 'A-Z_a-z:\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD';
  const __XML_NAME = new RegExp('^[' + __XML_NAME_START + '](?:[' + __XML_NAME_START + '\\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]|[\uD800-\uDB7F][\uDC00-\uDFFF])*$');
  const __XML_NAME_AT = new RegExp('[' + __XML_NAME_START + '](?:[' + __XML_NAME_START + '\\-.0-9\u00B7\u0300-\u036F\u203F-\u2040]|[\uD800-\uDB7F][\uDC00-\uDFFF])*', 'y');
  const __XML_REFS = { lt: '<', gt: '>', amp: '&', apos: "'", quot: '"' };
  let __piParsed = new Map();
  function __piAttrs(data) {
    let hit = __piParsed.get(data);
    if (hit !== undefined) return hit;
    hit = __piParse(data);
    if (__piParsed.size >= 256) __piParsed = new Map();
    __piParsed.set(data, hit);
    return hit;
  }
  // [[name, value]...] in source order (Chrome keeps a hash map: with two or
  // more attributes its order differs), or [] when the data is not a list of
  // attributes.
  function __piParse(raw) {
    const s = __s_replace(__s_replace(raw, /\r\n/g, '\n'), /\r/g, '\n');
    const out = [], seen = new Set();
    const ws = (c) => c === ' ' || c === '\t' || c === '\n';
    let i = 0;
    for (;;) {
      const at = i;
      while (i < s.length && ws(s[i])) i++;
      if (i >= s.length) break;
      if (out.length + seen.size && i === at) return [];
      __XML_NAME_AT.lastIndex = i;
      const m = __XML_NAME_AT.exec(s);
      if (!m) return [];
      const name = m[0];
      i += name.length;
      while (i < s.length && ws(s[i])) i++;
      if (s[i] !== '=') return [];
      i++;
      while (i < s.length && ws(s[i])) i++;
      const q = s[i];
      if (q !== '"' && q !== "'") return [];
      i++;
      let v = '';
      for (;;) {
        if (i >= s.length) return [];
        const c = s[i];
        if (c === q) { i++; break; }
        if (c === '<') return [];
        if (c === '&') {
          const end = __s_indexOf(s, ';', i);
          if (end < 0) return [];
          const ref = __s_slice(s, i + 1, end);
          let ch;
          if (/^#[0-9]+$/.test(ref)) ch = String.fromCodePoint(parseInt(__s_slice(ref, 1), 10));
          else if (/^#x[0-9a-fA-F]+$/.test(ref)) ch = String.fromCodePoint(parseInt(__s_slice(ref, 2), 16));
          else if (__XML_REFS[ref] !== undefined) ch = __XML_REFS[ref];
          else return [];
          v += ch;
          i = end + 1;
          continue;
        }
        v += ws(c) ? ' ' : c;
        i++;
      }
      if (seen.has(name)) return [];
      seen.add(name);
      if (name === 'xmlns' || __s_startsWith(name, 'xmlns:')) continue;
      out.push([name, v]);
    }
    return out;
  }
  const __piAttrValue = (v) => __s_replace(v, /[&<>"\u00A0]/g, (c) => (c === '\u00A0' ? '&nbsp;' : ESC[c]));
  function __piWrite(pi, attrs) {
    __cdSetAll(pi, attrs.map(([k, v]) => k + '="' + __piAttrValue(v) + '"').join(' '));
  }
  const __asciiLower = (s) => __s_replace(String(s), /[A-Z]/g, (c) => __s_toLowerCase(c));
  class ProcessingInstruction extends CharacterData {
    constructor(...a) {
      if (a[0] !== __PI_MAKE) throw __pt_mkErr(TypeError, "Failed to construct 'ProcessingInstruction': Illegal constructor");
      super(7);
      this.__ptTarget = a[1];
      this.__ptData = a[2];
    }
    get target() { return this.__ptTarget; }
    get sheet() { return null; }
    getAttribute(name) {
      __needArgs(arguments.length, 1, 'getAttribute', 'ProcessingInstruction');
      const n = __asciiLower(name);
      for (const [k, v] of __piAttrs(this.__ptData)) if (k === n) return v;
      return null;
    }
    getAttributeNames() { return __piAttrs(this.__ptData).map((p) => p[0]); }
    hasAttribute(name) {
      __needArgs(arguments.length, 1, 'hasAttribute', 'ProcessingInstruction');
      const n = __asciiLower(name);
      return __piAttrs(this.__ptData).some((p) => p[0] === n);
    }
    hasAttributes() { return __piAttrs(this.__ptData).length > 0; }
    removeAttribute(name) {
      __needArgs(arguments.length, 1, 'removeAttribute', 'ProcessingInstruction');
      const n = __asciiLower(name), attrs = __piAttrs(this.__ptData).slice();
      const i = attrs.findIndex((p) => p[0] === n);
      if (i < 0) return;
      attrs.splice(i, 1);
      __piWrite(this, attrs);
    }
    setAttribute(name, value) {
      __needArgs(arguments.length, 2, 'setAttribute', 'ProcessingInstruction');
      const n = __asciiLower(name), v = String(value), attrs = __piAttrs(this.__ptData).map((p) => p.slice());
      const hit = attrs.find((p) => p[0] === n);
      if (hit) hit[1] = v; else attrs.push([n, v]);
      __piWrite(this, attrs);
    }
    toggleAttribute(name, force) {
      __needArgs(arguments.length, 1, 'toggleAttribute', 'ProcessingInstruction');
      const raw = String(name);
      if (!__XML_NAME.test(raw)) {
        throw __pt_mkErr(globalThis.DOMException || Error,
          "Failed to execute 'toggleAttribute' on 'ProcessingInstruction': Invalid attribute name: " + raw, 'InvalidCharacterError');
      }
      const n = __asciiLower(raw);
      const there = __piAttrs(this.__ptData).some((p) => p[0] === n);
      const on = force === undefined ? !there : !!force;
      if (on) { if (!there) this.setAttribute(n, ''); } else this.removeAttribute(n);
    }
    __ptShallowClone() { return new ProcessingInstruction(__PI_MAKE, this.__ptTarget, this.__ptData); }
  }
  const __makePI = (doc, target, data) => {
    const n = new ProcessingInstruction(__PI_MAKE, String(target), String(data));
    n.__ptDoc = doc;
    return n;
  };

  // ---- Element --------------------------------------------------------------
  /// A shadow root: a fragment that carries the query surface of an element and
  /// remembers its host, so a subtree can live outside the document tree while
  /// still being connected through it.
  // DocumentFragment is its own interface, not an alias of Node: Chrome has
  // eleven members on it, and `t.content.querySelector(...)` relies on them.
  class DocumentFragment extends Node {
    constructor() { super(DOCUMENT_FRAGMENT_NODE); }
    get [Symbol.toStringTag]() { return 'DocumentFragment'; }
    // Fragments are cloneable too; `importNode` and `<template>` content need it.
    __ptShallowClone() { const f = new DocumentFragment(); f.__ptDoc = this.ownerDocument; return f; }
    get children() { return __collection(this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.__ptType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    getElementById(id) { const want = String(id); return firstMatch(this, (e) => __ptGetA(e, 'id') === want); }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return queryFirst(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'));
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    // A fragment appended to itself is let through, as in Chrome.
    append(...nodes) {
      __needNoneAncestor(this, nodes.filter((n) => n !== this), 'append', 'DocumentFragment');
      for (const n of nodes) if (n !== this) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    prepend(...nodes) {
      __needNoneAncestor(this, nodes.filter((n) => n !== this), 'prepend', 'DocumentFragment');
      const first = this.__ptKids[0] || null;
      for (const n of nodes) if (n !== this) this.insertBefore(typeof n === 'string' ? new Text(n) : n, first);
    }
    replaceChildren(...nodes) {
      __needNoneAncestor(this, nodes, 'replaceChildren', 'DocumentFragment');
      __ptDropKids(this);
      for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    moveBefore(node, child) { __moveBefore(this, arguments, 'DocumentFragment'); }
  }

  class ShadowRoot extends DocumentFragment {
    constructor(host, mode) {
      super();
      this.__ptHost = host;
      this.__ptMode = mode;
      this.__ptDoc = host.ownerDocument;
    }
    get [Symbol.toStringTag]() { return 'ShadowRoot'; }
    get host() { return this.__ptHost; }
    get mode() { return this.__ptMode; }
    get delegatesFocus() { return !!this.__ptDelegatesFocus; }
    get clonable() { return !!this.__ptClonable; }
    get serializable() { return !!this.__ptSerializable; }
    get slotAssignment() { return this.__ptSlotAssignment || 'named'; }
    getHTML(opts) { return this.__ptKids.map((n) => serializeNode(n, !!(opts && opts.serializableShadowRoots))).join(''); }
    get nodeName() { return '#document-fragment'; }
    get nodeValue() { return null; }
    get textContent() { return __descText(this); }
    set textContent(v) { __ptDropKids(this); if (v !== '') this.appendChild(new Text(String(v))); }
    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      html = __pt_ttSink('TrustedHTML', 'ShadowRoot innerHTML', html, "Failed to set the 'innerHTML' property on 'ShadowRoot'");
      // Template markup is parsed into its content.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      __ptDropKids(host);
      for (const n of parseFragment(String(html), this.__ptHost || null)) __ptAdd.call(host, n);
    }
    // A collection, not an array: `document.children` is an HTMLCollection,
    // and `Object.prototype.toString` says so.
    get children() { return __collection(this.__ptKids.filter(n => n.__ptType === ELEMENT_NODE)); }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get childElementCount() { return this.children.length; }
    // `<body>` once there is a body, not null. It is also assigned (by
    // `focus()`), so a getter alone is not enough.
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    // Not an array: Chrome returns a `StyleSheetList`, `Array.isArray` is
    // false. The widget lives in a shadow root and reads it there.
    get styleSheets() { return __styleSheetList(__sheetOwners(this)); }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    getElementById(id) { const want = String(id); return firstMatch(this, (e) => __ptGetA(e, 'id') === want); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) { return __collection(__byClass(this, c)); }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return queryFirst(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'));
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    append(...ns) {
      __needNoneAncestor(this, ns, 'append', 'DocumentFragment');
      for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    prepend(...ns) {
      __needNoneAncestor(this, ns, 'prepend', 'DocumentFragment');
      for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild);
    }
    // DocumentOrShadowRoot: a shadow root answers like the document (Chrome
    // returns the stack up to <html>).
    elementFromPoint(x, y) { const d = globalThis.document; return d ? d.elementFromPoint(x, y) : null; }
    elementsFromPoint(x, y) { const d = globalThis.document; return d ? d.elementsFromPoint(x, y) : []; }
    getSelection() { return typeof globalThis.getSelection === 'function' ? globalThis.getSelection() : null; }
    getAnimations() { return []; }
  }

  // --- custom elements -------------------------------------------------------
  // A real registry: definition, upgrade of nodes already in the document, and
  // the three lifecycle callbacks (`customElements.get` is common in bundles).
  const __customs = new Map();          // name -> class
  const __customPending = new Map();    // name -> { promise, resolve }
  const __customName = (ctor) => {
    for (const [name, C] of __customs) if (C === ctor) return name;
    return null;
  };
  const __customCallback = (el, name, args) => {
    const fn = el[name];
    if (typeof fn === 'function') { try { fn.apply(el, args || []); } catch (e) { /* component threw */ } }
  };
  const __customUpgrade = (el, Ctor) => {
    if (el.__ptUpgraded) return;
    Object.defineProperty(el, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
    try { Object.setPrototypeOf(el, Ctor.prototype); } catch (e) { return; }
    // The constructor runs on the element itself (its fields, its state);
    // one that throws is reported and the element stays as it is.
    const prev = __upgrading;
    __upgrading = { el, ctor: Ctor };
    try { Reflect.construct(Ctor, []); }
    catch (e) { if (typeof globalThis.__pt_reportError === 'function') __pt_reportError(e, 'custom element'); }
    finally { __upgrading = prev; }
    const watched = Ctor.observedAttributes;
    if (Array.isArray(watched)) {
      for (const a of watched) {
        const v = __ptGetA(el, a);
        if (v !== null) __customCallback(el, 'attributeChangedCallback', [a, null, v, null]);
      }
    }
    if (el.isConnected) __customCallback(el, 'connectedCallback');
  };

  class CustomElementRegistry {
    define(name, ctor, options) {
      name = String(name);
      if (!/^[a-z][a-z0-9._]*-[a-z0-9._-]*$/.test(name)) {
        throw __pt_mkErr(globalThis.DOMException || Error, `"${name}" is not a valid custom element name`, 'SyntaxError');
      }
      if (__customs.has(name)) {
        throw __pt_mkErr(globalThis.DOMException || Error, `"${name}" has already been defined`, 'NotSupportedError');
      }
      if (typeof ctor !== 'function') throw __pt_mkErr(TypeError, 'constructor is not a constructor');
      __customs.set(name, ctor);
      const doc = globalThis.document;
      // `:defined` may now match: style is asked again. Rules added since
      // the last pass marked it themselves.
      if (doc && doc.documentElement && __readsDefined(__rules)) __markDirty(doc.documentElement);
      if (doc && doc.documentElement) {
        for (const el of __docTags(doc, name)) __customUpgrade(el, ctor);
      }
      const pending = __customPending.get(name);
      if (pending) { pending.resolve(ctor); __customPending.delete(name); }
    }
    get(name) { return __customs.get(String(name)); }
    getName(ctor) { return __customName(ctor); }
    whenDefined(name) {
      name = String(name);
      const known = __customs.get(name);
      if (known) return Promise.resolve(known);
      let entry = __customPending.get(name);
      if (!entry) {
        let resolve;
        const promise = new Promise((r) => { resolve = r; });
        entry = { promise, resolve };
        __customPending.set(name, entry);
      }
      return entry.promise;
    }
    upgrade(root) {
      __walkTree(root, (el) => {
        if (el.__ptType !== ELEMENT_NODE) return;
        const C = __customs.get(el.__ptLocal);
        if (C) __customUpgrade(el, C);
      });
    }
  }

  // A form is a proxy over its element that answers its controls by name and
  // index (the forms block below makes it). The engine reads the form's own
  // members through `__formGet`, past any control of the same name.
  let __formProxy = null;
  const __formTargets = new WeakMap();
  // Every value an id or a name attribute has had: a key not in it names no
  // control, without a look at the tree. A page that keeps making new ids
  // fills it once; past that every key is looked up.
  const __namesSet = new Set();
  let __namesFull = false;
  const __namesSeen = {
    add(v) { if (__namesFull) return; if (__namesSet.size >= 65536) { __namesFull = true; __namesSet.clear(); } else __namesSet.add(v); },
    has(k) { return __namesFull || __namesSet.has(k); },
  };
  // Bumped by the changes that can move a control between forms or rename
  // it, so a form works out its controls again only then.
  let __formSeq = 0;
  const __FORM_TREE = new Set(['form', 'img', 'button', 'fieldset', 'input', 'object', 'output', 'select', 'textarea']);
  const __formNoteTree = (n) => {
    if (!n || n.__ptType !== ELEMENT_NODE && n.__ptType !== 11) return;
    if (__FORM_TREE.has(n.__ptLocal)) { __formSeq++; return; }
    const st = [n];
    while (st.length) {
      const kids = st.pop().__ptKids;
      if (kids) for (let i = 0; i < kids.length; i++) {
        const k = kids[i];
        if (k.__ptType !== ELEMENT_NODE) continue;
        if (__FORM_TREE.has(k.__ptLocal)) { __formSeq++; return; }
        if (k.__ptKids.length) st.push(k);
      }
    }
  };
  const __formNoteAttr = (name) => { if (name === 'id' || name === 'name' || name === 'form' || name === 'type') __formSeq++; };
  const __formGet = (f, k) => Reflect.get(__formTargets.get(f) || f, k, f);

  class Element extends Node {
    moveBefore(node, child) { __moveBefore(this, arguments, 'Element'); }
    constructor(tag) {
      super(ELEMENT_NODE);
      // `new MyElement()` passes no tag name; the registry knows it by the
      // class. Real HTMLElement works the same way.
      if (tag === undefined && new.target) tag = __customName(new.target) || 'unknown';
      this.__ptTag = __s_toUpperCase(String(tag));
      this.__ptLocal = __s_toLowerCase(String(tag));
      this.__ptAttrs = new Map();
      if (this.__ptLocal === 'form' && __formProxy) return __formProxy(this);
    }
    get nodeName() { return this.tagName; }
    get tagName() { return this.__ptTag; }
    get localName() { return this.__ptLocal; }
    // Element namespace, including SVG from createElementNS.
    get namespaceURI() { return this.__ptNS === undefined ? 'http://www.w3.org/1999/xhtml' : this.__ptNS; }
    get prefix() { return this.__ptPrefix || null; }
    // The style declaration is built on first access, not at node creation:
    // it has 700 own properties, ~0.5 ms per node.
    get style() {
      if (!this.__ptStyle) {
        Object.defineProperty(this, '__ptStyle', {
          value: makeStyle(this), writable: true, enumerable: false, configurable: true,
        });
      }
      return this.__ptStyle;
    }

    // Attributes. Names are lowercased for HTML elements only; SVG and other
    // foreign names are case-sensitive (`viewBox`), per spec.
    getAttribute(n) { const v = this.__ptAttrs.get(__attrName(this, n)); return v === undefined ? null : v; }
    setAttribute(n, v) {
      __needArgs(arguments.length, 2, 'setAttribute', 'Element');
      const name = __attrName(this, n), old = this.__ptAttrs.get(name);
      if (name === 'nonce') { this.__ptNonce = String(v); if (__csp.headerDelivered) v = ''; }
      if (name === 'src' && this.__ptLocal === 'script') v = __pt_ttSink('TrustedScriptURL', 'HTMLScriptElement src', v, "Failed to execute 'setAttribute' on 'Element'");
      else if (name === 'srcdoc' && this.__ptLocal === 'iframe') v = __pt_ttSink('TrustedHTML', 'HTMLIFrameElement srcdoc', v, "Failed to execute 'setAttribute' on 'Element'");
      this.__ptAttrs.set(name, String(v));
      if (name === 'id' || name === 'name') __namesSeen.add(String(v));
      if (old === undefined) __attrMapSync(this);
      __styleTouchAttr(this, name, old, String(v));
      __ptOnTouched(this, name);
      __hasNoteAttr(name, old, String(v));
      if (name === 'src' && (this.__ptLocal === 'video' || this.__ptLocal === 'audio') && globalThis.__pt_mediaLoad) __pt_mediaLoad(this);
      if (this.__ptUpgraded) {
        const watched = this.constructor && this.constructor.observedAttributes;
        if (Array.isArray(watched) && __s_indexOf(watched, name) >= 0) {
          __customCallback(this, 'attributeChangedCallback',
            [name, old === undefined ? null : old, String(v), null]);
        }
      }
      __markDirty(this);
      const info = __attrNsOf(this, name);
      __mutation({ type: 'attributes', target: this, attributeName: info ? info[2] : name, attributeNamespace: info ? info[0] : null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    removeAttribute(n) {
      const name = __attrName(this, n), old = this.__ptAttrs.get(name);
      if (old === undefined) return;
      this.__ptAttrs.delete(name);
      __attrDetach(this, name, old);
      __attrMapSync(this);
      if (name === 'src' && this.__ptLocal === 'img' && this.__ptCurWant !== undefined) {
        this.__ptCurWant = undefined;
        Object.defineProperty(this, '__ptCurSrc', { value: '', writable: true, configurable: true, enumerable: false });
      }
      const info = __attrNsOf(this, name);
      if (info) this.__ptAttrNS.delete(name);
      __markDirty(this);
      __styleTouchAttr(this, name, old, null);
      __ptOnTouched(this, name);
      __hasNoteAttr(name, old, null);
      __mutation({ type: 'attributes', target: this, attributeName: info ? info[2] : name, attributeNamespace: info ? info[0] : null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    hasAttribute(n) { return this.__ptAttrs.has(__attrName(this, n)); }
    getAttributeNS(ns, local) {
      __needArgs(arguments.length, 2, 'getAttributeNS', 'Element');
      const q = __attrNsFind(this, ns, local);
      return q === null ? null : this.__ptAttrs.get(q);
    }
    hasAttributeNS(ns, local) {
      __needArgs(arguments.length, 2, 'hasAttributeNS', 'Element');
      return __attrNsFind(this, ns, local) !== null;
    }
    getAttributeNodeNS(ns, local) {
      __needArgs(arguments.length, 2, 'getAttributeNodeNS', 'Element');
      const q = __attrNsFind(this, ns, local);
      return q === null ? null : __attrNode(this, q);
    }
    setAttributeNS(ns, qname, v) {
      __needArgs(arguments.length, 3, 'setAttributeNS', 'Element');
      const [N, prefix, local] = __attrNsExtract(ns, qname, 'setAttributeNS');
      // An attribute already there keeps its prefix; only its value changes.
      const was = __attrNsFind(this, N, local);
      const q = was !== null ? was : prefix !== null ? prefix + ':' + local : local;
      const old = this.__ptAttrs.get(q), val = String(v);
      this.__ptAttrs.set(q, val);
      if (q === 'id' || q === 'name') __namesSeen.add(val);
      if (old === undefined) __attrMapSync(this);
      if (was === null) { if (N !== null) __attrNsMap(this).set(q, [N, prefix, local]); else if (this.__ptAttrNS) this.__ptAttrNS.delete(q); }
      __styleTouchAttr(this, q, old, val);
      __ptOnTouched(this, q);
      __hasNoteAttr(q, old, val);
      __markDirty(this);
      __mutation({ type: 'attributes', target: this, attributeName: local, attributeNamespace: N,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    removeAttributeNS(ns, local) {
      __needArgs(arguments.length, 2, 'removeAttributeNS', 'Element');
      const q = __attrNsFind(this, ns, local);
      if (q === null) return;
      const info = __attrNsOf(this, q), old = this.__ptAttrs.get(q);
      this.__ptAttrs.delete(q);
      __attrDetach(this, q, old);
      __attrMapSync(this);
      if (info) this.__ptAttrNS.delete(q);
      __markDirty(this);
      __styleTouchAttr(this, q, old, null);
      __ptOnTouched(this, q);
      __hasNoteAttr(q, old, null);
      __mutation({ type: 'attributes', target: this, attributeName: info ? info[2] : q, attributeNamespace: info ? info[0] : null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    getAttributeNames() { return [...this.__ptAttrs.keys()]; }
    getAttributeNode(n) {
      __needArgs(arguments.length, 1, 'getAttributeNode', 'Element');
      const name = __attrName(this, n);
      return this.__ptAttrs.has(name) ? __attrNode(this, name) : null;
    }
    get attributes() { return __namedNodeMap(this); }

    get id() { return __ptGetA(this, 'id') || ''; }
    set id(v) { __ptSetA(this, 'id', v); }
    get className() { return __ptGetA(this, 'class') || ''; }
    set className(v) { __ptSetA(this, 'class', v); }
    get classList() { return __tokenList(this); }
    get dataset() { return makeDataset(this); }

    // URL-valued attributes reflect as *absolute* URLs, exactly as in a browser.
    // Not cosmetic: Cloudflare's Turnstile finds its own `<script>` by comparing
    // `script.src` against its api.js URL, and while this returned `''` the
    // widget refused to initialise ("Could not find Turnstile valid script tag").
    get src() { return this.__ptUrlAttr('src'); }
    set src(v) {
      if (this.__ptLocal === 'script') v = __pt_ttSink('TrustedScriptURL', 'HTMLScriptElement src', v, "Failed to set the 'src' property on 'HTMLScriptElement'");
      __csp.ttSkip = true;
      try { __ptSetA(this, 'src', v); } finally { __csp.ttSkip = false; }
      // An image hits the network on assignment alone, no document needed
      // (`new Image().src = …` is a common way to send a GET). The browser
      // makes the request, so it bypasses the page's `fetch`; then `load` or
      // `error` fires.
      if (this.__ptLocal === 'img') { this.__ptLoadImage(true); return; }
      if (!this.isConnected) return;
      // The src can arrive after the element is in the document, in either order:
      // `el.src = …; head.appendChild(el)` or `head.appendChild(el); el.src = …`.
      if (this.__ptConnectFrame) this.__ptConnectFrame();
      if (this.__ptRunScript) this.__ptRunScript();
    }

    // `later`: the address came from script. Chrome then shows it in
    // currentSrc from the next task on; an image from markup has it at once.
    __ptLoadImage(later) {
      const raw = __imgSource(this);
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptImgAt === url) return;                 // same URL: do not load twice
      // A new address ends the old decode: Chrome rejects what waited on it.
      if (this.__ptDecodeWait) __imgDecodeSettle(this, false);
      if (__imageSkipped(url)) { __imgCurrent(this, url, later); return; }
      if (__lazyDeferred(this)) return;
      __imgCurrent(this, url, later);
      Object.defineProperty(this, '__ptImgAt', { value: url, configurable: true, enumerable: false });
      Object.defineProperty(this, '__ptImgDone', { value: false, writable: true, configurable: true, enumerable: false });
      if (__s_toLowerCase(String(__ptGetA(this, 'loading') || '')) !== 'lazy') this.__ptHoldLoad();
      if (__s_slice(url, 0, 5) === 'data:' || __s_slice(url, 0, 5) === 'blob:') {
        this.__ptImgDone = true;
        // Not an image (`data:,x`, a text blob): Chrome fires `error`.
        let isImage = true;
        try {
          if (__s_slice(url, 0, 5) === 'data:') {
            const comma = __s_indexOf(url, ',');
            const meta = comma < 0 ? '' : __s_toLowerCase(__s_slice(url, 5, comma));
            const mime = __s_split(meta, ';')[0];
            if (mime && __s_slice(mime, 0, 6) !== 'image/') isImage = false;
            if (!mime) isImage = false;
            if (isImage && mime !== 'image/svg+xml') {
              const payload = comma < 0 ? '' : __s_slice(url, comma + 1);
              const head = /;base64/.test(meta) ? globalThis.atob(__s_slice(payload, 0, 16)) : decodeURIComponent(__s_slice(payload, 0, 24));
              isImage = /^(\x89PNG|GIF8|\xff\xd8|RIFF|BM|\x00\x00\x01\x00|<svg|<\?xml)/.test(head);
            }
          } else if (globalThis.__pt_blobs) {
            const b = __pt_blobs.get(url);
            if (b && !/^image\//.test(String(b.type || ''))) isImage = false;
          }
        } catch (e) {}
        // The decode result is a task after already queued messages, as in
        // Chrome (the decoder answers from another thread).
        __ptLater(() => this.__ptFireLoad(isImage), 0);
        return;
      }
      if (typeof globalThis.__pt_subresource !== 'function') return;
      // In the document an image starts Medium; one made by script, Low. With
      // `crossorigin` it is a CORS load: an answer that does not allow this
      // origin is an `error`.
      const co = __ptGetA(this, 'crossorigin');
      const corsCreds = co === null ? null : (__s_toLowerCase(__s_trim(co)) === 'use-credentials' ? 'include' : 'same-origin');
      __pt_subresource(url, corsCreds ? (this.isConnected ? 'image-cors' : 'image-cors-low') : (this.isConnected ? 'image' : 'image-low'), null, corsCreds).then(
        () => { this.__ptImgDone = true; this.__ptFireLoad(!(globalThis.__pt_imageIsBad && __pt_imageIsBad(url))); },
        () => { this.__ptImgDone = true; this.__ptFireLoad(false); },
      );
    }

    __ptFireLoad(ok) {
      const type = ok ? 'load' : 'error';
      // dispatchEvent alone is enough: it calls both `onload` and listeners
      // (calling the handler directly too fired it twice). The engine sends
      // the event, so `isTrusted` is true; an untrusted frame or image load is
      // a tell.
      try { this.dispatchEvent && this.dispatchEvent(__ptTrust(new Event(type))); } catch (e) {}
      if (this.__ptLocal === 'img') {
        Object.defineProperty(this, '__ptImgOk', { value: !!ok, writable: true, configurable: true, enumerable: false });
        __imgDecodeSettle(this, !!ok);
      }
      this.__ptReleaseLoad();
    }
    // The element's load delays the document's until its own event has fired.
    __ptHoldLoad() {
      if (this.__ptLoadRel) return;
      const what = this.localName + ' ' + (__ptGetA(this, 'src') || __ptGetA(this, 'href') || '');
      Object.defineProperty(this, '__ptLoadRel', { value: __holdLoad(what), writable: true, configurable: true, enumerable: false });
    }
    __ptReleaseLoad() {
      const rel = this.__ptLoadRel;
      if (rel) { this.__ptLoadRel = null; rel(); }
    }
    // `script.text` is the same text as textContent, and assigning it runs the
    // script: `s.text = <source>; head.appendChild(s)` is how the challenge
    // declares its top-level functions.
    get text() {
      const t = this.tagName;
      if (t === 'SCRIPT' || t === 'TITLE' || t === 'OPTION' || t === 'A') return this.textContent || '';
      return __ptGetA(this, 'text');
    }
    set text(v) {
      if (this.__ptLocal === 'script') v = __pt_ttSink('TrustedScript', 'HTMLScriptElement text', v, "Failed to set the 'text' property on 'HTMLScriptElement'");
      __csp.ttSkip = true;
      try { this.textContent = String(v); } finally { __csp.ttSkip = false; }
      if (this.__ptLocal === 'script' && this.isConnected && this.__ptRunScript) this.__ptRunScript();
    }
    // `srcdoc` is a document written in the attribute: no URL, reflected as is.
    // Assigning it after insertion means a new document in this window, like a
    // navigation.
    get srcdoc() { const v = __ptGetA(this, 'srcdoc'); return v === null ? '' : v; }
    set srcdoc(v) {
      if (this.__ptLocal === 'iframe') v = __pt_ttSink('TrustedHTML', 'HTMLIFrameElement srcdoc', v, "Failed to set the 'srcdoc' property on 'HTMLIFrameElement'");
      __csp.ttSkip = true;
      try { __ptSetA(this, 'srcdoc', v); } finally { __csp.ttSkip = false; }
      if (this.__ptLocal !== 'iframe') return;
      try {
        const w = this.__ptRealm || (this.isConnected ? this.__ptRealmWindow() : null);
        if (w && typeof w.__pt_writeDocument === 'function') w.__pt_writeDocument(String(v));
      } catch (e) {}
    }
    get sandbox() { return __ptGetA(this, 'sandbox') || ''; }
    set sandbox(v) { __ptSetA(this, 'sandbox', v); }
    get allow() { return __ptGetA(this, 'allow') || ''; }
    set allow(v) { __ptSetA(this, 'allow', v); }
    get href() { return this.__ptUrlAttr('href'); }
    set href(v) {
      __ptSetA(this, 'href', v);
      // `<link>` is a request too: preload, stylesheet, icon.
      if (this.__ptLocal === 'link' && this.__ptLoadLink) this.__ptLoadLink();
    }

    __ptLoadLink() {
      const rel = __s_toLowerCase(String(__ptGetA(this, 'rel') || ''));
      // Kinds the document loads. Icons are the browser's (it asks for them
      // after load, see the engine), `apple-touch-icon` is not fetched by
      // desktop Chrome, and the rest (`alternate`, `canonical`,
      // `dns-prefetch`) make no request.
      if (!/^(stylesheet|preload|prefetch|modulepreload|manifest|prerender)$/.test(rel)) return;
      const raw = __ptGetA(this, 'href');
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptLinkAt === url) return;
      Object.defineProperty(this, '__ptLinkAt', { value: url, configurable: true, enumerable: false });
      // `prerender` is Chrome's no-state prefetch: the page's document asked
      // for as a navigation would, same-origin only (measured), nothing kept.
      if (rel === 'prerender') {
        let same = false;
        try { same = new URL(url).origin === location.origin; } catch (e) {}
        if (same && typeof globalThis.__pt_subresource === 'function') __pt_subresource(url, 'prerender').catch(() => {});
        return;
      }
      // A stylesheet in a data URL is still a stylesheet, parsed without the
      // network.
      if (__s_slice(url, 0, 5) === 'data:') {
        if (rel === 'stylesheet') {
          try {
            const comma = __s_indexOf(url, ',');
            const head = __s_slice(url, 5, comma);
            const raw = __s_slice(url, comma + 1);
            const text = /;base64$/i.test(head) ? atob(raw) : decodeURIComponent(raw);
            Object.defineProperty(this, '__ptSheetText',
              { value: text, writable: true, enumerable: false, configurable: true });
            __markDirty();
          } catch (e) {}
        }
        if (this.__ptFireLoad) __pt_soon(() => this.__ptFireLoad(true));
        return;
      }
      if (__s_slice(url, 0, 5) === 'blob:' || typeof globalThis.__pt_subresource !== 'function') return;
      // The destination on the wire; resource timing names all of them `link`.
      const as = __s_toLowerCase(String(__ptGetA(this, 'as') || ''));
      const kind = rel === 'stylesheet' ? 'stylesheet'
        : rel === 'modulepreload' ? 'link-module'
        : rel === 'prefetch' ? 'prefetch'
        : rel === 'manifest' ? 'manifest'
        : as === 'script' ? 'link-script' : as === 'style' ? 'link-style' : as === 'font' ? 'link-font'
        : as === 'image' ? 'link-image' : as === 'fetch' ? 'link-fetch' : 'link';
      if (kind === 'link-image' && __imageSkipped(url)) return;
      // A markup stylesheet blocks the scripts after it until parsed; otherwise
      // they measure an unstyled page (Turnstile's api.js reported the
      // wrapper at the right edge instead of centred).
      // A sheet for another medium (`media="print"`, the async-CSS trick) blocks nothing.
      const media = __ptGetA(this, 'media');
      const blocking = rel === 'stylesheet' && !document.__ptCurScript
        && this.ownerDocument === document && document.__ptReady === 'loading'
        && (!media || __mediaApplies(media));
      if (blocking) {
        globalThis.__ptBlockingSheets = (globalThis.__ptBlockingSheets | 0) + 1;
        (globalThis.__ptBlockingSheetUrls || (globalThis.__ptBlockingSheetUrls = new Set())).add(url);
      }
      let released = false;
      const dclRel = blocking ? __holdDcl(this) : null;
      const release = () => {
        if (!blocking || released) return;
        released = true;
        dclRel();
        globalThis.__ptBlockingSheets = Math.max(0, (globalThis.__ptBlockingSheets | 0) - 1);
        try { globalThis.__ptBlockingSheetUrls.delete(url); } catch (e) {}
      };
      if (rel === 'stylesheet') this.__ptHoldLoad();
      __pt_subresource(url, kind).then(
        (res) => {
          // An external stylesheet is rules, not just a request: they go into
          // `document.styleSheets[i].cssRules` and the cascade.
          const wanted = rel === 'stylesheet';
          const take = (text) => {
            let imports = null;
            if (wanted && typeof text === 'string') {
              Object.defineProperty(this, '__ptSheetText',
                { value: text, writable: true, enumerable: false, configurable: true });
              __markDirty();
              // The sheet is parsed now and its imports start; its `load`
              // waits for them, as Chrome's does.
              try { imports = __cssom.get(__sheetFor(this)).imports; } catch (e) {}
            }
            const finish = () => { release(); if (this.__ptFireLoad) this.__ptFireLoad(true); };
            if (imports) imports.then(finish, finish); else finish();
          };
          // An answer that is not ok (404, 500) is no stylesheet: no rules,
          // and `error` (Chrome's 404 page parsed as CSS gave rules).
          if (wanted && res && res.ok === false) {
            release();
            if (this.__ptFireLoad) this.__ptFireLoad(false);
          } else if (wanted && res && typeof res.text === 'function') {
            res.text().then(take, () => take(null));
          } else take(null);
          // A manifest names an icon for installability: Chrome fetches the
          // largest of at least 144px it can use, as an icon request.
          if (rel === 'manifest' && res && typeof res.text === 'function' && this.ownerDocument === document) {
            res.text().then((text) => {
              let m = null; try { m = __ptJSON.parse(text); } catch (e) { return; }
              const icons = m && Array.isArray(m.icons) ? m.icons : [];
              let best = null, bestSize = 0;
              for (const ic of icons) {
                if (!ic || typeof ic.src !== 'string') continue;
                const purpose = __s_toLowerCase(String(ic.purpose || 'any'));
                if (!/(^|\s)any(\s|$)/.test(purpose)) continue;
                const type = __s_toLowerCase(String(ic.type || ''));
                if (type && !/^image\/(png|webp|svg\+xml|jpeg|gif|x-icon|vnd\.microsoft\.icon)$/.test(type)) continue;
                let size = 0;
                for (const sz of __s_split(String(ic.sizes || ''), /\s+/)) {
                  const mm = /^(\d+)x(\d+)$/i.exec(sz); if (mm) size = Math.max(size, Math.min(+mm[1], +mm[2]));
                  if (__s_toLowerCase(sz) === 'any') size = Math.max(size, 1e6);
                }
                if (size >= 144 && size > bestSize) { best = ic; bestSize = size; }
              }
              if (!best) return;
              let u = null; try { u = new URL(best.src, url).href; } catch (e) { return; }
              if (/^https?:/.test(u)) __pt_subresource(u, 'icon').catch(() => {});
            }, () => {});
          }
        },
        () => { release(); if (this.__ptFireLoad) this.__ptFireLoad(false); },
      );
    }

    // A link reflects the parts of its URL, and parsing a URL by assigning it to a
    // throwaway `<a>` and reading the pieces back is one of the oldest idioms on
    // the web — Cloudflare's challenge does it, and got `undefined` where it
    // expected a hostname, then died reading a property of that. Only `<a>` and
    // `<area>` have these; anything else reports `undefined`, as in a browser.
    get protocol() { const u = this.__ptLinkURL(); return u && u.protocol; }
    set protocol(v) { this.__ptSetLinkPart('protocol', v); }
    get host() { const u = this.__ptLinkURL(); return u && u.host; }
    set host(v) { this.__ptSetLinkPart('host', v); }
    get hostname() { const u = this.__ptLinkURL(); return u && u.hostname; }
    set hostname(v) { this.__ptSetLinkPart('hostname', v); }
    get port() { const u = this.__ptLinkURL(); return u && u.port; }
    set port(v) { this.__ptSetLinkPart('port', v); }
    get pathname() { const u = this.__ptLinkURL(); return u && u.pathname; }
    set pathname(v) { this.__ptSetLinkPart('pathname', v); }
    get search() { const u = this.__ptLinkURL(); return u && u.search; }
    set search(v) { this.__ptSetLinkPart('search', v); }
    get hash() { const u = this.__ptLinkURL(); return u && u.hash; }
    set hash(v) { this.__ptSetLinkPart('hash', v); }
    get origin() { const u = this.__ptLinkURL(); return u && u.origin; }
    get username() { const u = this.__ptLinkURL(); return u && (u.username || ''); }
    get password() { const u = this.__ptLinkURL(); return u && (u.password || ''); }
    __ptLinkURL() {
      const tag = this.__ptLocal;
      if (tag !== 'a' && tag !== 'area') return undefined;
      const raw = __ptGetA(this, 'href');
      if (raw == null) return undefined;
      const base = (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base); } catch (e) { return undefined; }
    }
    __ptSetLinkPart(part, v) {
      const u = this.__ptLinkURL();
      if (!u) return;
      try { u[part] = v; __ptSetA(this, 'href', u.href); } catch (e) {}
    }
    get action() { return this.__ptUrlAttr('action') || ((__formGet(this, 'ownerDocument') || document).URL || ''); }
    set action(v) { __ptSetA(this, 'action', v); }
    // Form: `method`/`enctype` are enumerated, `elements` are its fields,
    // `submit()` goes to the action URL without an event, `requestSubmit()`
    // after a submit event. The Cloudflare interstitial submits a form.
    get method() { const m = __s_toLowerCase(String(__ptGetA(this, 'method') || '')); return m === 'post' ? 'post' : m === 'dialog' ? 'dialog' : 'get'; }
    set method(v) { __ptSetA(this, 'method', v); }
    get enctype() { const e = __s_toLowerCase(String(__ptGetA(this, 'enctype') || '')); return e === 'multipart/form-data' || e === 'text/plain' ? e : 'application/x-www-form-urlencoded'; }
    set enctype(v) { __ptSetA(this, 'enctype', v); }
    get elements() {
      const out = [];
      __walkTree(this, (n) => { if (n && n.__ptType === ELEMENT_NODE && /^(input|select|textarea|button|fieldset|object|output)$/.test(n.__ptLocal || '') && !(n.__ptLocal === 'input' && __inputType(n) === 'image')) out.push(n); });
      return __collection(out);
    }
    get length() { return this.__ptLocal === 'form' ? this.elements.length : undefined; }
    // The form's entry list as Chrome builds it for FormData and submission:
    // a control under a disabled fieldset (outside its first legend) is
    // disabled, a file input without files sends an empty File, `dirname`
    // adds the text direction, a hidden `_charset_` sends UTF-8. Then
    // `formdata` fires with the list in `fd`, and what listeners add is kept.
    __ptFormData(submitter, fd) {
      const pairs = [];
      for (const el of __formGet(this, 'elements')) {
        const tag = el.__ptLocal;
        if (tag === 'fieldset' || tag === 'object' || tag === 'output' || __isDisabled(el)) continue;
        let skip = false;
        for (let p = el.__ptParent; p && !skip; p = p.__ptParent) if (p.__ptLocal === 'datalist') skip = true;
        if (skip) continue;
        const type = tag === 'input' ? __inputType(el) : tag === 'button' ? __s_toLowerCase(String(__ptGetA(el, 'type') || 'submit')) : '';
        const name = __ptGetA(el, 'name');
        if (tag === 'button' || (tag === 'input' && (type === 'submit' || type === 'button' || type === 'reset' || type === 'image'))) {
          if (el !== submitter) continue;
          if (type === 'image') { const pre = name ? name + '.' : ''; pairs.push([pre + 'x', '0'], [pre + 'y', '0']); continue; }
        }
        if (!name) continue;
        if (tag === 'select') {
          for (const o of el.options || []) {
            const g = o.__ptParent;
            if (o.selected && !__ptHasA(o, 'disabled') && !(g && g.__ptLocal === 'optgroup' && __ptHasA(g, 'disabled'))) pairs.push([name, o.value]);
          }
          continue;
        }
        if (tag === 'input') {
          if ((type === 'checkbox' || type === 'radio') && !el.checked) continue;
          if (type === 'file') {
            const files = el.files;
            if (files && files.length) { for (let i = 0; i < files.length; i++) pairs.push([name, files[i]]); }
            else if (typeof File === 'function') pairs.push([name, new File([], '', { type: 'application/octet-stream' })]);
            continue;
          }
          if (type === 'hidden' && __s_toLowerCase(name) === '_charset_') { pairs.push([name, 'UTF-8']); continue; }
        }
        pairs.push([name, String(el.value == null ? '' : el.value)]);
        const dirname = __ptGetA(el, 'dirname');
        if (dirname && (tag === 'textarea' || /^(text|search|tel|url|email|password|submit|reset|button|hidden)$/.test(type))) {
          let dir = 'ltr';
          for (let p = el; p && p.__ptType === ELEMENT_NODE; p = p.__ptParent) {
            const d = __s_toLowerCase(String(__ptGetA(p, 'dir') || ''));
            if (d === 'rtl' || d === 'ltr') { dir = d; break; }
          }
          pairs.push([dirname, dir]);
        }
      }
      const data = fd || (typeof FormData === 'function' ? new FormData() : null);
      if (!data || !globalThis.FormDataEvent) return pairs;
      data.__ptD = pairs;
      __formGet(this, 'dispatchEvent').call(this, __ptTrust(new FormDataEvent('formdata', { bubbles: true, formData: data })));
      return data.__ptD;
    }
    // `new FormData(form, submitter)`: the submitter must be a submit button
    // of this form.
    __ptEntryList(submitter, fd) {
      if (submitter !== undefined && submitter !== null) {
        if (submitter.__ptType !== ELEMENT_NODE) throw __pt_mkErr(TypeError, "Failed to construct 'FormData': parameter 2 is not of type 'HTMLElement'.");
        const tag = submitter.__ptLocal, type = tag === 'input' ? __inputType(submitter) : __s_toLowerCase(String(__ptGetA(submitter, 'type') || 'submit'));
        if (!((tag === 'button' && type === 'submit') || (tag === 'input' && (type === 'submit' || type === 'image')))) throw __pt_mkErr(TypeError, "Failed to construct 'FormData': The specified element is not a submit button.");
        if (submitter.form !== this) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to construct 'FormData': The specified element is not owned by this form element.", 'NotFoundError');
      }
      return this.__ptFormData(submitter || null, fd);
    }
    __ptSubmit(submitter) {
      if (this.__ptLocal !== 'form' || !__formGet(this, 'isConnected')) return;
      const method = __formGet(this, 'method');
      if (method === 'dialog') return;
      let action = __formGet(this, 'action');
      try { if (submitter && __ptHasA(submitter, 'formaction')) action = new URL(__ptGetA(submitter, 'formaction'), (this.__ptDoc || document).baseURI).href; } catch (e) {}
      const pairs = this.__ptFormData(submitter).map(([k, v]) => [k, typeof v === 'string' ? v : String(v && v.name || '')]);
      const enc = (s) => __s_replace(__s_replace(encodeURIComponent(s), /%20/g, '+'), /[!'()~]/g, (c) => '%' + __s_toUpperCase(__s_charCodeAt(c, 0).toString(16)));
      const query = pairs.map(([k, v]) => enc(k) + '=' + enc(v)).join('&');
      if (typeof globalThis.__pt_navSubmit !== 'function') return;
      let getUrl = null;
      if (method !== 'post') {
        try { const u = new URL(action); u.search = query ? '?' + query : ''; u.hash = ''; getUrl = u.href; } catch (e) { return; }
      }
      // Where the response goes: `formtarget`, `target`, then `<base target>`.
      // Only this window (or the top, which it is for the page) navigates.
      let target = submitter && __ptHasA(submitter, 'formtarget') ? __ptGetA(submitter, 'formtarget') : __ptGetA(this, 'target');
      if (!target) {
        const base = __docTags(__formGet(this, 'ownerDocument') || document, 'base').find((b) => __ptHasA(b, 'target'));
        target = base ? __ptGetA(base, 'target') : '';
      }
      const kw = __s_toLowerCase(target || '');
      if (kw && kw !== '_self' && kw !== '_top' && kw !== '_parent') {
        // A frame of that name loads the response; the page stays. A new window
        // (`_blank`, an unknown name) without a user's click is a blocked popup.
        const frame = kw === '_blank' ? null : __docTags(__formGet(this, 'ownerDocument') || document, 'iframe').find((f) => __ptGetA(f, 'name') === target);
        if (!frame) return;
        if (method === 'post') frame.__ptNavigate(action, 'POST', query, 'application/x-www-form-urlencoded');
        else frame.__ptNavigate(getUrl, 'GET', null, '');
        return;
      }
      if (method === 'post') { __pt_navSubmit(action, 'POST', query, 'application/x-www-form-urlencoded'); return; }
      __pt_navSubmit(getUrl, 'GET', '', '');
    }
    submit() { this.__ptSubmit(null); }
    requestSubmit(submitter) {
      if (this.__ptLocal !== 'form') return;
      if (submitter !== undefined && submitter !== null && !(submitter && submitter.__ptType === ELEMENT_NODE)) throw __pt_mkErr(TypeError, "Failed to execute 'requestSubmit' on 'HTMLFormElement': parameter 1 is not of type 'HTMLElement'.");
      // The browser sends `submit`, so it is trusted even when a script asked
      // for submission (`isTrusted` true in Chrome).
      const ev = __ptTrust(new (globalThis.SubmitEvent || Event)('submit', { bubbles: true, cancelable: true, submitter: submitter || null }));
      if (!__formGet(this, 'dispatchEvent').call(this, ev)) return;
      this.__ptSubmit(submitter || null);
    }
    __ptUrlAttr(n) {
      const raw = __ptGetA(this, n);
      if (raw == null) return '';
      // An empty frame takes its base URL from the creator: `s.src = 'x.js'`
      // resolves against the parent, not `about://x.js`.
      const base = (__formGet(this, 'ownerDocument') || document).baseURI || (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base).href; } catch (e) { return raw; }
    }

    // Plain string/boolean reflections a page can read back off an element.
    get rel() { return __ptGetA(this, 'rel') || ''; }
    set rel(v) { __ptSetA(this, 'rel', v); }
    get target() { return __ptGetA(this, 'target') || ''; }
    set target(v) { __ptSetA(this, 'target', v); }
    get alt() { return __ptGetA(this, 'alt') || ''; }
    set alt(v) { __ptSetA(this, 'alt', v); }
    get integrity() { return __ptGetA(this, 'integrity') || ''; }
    set integrity(v) { __ptSetA(this, 'integrity', v); }
    // HTMLElement reflections: `dir` (enumerated), `lang`, `title`,
    // `accessKey`. The Cloudflare interstitial sets
    // `document.documentElement.dir`, and the DOM snapshot sees it.
    get dir() { const v = __s_toLowerCase(String(__ptGetA(this, 'dir') || '')); return v === 'ltr' || v === 'rtl' || v === 'auto' ? v : ''; }
    set dir(v) { __ptSetA(this, 'dir', v); }
    get lang() { return __ptGetA(this, 'lang') || ''; }
    set lang(v) { __ptSetA(this, 'lang', v); }
    get title() { return __ptGetA(this, 'title') || ''; }
    set title(v) { __ptSetA(this, 'title', v); }
    get accessKey() { return __ptGetA(this, 'accesskey') || ''; }
    set accessKey(v) { __ptSetA(this, 'accesskey', v); }
    // Chrome hides a header-CSP nonce: the attribute reads empty, the value
    // lives only in the `nonce` property.
    get nonce() { return this.__ptNonce !== undefined ? this.__ptNonce : (__ptGetA(this, 'nonce') || ''); }
    set nonce(v) { this.__ptNonce = String(v); }
    __ptHideNonce() {
      if (!__csp.headerDelivered) return;
      const v = __ptGetA(this, 'nonce');
      if (v === null || v === '') return;
      this.__ptNonce = v;
      this.__ptAttrs.set('nonce', '');
    }
    get crossOrigin() { return __ptHasA(this, 'crossorigin') ? (__ptGetA(this, 'crossorigin') || 'anonymous') : null; }
    set crossOrigin(v) { __ptSetA(this, 'crossorigin', v); }
    get referrerPolicy() { return __ptGetA(this, 'referrerpolicy') || ''; }
    set referrerPolicy(v) { __ptSetA(this, 'referrerpolicy', v); }
    get async() { return __ptHasA(this, 'async'); }
    set async(v) { v ? __ptSetA(this, 'async', '') : __ptDelA(this, 'async'); }
    get defer() { return __ptHasA(this, 'defer'); }
    set defer(v) { v ? __ptSetA(this, 'defer', '') : __ptDelA(this, 'defer'); }
    // `'noModule' in script` is how pages detect module support; without it
    // Vite builds serve their legacy half.
    get noModule() { return __ptHasA(this, 'nomodule'); }
    set noModule(v) { v ? __ptSetA(this, 'nomodule', '') : __ptDelA(this, 'nomodule'); }
    get hreflang() { return __ptGetA(this, 'hreflang') || ''; }
    set hreflang(v) { __ptSetA(this, 'hreflang', v); }
    get content() { return __ptGetA(this, 'content') || ''; }
    set content(v) { __ptSetA(this, 'content', v); }
    get httpEquiv() { return __ptGetA(this, 'http-equiv') || ''; }
    set httpEquiv(v) { __ptSetA(this, 'http-equiv', v); }
    get loading() { return __ptGetA(this, 'loading') || 'auto'; }
    set loading(v) { __ptSetA(this, 'loading', v); }
    get maxLength() { const v = parseInt(__ptGetA(this, 'maxlength'), 10); return Number.isFinite(v) ? v : -1; }
    set maxLength(v) { __ptSetA(this, 'maxlength', String(v)); }
    get minLength() { const v = parseInt(__ptGetA(this, 'minlength'), 10); return Number.isFinite(v) ? v : -1; }
    set minLength(v) { __ptSetA(this, 'minlength', String(v)); }
    get defaultValue() { return __ptGetA(this, 'value') || ''; }
    set defaultValue(v) { __ptSetA(this, 'value', v); }
    // Fields taking part in form validation: `true` on an enabled button or
    // field; pages read it.
    get willValidate() {
      const t = __s_toLowerCase(String(__ptGetA(this, 'type') || ''));
      if (this.__ptLocal !== 'input' && this.__ptLocal !== 'textarea' && this.__ptLocal !== 'select') return undefined;
      return !__ptHasA(this, 'disabled') && !__ptHasA(this, 'readonly')
             && t !== 'hidden' && t !== 'button' && t !== 'reset';
    }
    // A token list, not a string: `rel`, `sandbox`, `relList` are
    // `DOMTokenList`, and pages read `length` and iterate.
    get relList() { return makeClassList(this, 'rel'); }
    get sandbox() { return makeClassList(this, 'sandbox'); }
    get htmlFor() { return __ptGetA(this, 'for') || ''; }
    set htmlFor(v) { __ptSetA(this, 'for', v); }

    get children() { return __collection(this.__ptKids.filter(n => n.__ptType === ELEMENT_NODE)); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() { let n = this.nextSibling; while (n && n.__ptType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.__ptType !== ELEMENT_NODE) n = n.previousSibling; return n; }

    append(...ns) {
      __needNoneAncestor(this, ns, 'append', 'Element');
      for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    prepend(...ns) {
      __needNoneAncestor(this, ns, 'prepend', 'Element');
      for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild);
    }
    replaceChildren(...ns) {
      __needNoneAncestor(this, ns, 'replaceChildren', 'Element');
      const nodes = ns.map((n) => (typeof n === 'string' ? new Text(n) : n));
      for (const n of nodes) if (n && n.__ptParent === this) this.removeChild(n);
      __ptDropKids(this);
      for (const n of nodes) this.appendChild(n);
    }

    // Queries (scoped to this subtree)
    // Element has no getElementById; only document and fragment do.
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    getElementsByClassName(c) { return __collection(__byClass(this, c)); }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return queryFirst(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'));
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    closest(sel) {
      __needArgs(arguments.length, 1, 'closest', 'Element');
      __checkSelector(sel, 'closest', 'Element');
      for (let e = this; e; e = e.__ptParent) if (e.__ptType === ELEMENT_NODE && matchesSelector(e, sel, this)) return e;
      return null;
    }
    matches(sel) {
      __needArgs(arguments.length, 1, 'matches', 'Element');
      return matchesSelector(this, __checkSelector(sel, 'matches', 'Element'), this);
    }

    // Serialization
    // --- iframes ----------------------------------------------------------
    // An iframe is a *browsing context*, not a tag: a widget creates one, then
    // polls `contentWindow` and refuses to proceed until it answers. Connecting
    // one queues a request the engine turns into a real child context; until it
    // is ready `contentWindow` is null, exactly as in a browser.
    get contentWindow() {
      // Present the moment the frame is connected, not once its document has
      // loaded — that is how a browser behaves (the window exists, `about:blank`
      // at first, and navigates afterwards). Waiting for the load was enough to
      // make widgets that poll this synchronously give up and start over.
      const st = __frames.get(this.__ptFrameId);
      if (st) return st.win;
      return this.__ptRealmWindow();
    }
    get contentDocument() {
      const st = __frames.get(this.__ptFrameId);
      // A cross-origin frame exposes no document at all — that is the rule, not a
      // limitation, and a networked frame's document lives in another context we
      // cannot hand back. A blank same-origin frame is a different matter: it has
      // a real realm of its own (below), and its document comes with it.
      if (st) return st.ready && st.sameOrigin ? st.doc || null : null;
      const w = this.__ptRealmWindow();
      return w ? w.document || null : null;
    }

    // A same-origin `<iframe>` with no `src` is a *window*, immediately — with its
    // own untouched natives. Code reaches into one synchronously
    // (`contentWindow.eval`, `contentWindow.Function`) precisely because a fresh
    // realm is where a patched function can be compared against a clean one; an
    // anti-bot VM that finds `null` there stops dead. The realm is a second V8
    // context in this same isolate, so its global is an ordinary object we can
    // hand back and the page can use directly.
    __ptRealmWindow() {
      if (this.__ptLocal !== 'iframe' || !this.isConnected) return null;
      if (this.__ptRealm) return this.__ptRealm;
      const src = __ptGetA(this, 'src');
      if (src && src !== 'about:blank') return null;
      if (typeof globalThis.__pt_makeRealm !== 'function') return null;
      const w = globalThis.__pt_makeRealm();
      if (!w) return null;
      // The parent's queue drives the realm's timers; the realm has no driver.
      try { if (typeof globalThis.__pt_addChildRealm === 'function') __pt_addChildRealm(w); } catch (e) {}
      // Implementation traces (canvas, WebGPU) from a realm go to the parent's
      // console, which the engine reads. Trace flag only.
      if (globalThis.__pt_canvasTrace || globalThis.__pt_gpuTrace || globalThis.__pt_encTrace) {
        try { Object.defineProperty(w, '__pt_parentConsole', { value: globalThis.__pt_parentConsole || console, configurable: true }); } catch (e) {}
      }
      // It is a child: it sees us as its parent, and knows the element it is in.
      for (const [k, v] of [['parent', globalThis], ['top', globalThis.top || globalThis],
        ['frameElement', this], ['self', w], ['window', w]]) {
        try { Object.defineProperty(w, k, { value: v, configurable: true }); } catch (e) {}
      }
      // The sandbox inherits the frame's cross-site status: permissions and
      // Notification answer as in the frame.
      try { Object.defineProperty(w, '__pt_crossSite', { value: !!globalThis.__pt_crossSite, configurable: true }); } catch (e) {}
      // And the security policy: about:blank and about:srcdoc inherit the
      // creator's CSP (nonce, 'unsafe-eval', Trusted Types).
      try { if (typeof w.__pt_applyCsp === 'function') for (const p of __csp.policies) w.__pt_applyCsp(p.raw, 'inherited'); } catch (e) {}
      // In Chrome an empty frame's window inside a cross-site frame has
      // screenX/screenY 0, and outerWidth/outerHeight equal to the browser
      // window size (checked against a probe-free reference).
      if (globalThis.__pt_crossSite) {
        const outer = { outerWidth: globalThis.outerWidth | 0, outerHeight: globalThis.outerHeight | 0 };
        for (const k of ['outerWidth', 'outerHeight', 'screenX', 'screenY', 'screenLeft', 'screenTop']) {
          try { const d = Object.getOwnPropertyDescriptor(w, k); Object.defineProperty(w, k, { value: k in outer ? outer[k] : 0, writable: true, enumerable: d ? d.enumerable : true, configurable: true }); } catch (e) {}
        }
      }
      // `about:blank` takes its creator's origin: origin and document.domain
      // answer as the creator, the URL stays about:blank.
      try {
        Object.defineProperty(w, '__pt_inheritedOrigin', { value: (globalThis.location && location.origin) || 'null', configurable: true });
        Object.defineProperty(w, '__pt_inheritedBase', { value: (globalThis.document && document.baseURI) || (globalThis.location && location.href) || 'about:blank', configurable: true });
        Object.defineProperty(w, '__pt_inheritedHost', { value: (globalThis.location && location.hostname) || '', configurable: true });
      } catch (e) {}
      Object.defineProperty(this, '__ptRealm', { value: w, configurable: true, enumerable: false });
      try { __realmFrames.add(this); } catch (e) {}
      // A frame's viewport is its own box, not the page's (a 300x150 frame has
      // a 284px-wide body, as in Chrome). Declared size only, no layout:
      // building layout for an empty frame's window cost 7-11 ms per insertion
      // (87 ms the first), and the challenge inserts such frames in a row while
      // timing itself. The exact size arrives with the next layout.
      try {
        // Hidden itself or by any ancestor (through shadow hosts): Chrome
        // gives such a frame's window 0x0.
        let hidden = false;
        for (let p = this; p && p.__ptType === ELEMENT_NODE; p = p.__ptParent && p.__ptParent.__ptType === 11 && p.__ptParent.__ptHost ? p.__ptParent.__ptHost : p.__ptParent) {
          if (String((p.style && p.style.display) || '') === 'none' || __ptHasA(p, 'hidden')) { hidden = true; break; }
        }
        // Chrome does not lay out a boxless (0x0) cross-site frame: its empty
        // frames stay unsized, innerWidth 0.
        if (!hidden && __ptHiddenFrame()) hidden = true;
        // Chrome does not render a cross-site frame of at most 1x1 (Turnstile
        // in invisible mode): no layout inside, freshly inserted empty frames
        // stay 0x0 (probe-free reference, section Mrvi5). Document visibility
        // is unchanged.
        if (!hidden && globalThis.__pt_crossSite && (globalThis.innerWidth | 0) <= 1 && (globalThis.innerHeight | 0) <= 1) hidden = true;
        const [dw, dh] = __ptJSON.parse(__pt_frameBoxOf(this));
        // Trace NOKK_TRACE_SRCDOC=1: the empty frame's surroundings at creation.
        if (globalThis.__pt_srcdocTrace) {
          try {
            const chain = [];
            for (let p = this; p; p = p.__ptParent && p.__ptParent.__ptType === 11 && p.__ptParent.__ptHost ? (chain.push('#shadow'), p.__ptParent.__ptHost) : p.__ptParent) {
              if (p.__ptType !== 1) { chain.push('#' + p.__ptType); break; }
              chain.push(p.localName + (p.id ? '#' + p.id : '') + (p.getAttribute('style') ? '[' + p.getAttribute('style') + ']' : '') + (p.className ? '.' + __s_slice(String(p.className), 0, 30) : ''));
            }
            let cs = ''; try { const c = getComputedStyle(this); cs = [c.display, c.width, c.height, c.visibility, c.position, c.left, c.top].join(','); } catch (e) {}
            (globalThis.__pt_parentConsole || console).error('[realm] ' + __s_slice(String(this.outerHTML), 0, 300) + ' | chain ' + chain.join(' < ') + ' | cs ' + cs + ' | box ' + dw + 'x' + dh + ' | hidden ' + hidden + ' | flat ' + (typeof __pt_inFlatTree === 'function' ? __pt_inFlatTree(this) : '?'));
          } catch (e) {}
        }
        __ptTellFrame(this, hidden ? null : { cw: dw, ch: dh });
      } catch (e) {}
      // An empty frame's referrer and base URL are the creator document's, as
      // in Chrome; set before writing markup, whose scripts read document.referrer.
      try { Object.defineProperty(w, '__pt_creatorURL', { value: (globalThis.location && location.href) || '', configurable: true }); } catch (e) {}
      // An empty window has html/head/body, and pages write into it. `srcdoc`
      // goes the same way.
      try {
        const markup = __ptGetA(this, 'srcdoc');
        // Trace NOKK_TRACE_SRCDOC=1: srcdoc frame markup to the parent console.
        if (globalThis.__pt_srcdocTrace && markup != null) { try { (globalThis.__pt_parentConsole || console).error('[srcdoc] ' + __s_slice(String(markup), 0, 4000)); } catch (e) {} }
        // A srcdoc frame's URL is about:srcdoc.
        if (markup != null && typeof w.__pt_setLocation === 'function') w.__pt_setLocation({ href: 'about:srcdoc', protocol: 'about:', pathname: 'srcdoc', host: '', hostname: '', port: '', search: '', hash: '' });
        if (typeof w.__pt_writeDocument === 'function') w.__pt_writeDocument(markup || '');
      } catch (e) {}
      return w;
    }
    // A `<script>` that has just entered the document runs — once. The "already
    // started" flag is the spec's, and it is what keeps a parser-built script
    // (the engine runs those itself, in document order) from running twice, and a
    // re-inserted element from running again.
    __ptRunScript() {
      if (this.__ptRan || this.__ptLocal !== 'script') return;
      const type = __s_trim(__s_toLowerCase(String(__ptGetA(this, 'type') || '')));
      // Anything that is not classic JS — a JSON island, a template, an importmap
      // — is data the page reads itself, not code to run.
      if (type && !/^(text|application)\/(java|ecma)script$|^module$/.test(type)) return;
      // `nomodule` is for browsers without modules; we have modules, so skip.
      if (type !== 'module' && __ptHasA(this, 'nomodule')) return;
      const src = __ptGetA(this, 'src');
      // Nothing to run *yet*: an element appended empty starts when its `src`
      // arrives, so the flag must not be set until there is something to do.
      if (!src && !this.textContent) return;
      Object.defineProperty(this, '__ptRan', { value: true, configurable: true, enumerable: false });
      // CSP: inline without nonce and foreign URLs do not run.
      // 'strict-dynamic' trusts what a script inserts, not what a parser does.
      if (globalThis.__pt_cspActive && __pt_cspActive()) {
        const dyn = !this.__ptParserIns;
        if (!src && __pt_cspBlocksInline(this, dyn)) return;
        if (src && __pt_cspBlocksScriptUrl(this, String(src), dyn)) {
          // A refused fetch is a network error: `error` on a later task, as
          // Chrome fires it (script loaders wait for load or error).
          this.__ptHoldLoad();
          __ptLater(() => this.__ptFireLoad(false), 0);
          return;
        }
      }
      // A module has its own parsing, `import` and scope; the engine runs it,
      // both external and inline.
      const isModule = type === 'module';
      if (src) {
        const id = __nextScriptId++;
        this.__ptHoldLoad();
        __scriptEls.set(id, this);
        // Resolved here, against the document's base URL (`<base href>`).
        let abs = String(src);
        try { abs = new URL(abs, (this.ownerDocument || document).baseURI).href; } catch (e) {}
        __scriptOps.push({ op: 'load', id, src: abs, module: isModule });
        return;
      }
      const code = this.textContent;
      if (!code) return;
      if (isModule) {
        const id = __nextScriptId++;
        __scriptEls.set(id, this);
        __scriptOps.push({ op: 'load', id, src: '', code: String(code), module: true });
        return;
      }
      // A real script, not `eval`: V8 tags every stack frame with
      // "eval at <caller name>", leaking our internal name into any page's
      // stack trace. The fallback stays for builds without this builtin.
      try {
        // URL of the document: an inline script has none of its own and Chrome
        // names its stack frames with the page URL. An empty name would show as
        // `<anonymous>` in `Error().stack`.
        let where_ = '';
        try { where_ = String((this.ownerDocument && this.ownerDocument.URL) || location.href || ''); } catch (e) {}
        const line = typeof __pt_markupLine === 'function' ? __pt_markupLine(String(code)) : 0;
        if (typeof __pt_evalScript === 'function') __pt_evalScript(String(code), where_, line > 0 ? line - 1 : 0);
        else (0, eval)(code);
      } catch (e) { __pt_reportError(e, 'inline script'); }
    }

    __ptConnectFrame() {
      if (this.__ptFrameId || this.__ptLocal !== 'iframe') return;
      const src = __ptGetA(this, 'src');
      // `about:blank` is not fetched: it is the same initial empty document as
      // a frame without src, and its realm is ready at once. Pages do
      // `f.src='about:blank'; body.appendChild(f); f.contentWindow.eval(…)` to
      // get pristine builtins, and challenges rely on it.
      const blank = !src || /^about:blank(\?|#|$)/.test(__s_trim(src));
      if (blank) {
        // A `srcdoc` frame loads as soon as it is in the document, without
        // waiting for `contentWindow` to be read.
        if (src || __ptGetA(this, 'srcdoc') !== null) { try { this.__ptRealmWindow(); } catch (e) {} }
        // An empty document loads too: Chrome fires `load`, and pages wait for
        // `iframe.onload`.
        if (!this.__ptBlankLoaded) {
          Object.defineProperty(this, '__ptBlankLoaded', { value: true, configurable: true, enumerable: false });
          // In Chrome an empty frame is already loaded on insertion: `load`
          // fires right away, in the same task. The challenge inserts a
          // sandbox, waits for load, grabs the window and removes the frame in
          // one turn. A srcdoc frame is parsed and loads on the next turn.
          if (__ptGetA(this, 'srcdoc') === null) { try { this.__ptFireLoad(true); } catch (e) {} }
          else __pt_soon(() => { try { this.__ptFireLoad(true); } catch (e) {} });
        }
        return;
      }
      if (__lazyDeferred(this)) return;
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      // The element size travels with the request: the frame context must know
      // its viewport before its first line runs. Layout cannot be queried here
      // (mid-parse it would freeze half-built); use the declared size.
      const box = __ptJSON.parse(globalThis.__pt_frameBoxOf ? __pt_frameBoxOf(this) : '[300,150]');
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      this.__ptHoldLoad();
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      let abs = String(src);
      try { abs = new URL(abs, (this.ownerDocument || document).baseURI).href; } catch (e) {}
      __frameOps.push({ op: 'open', id, src: abs, name: __ptGetA(this, 'name') || '', w: box[0] || 300, h: box[1] || 150 });
    }

    // A form aimed at this frame (`target` = its name) navigates it, as `src`
    // does, with the form's method and body; `src` itself is not touched.
    __ptNavigate(url, method, body, contentType) {
      if (this.__ptLocal !== 'iframe' || !this.isConnected) return;
      if (this.__ptFrameId) __ptDisconnectFrame(this);
      if (this.__ptRealm) {
        try { if (typeof this.__ptRealm.__pt_detach === 'function') this.__ptRealm.__pt_detach(); } catch (e) {}
        try { __realmFrames.delete(this); } catch (e) {}
        try { delete this.__ptRealm; } catch (e) {}
      }
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      const box = __ptJSON.parse(globalThis.__pt_frameBoxOf ? __pt_frameBoxOf(this) : '[300,150]');
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      this.__ptHoldLoad();
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      __frameOps.push({ op: 'open', id, src: String(url), name: __ptGetA(this, 'name') || '', w: box[0] || 300, h: box[1] || 150, method, body, contentType });
    }

    // Shadow DOM. A widget that draws itself into a shadow root — Cloudflare's
    // Turnstile does, and so does most of the web-component world — dies at the
    // first line without this. The tree is genuinely separate: nothing inside is
    // reachable from `document.querySelector`, which is the point of it.
    attachShadow(init) {
      const m = init && init.mode;
      if (m !== 'open' && m !== 'closed') {
        throw __pt_mkErr(TypeError, "Failed to execute 'attachShadow' on 'Element': Failed to read the 'mode' property from 'ShadowRootInit': The provided value '" + m + "' is not a valid enum value of type ShadowRootMode.");
      }
      if (this.__ptShadow) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'attachShadow' on 'Element': Shadow root cannot be created on a host which already hosts a shadow tree.", 'NotSupportedError');
      const sr = new ShadowRoot(this, m);
      sr.__ptDelegatesFocus = !!init.delegatesFocus;
      sr.__ptClonable = !!init.clonable;
      sr.__ptSerializable = !!init.serializable;
      sr.__ptSlotAssignment = init.slotAssignment === 'manual' ? 'manual' : 'named';
      this.__ptShadow = sr;
      __markDirty(this);
      __styleTouch(this);
      __hasMut.any = true;
      return sr;
    }
    getAnimations() { return []; }
    getHTML(opts) {
      const kids = (this.__ptLocal === 'template' ? __templateContent(this) : this).__ptKids;
      const withShadow = !!(opts && opts.serializableShadowRoots);
      // The element's own serializable shadow root comes first, as a
      // declarative <template shadowrootmode>.
      const sr = withShadow && this.__ptShadow && this.__ptShadow.__ptSerializable ? this.__ptShadow : null;
      const own = sr ? `<template shadowrootmode="${sr.mode}"${sr.__ptDelegatesFocus ? ' shadowrootdelegatesfocus=""' : ''}${sr.__ptSerializable ? ' shadowrootserializable=""' : ''}${sr.__ptClonable ? ' shadowrootclonable=""' : ''}>` + sr.__ptKids.map((n) => serializeNode(n, true)).join('') + '</template>' : '';
      return own + kids.map((n) => serializeNode(n, withShadow)).join('');
    }
    get shadowRoot() {
      const r = this.__ptShadow;
      // A closed root is invisible even to its own host's `shadowRoot`.
      return r && r.mode === 'open' ? r : null;
    }

    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      html = __pt_ttSink('TrustedHTML', 'Element innerHTML', html, "Failed to set the 'innerHTML' property on 'Element'");
      // Template markup is parsed into its content.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      __ptDropKids(host);
      for (const n of parseFragment(String(html), this)) __ptAdd.call(host, n);
    }
    get outerHTML() { return serializeNode(this); }
    // Rendered text (hidden subtrees excluded, whitespace collapsed) — an
    // approximation of `innerText` good enough for tools that read it.
    get innerText() { return __innerText(this); }
    set innerText(v) { if (this.__ptLocal === 'script') v = __pt_ttSink('TrustedScript', 'HTMLScriptElement innerText', v, "Failed to set the 'innerText' property on 'HTMLScriptElement'"); __csp.ttSkip = true; try { this.textContent = String(v); } finally { __csp.ttSkip = false; } }
    get outerText() { return __innerText(this); }
    insertAdjacentHTML(pos, html) {
      __needArgs(arguments.length, 2, 'insertAdjacentHTML', 'Element');
      if (!/^(beforebegin|afterbegin|beforeend|afterend)$/i.test(String(pos))) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'insertAdjacentHTML' on 'Element': The value provided ('" + pos +
          "') is not one of 'beforeBegin', 'afterBegin', 'beforeEnd', or 'afterEnd'.",
          'SyntaxError');
      }
      html = __pt_ttSink('TrustedHTML', 'Element insertAdjacentHTML', html, "Failed to execute 'insertAdjacentHTML' on 'Element'");
      // The parent is the context around the element, the element itself
      // inside it; `<html>` (or no element) parses as `<body>`.
      const where = __s_toLowerCase(String(pos));
      let ctx = where === 'beforebegin' || where === 'afterend' ? this.__ptParent : this;
      if (!ctx || ctx.__ptType !== ELEMENT_NODE || (ctx.__ptLocal === 'html' && __isHtmlEl(ctx))) ctx = null;
      const nodes = parseFragment(String(html), ctx || this.__ptDoc || globalThis.document);
      pos = where;
      if (pos === 'beforeend') for (const n of nodes) __ptAdd.call(this, n);
      else if (pos === 'afterbegin') for (const n of nodes.reverse()) __ptInsert.call(this, n, this.firstChild);
      else if (pos === 'beforebegin') for (const n of nodes) __ptInsert.call(this.__ptParent, n, this);
      else if (pos === 'afterend') for (const n of nodes.reverse()) __ptInsert.call(this.__ptParent, n, this.nextSibling);
    }

    // Synthetic layout (no real rendering): rendered elements report a non-empty
    // box so coordinate + visibility tooling works, hidden/detached ones an empty
    // one. See __relayout / __boxOf below.
    getBoundingClientRect() { return __rectFromBox(__boxOf(this)); }
    getClientRects() { const b = __boxOf(this); if (!b) return __ptRectList([]); return __ptRectList([__rectFromBox(b)]); }
    // Spec order: no box (display:none here or above) or content-visibility:hidden
    // above is false; opacity and visibility only when asked. Playwright tests
    // visibility with this first, so anything but a boolean hid every element.
    checkVisibility(options) {
      const o = options || {};
      const view = globalThis.getComputedStyle;
      if (!this.isConnected || typeof view !== 'function') return false;
      for (let e = this; e && e.__ptType === ELEMENT_NODE; e = e.parentElement) {
        let st; try { st = view(e); } catch (x) { st = null; }
        if (!st) continue;
        if (String(st.display) === 'none') return false;
        if (e !== this && String(st.contentVisibility || st.getPropertyValue && st.getPropertyValue('content-visibility')) === 'hidden') return false;
        if ((o.checkOpacity || o.opacityProperty) && String(st.opacity) === '0') return false;
      }
      if (o.checkVisibilityCSS || o.visibilityProperty) {
        let st; try { st = view(this); } catch (x) { st = null; }
        if (st && String(st.visibility) !== 'visible') return false;
      }
      return true;
    }
    get parentElement() { const p = this.__ptParent; return p && p.__ptType === ELEMENT_NODE ? p : null; }
    // Layout-metric accessors derived from the synthetic box. `documentElement`'s
    // client size is the viewport (drivers clamp click boxes to it).
    // `clientWidth` is the content box plus padding, no borders, as an
    // integer; `offsetWidth` includes borders.
    get clientWidth() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.W; const b = __boxOf(this); return b ? Math.round(b.w - b.bx - (b.bar ? b.bar[0] : 0)) : 0; }
    get clientHeight() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.H; const b = __boxOf(this); return b ? Math.round(b.h - b.by - (b.bar ? b.bar[1] : 0)) : 0; }
    get clientTop() { return 0; }
    get clientLeft() { return 0; }
    // Scroll area is the content extent: `scrollWidth` of a block with hidden
    // overflow exceeds its visible part.
    get scrollWidth() { const b = __boxOf(this); return b ? Math.round(Math.max(this.clientWidth, b.sw)) : this.clientWidth; }
    get scrollHeight() { const b = __boxOf(this); return b ? Math.round(Math.max(this.clientHeight, b.sh)) : this.clientHeight; }
    // The document scrolls through its root element (`scrollingElement`); other
    // boxes do not scroll here.
    get scrollTop() { const d = this.ownerDocument || globalThis.document; return d && this === d.documentElement && d === globalThis.document ? __scrollPos[1] : 0; }
    set scrollTop(v) { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement && d === globalThis.document) __scrollWindowTo(__scrollPos[0], v); }
    get scrollLeft() { const d = this.ownerDocument || globalThis.document; return d && this === d.documentElement && d === globalThis.document ? __scrollPos[0] : 0; }
    set scrollLeft(v) { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement && d === globalThis.document) __scrollWindowTo(v, __scrollPos[1]); }
    get offsetWidth() { const b = __boxOf(this); return b ? Math.round(b.w) : 0; }
    get offsetHeight() { const b = __boxOf(this); return b ? Math.round(b.h) : 0; }
    get offsetTop() { const b = __boxOf(this); return b ? b.y : 0; }
    get offsetLeft() { const b = __boxOf(this); return b ? b.x : 0; }
    get offsetParent() { return __boxOf(this) ? this.parentElement : null; }
    // Bring the element into the window by scrolling the document: `block` start,
    // center, end or nearest (`false` is end), as Chrome aligns it.
    scrollIntoView(arg) {
      const b = __boxOf(this);
      if (!b) return;
      const block = arg === false ? 'end' : (arg && typeof arg === 'object' && arg.block) || 'start';
      const vh = globalThis.innerHeight || LAYOUT.H, top = b.y, bottom = b.y + b.h, sy = __scrollPos[1];
      const y = block === 'center' ? top + b.h / 2 - vh / 2
        : block === 'end' ? bottom - vh
        : block === 'nearest' ? (top < sy ? top : bottom > sy + vh ? bottom - vh : sy)
        : top;
      __scrollWindowTo(__scrollPos[0], y);
    }
    scrollIntoViewIfNeeded(center) {
      const b = __boxOf(this);
      if (!b) return;
      const vh = globalThis.innerHeight || LAYOUT.H, sy = __scrollPos[1];
      if (b.y >= sy && b.y + b.h <= sy + vh) return;
      this.scrollIntoView({ block: center === false ? 'nearest' : 'center' });
    }
    focus() {
      const doc = this.ownerDocument || globalThis.document;
      // Focus inside a frame makes its <iframe> the parent's active element,
      // as in Chrome; keyboard input follows that chain down.
      if (doc && doc === globalThis.document) {
        __ptFocusHost();
        try { if (typeof __pt_focusSeq === 'function') doc.__ptFocusAt = __pt_focusSeq(); } catch (e) {}
      }
      if (!doc || doc.activeElement === this) return;
      const prev = doc.activeElement;
      // Chrome's order: `blur` and `focusout` on the old element, then `focus`
      // and `focusin` on the new, each with the other in `relatedTarget`.
      // The browser sends them, so `isTrusted` is true even when a script
      // asked for focus.
      if (prev && prev !== doc.body && prev.dispatchEvent) {
        prev.dispatchEvent(__ptFocusEvent('blur', this));
        prev.dispatchEvent(__ptFocusEvent('focusout', this, true));
      }
      doc.__ptActive = this;
      // `:focus` rules: a focus change restyles, as a tree change does.
      __markDirty(this);
      if (prev && prev.__ptType === ELEMENT_NODE) __markDirty(prev);
      // Body means "nothing focused": `relatedTarget` is then null, not `<body>`.
      const relatedFrom = prev && prev !== doc.body ? prev : null;
      this.dispatchEvent(__ptFocusEvent('focus', relatedFrom));
      this.dispatchEvent(__ptFocusEvent('focusin', relatedFrom, true));
    }
    blur() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement !== this) return;
      doc.__ptActive = doc.body || null;
      __markDirty(this);
      this.dispatchEvent(__ptFocusEvent('blur', null));
      this.dispatchEvent(__ptFocusEvent('focusout', null, true));
    }
    // Form-field value (reflects the `value` attribute until edited). Generic so
    // input/textarea typing works; harmless on other elements.
    get value() {
      if (this.__ptValue !== undefined) return this.__ptValue;
      const v = __ptGetA(this, 'value');
      if (v != null) return v;
      // A checkbox or radio button without a value is "on".
      return this.__ptLocal === 'input' && (__inputType(this) === 'checkbox' || __inputType(this) === 'radio') ? 'on' : '';
    }
    // Form state is styled (`:checked ~ x`, `:placeholder-shown`): new layout.
    set value(v) { this.__ptValue = String(v); __markDirty(this); }
    // Common form-field surface, reflected from attributes — drivers gate `fill`
    // and `select` on these (an input with no `type`/`disabled`/`readOnly` fails
    // Playwright's fillability check).
    // An unknown `type` value reads back as `text`.
    get type() {
      const t = __s_toLowerCase(__ptGetA(this, 'type') || '');
      if (this.tagName !== 'INPUT') return t;
      const KNOWN = ['button','checkbox','color','date','datetime-local','email','file','hidden',
                     'image','month','number','password','radio','range','reset','search','submit',
                     'tel','text','time','url','week'];
      return __s_indexOf(KNOWN, t) >= 0 ? t : 'text';
    }
    set type(v) { __ptSetA(this, 'type', v); }
    get disabled() { return __ptHasA(this, 'disabled'); }
    set disabled(v) { if (v) __ptSetA(this, 'disabled', ''); else __ptDelA(this, 'disabled'); }
    get readOnly() { return __ptHasA(this, 'readonly'); }
    set readOnly(v) { if (v) __ptSetA(this, 'readonly', ''); else __ptDelA(this, 'readonly'); }
    get name() { return __ptGetA(this, 'name') || ''; }
    set name(v) { __ptSetA(this, 'name', v); }
    get placeholder() { return __ptGetA(this, 'placeholder') || ''; }
    // Reflected dimension attributes. Without these, `canvas.width = 200` would
    // create an *own* property on the element (real ones are prototype
    // accessors), which is exactly the tell we hide everywhere else.
    get width() {
      const v = parseInt(__ptGetA(this, 'width'), 10);
      if (Number.isFinite(v)) return v;
      if (this.tagName === 'CANVAS') return 300;
      // Without the attribute an image's width is its intrinsic width.
      return this.tagName === 'IMG' ? this.naturalWidth : 0;
    }
    set width(v) {
      __ptSetA(this, 'width', String(Math.max(0, v | 0)));
      // Resizing a canvas resets its context state.
      if (this.__ptCtxResize) this.__ptCtxResize();
    }
    get height() {
      const v = parseInt(__ptGetA(this, 'height'), 10);
      if (Number.isFinite(v)) return v;
      if (this.tagName === 'CANVAS') return 150;
      return this.tagName === 'IMG' ? this.naturalHeight : 0;
    }
    set height(v) {
      __ptSetA(this, 'height', String(Math.max(0, v | 0)));
      if (this.__ptCtxResize) this.__ptCtxResize();
    }
    // Intrinsic image size: zero until loaded, real afterwards.
    get naturalWidth() { const s = this.__ptImgSize(); return s ? s[0] : 0; }
    get naturalHeight() { const s = this.__ptImgSize(); return s ? s[1] : 0; }
    __ptImgSize() {
      if (this.tagName !== 'IMG' || !this.__ptImgDone || !this.__ptImgAt) return null;
      try { return globalThis.__pt_imageSizeOf ? __pt_imageSizeOf(this.__ptImgAt) : null; } catch (e) { return null; }
    }
    get checked() { return this.__ptChecked !== undefined ? this.__ptChecked : __ptHasA(this, 'checked'); }
    set checked(v) {
      this.__ptChecked = !!v;
      // Checking a radio button unchecks the others of its group: the same
      // name, the same form (or none, in the same tree).
      if (v && this.__ptLocal === 'input' && __inputType(this) === 'radio') {
        const name = __ptGetA(this, 'name');
        if (name) {
          const owner = this.form || null;
          let root = owner;
          if (!root) { root = this; while (root.__ptParent) root = root.__ptParent; }
          __walkTree(root, (k) => {
            if (k !== this && k.__ptLocal === 'input' && k.__ptChecked !== false && __ptGetA(k, 'name') === name && __inputType(k) === 'radio' && (k.form || null) === owner && (k.__ptChecked || __ptHasA(k, 'checked'))) {
              k.__ptChecked = false;
              __markDirty(k);
            }
          });
        }
      }
      __markDirty(this);
    }
    get selectionStart() { return String(this.value || '').length; }
    get selectionEnd() { return String(this.value || '').length; }
    select() {}
    setSelectionRange() {}
    setRangeText() {}
    // Reflects `contenteditable`, case-insensitively: "true" for an empty
    // value, "inherit" for none or an unknown one.
    get contentEditable() {
      const a = __ptGetA(this, 'contenteditable');
      if (a == null) return 'inherit';
      const v = __s_toLowerCase(String(a));
      return v === '' || v === 'true' ? 'true' : v === 'false' || v === 'plaintext-only' ? v : 'inherit';
    }
    set contentEditable(v) {
      const s = String(v), m = __s_toLowerCase(s);
      if (m === 'inherit') { __ptDelA(this, 'contenteditable'); return; }
      if (m !== 'true' && m !== 'false' && m !== 'plaintext-only') {
        throw __pt_mkErr(globalThis.DOMException || Error, "Failed to set the 'contentEditable' property on 'HTMLElement': The value provided ('" + s + "') is not one of 'true', 'false', 'plaintext-only', or 'inherit'.", 'SyntaxError');
      }
      __ptSetA(this, 'contenteditable', m);
    }
    // Inherited from the nearest element that says: "", "true" or
    // "plaintext-only" turn editing on, "false" off, anything else defers to
    // the parent. designMode makes the whole document editable.
    get isContentEditable() {
      const doc = this.ownerDocument;
      if (doc && doc.__ptDesign) return true;
      for (let e = this; e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) {
        const a = __ptGetA(e, 'contenteditable');
        if (a == null) continue;
        const v = __s_toLowerCase(String(a));
        if (v === '' || v === 'true' || v === 'plaintext-only') return true;
        if (v === 'false') return false;
      }
      return false;
    }
    click() {
      const ok = this.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      if (ok) __ptActivate(this);
    }

    __ptShallowClone() {
      const e = new Element(this.localName);
      e.__ptAttrs = new Map(this.__ptAttrs);
      if (this.__ptAttrNS && this.__ptAttrNS.size) Object.defineProperty(e, '__ptAttrNS', { value: new Map(this.__ptAttrNS), enumerable: false, configurable: true });
      // A clone sits on the same interface step as the original: a copy of
      // `<template>` is an HTMLTemplateElement, of `<div>` an HTMLDivElement.
      try {
        if (this.__ptNS && globalThis.__pt_svgProto) {
          const p = __pt_svgProto(this.localName);
          if (p) { Object.setPrototypeOf(e, p); e.__ptNS = this.__ptNS; }
        } else if (globalThis.__pt_elementProto) {
          Object.setPrototypeOf(e, __pt_elementProto(this.localName));
        }
      } catch (x) {}
      e.__ptDoc = this.ownerDocument;
      return e;
    }
  }

  // ---- Document -------------------------------------------------------------
  class Document extends Node {
    moveBefore(node, child) { __moveBefore(this, arguments, 'Document'); }
    constructor() {
      super(DOCUMENT_NODE);
      this.__ptDocEl = null;
      this.__ptReady = 'loading';
      this.__ptCookie = '';
      this.__ptActive = null;
      this.__ptView = null;
      this.__ptCurScript = null;
    }
    get defaultView() { return this.__ptView; }
    set defaultView(v) { this.__ptView = v; }
    get currentScript() { return this.__ptCurScript; }
    set currentScript(v) { this.__ptCurScript = v; }
    // In Chrome a boxless (0x0) cross-site frame is hidden: its window is not
    // shown yet, and `visibilityState` there and in its empty frames is hidden.
    get visibilityState() { return globalThis.__ptDetached || __ptHiddenFrame() ? 'hidden' : 'visible'; }
    get hidden() { return !!globalThis.__ptDetached || __ptHiddenFrame(); }
    // `document.dir` reflects the root element's `dir`.
    get dir() { const h = this.documentElement; return h ? h.dir : ''; }
    set dir(v) { const h = this.documentElement; if (h) h.dir = v; }
    // The first element child, as in Chrome: the Turnstile VM swaps the root
    // with `document.replaceChild(html, documentElement)` and reads it back.
    get documentElement() {
      const kids = this.__ptKids;
      for (let i = 0; i < kids.length; i++) if (kids[i].__ptType === ELEMENT_NODE) return kids[i];
      return null;
    }
    // The document's ParentNode members are its own: `children` lives on
    // `Document.prototype` (otherwise the surface installs an empty stub).
    get children() { return __collection(this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.__ptType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.__ptType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    set documentElement(v) { this.__ptDocEl = v; }
    get readyState() { return this.__ptReady; }
    // A user's window is focused; a Chrome DevTools window answers false, a live one true.
    hasFocus() { return !globalThis.__ptDetached; }
    set readyState(v) { this.__ptReady = v; }
    // `<body>` as soon as there is one, never null in a loaded document:
    // fingerprinters bucket the value by type.
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    elementFromPoint(x, y) { return __elementFromPoint(x, y); }
    getAnimations() { return []; }
    // DOMImplementation: `document.implementation.createHTMLDocument()` is a
    // common way to get a clean document.
    get implementation() {
      if (this.__ptImpl) return this.__ptImpl;
      const self = this;
      const impl = {
        createHTMLDocument(title) {
          const d = globalThis.__pt_lateDom.parseDocument('<!doctype html><html><head></head><body></body></html>', 'text/html');
          if (title !== undefined) { const t = d.createElement('title'); __ptAdd.call(t, d.createTextNode(String(title))); __ptAdd.call(d.head, t); }
          return d;
        },
        createDocument(ns, qname, doctype) {
          const d = globalThis.__pt_lateDom.parseDocument(qname ? '<' + String(qname) + '/>' : '', ns === 'http://www.w3.org/1999/xhtml' ? 'application/xhtml+xml' : 'application/xml');
          if (!qname) { for (const k of __s_slice(d.__ptKids)) d.removeChild(k); }
          return d;
        },
        createDocumentType(name, publicId, systemId) { return { nodeType: 10, name: String(name), publicId: String(publicId || ''), systemId: String(systemId || ''), nodeName: String(name) }; },
        hasFeature() { return true; },
      };
      try { const D = globalThis.DOMImplementation; if (D && D.prototype) { for (const k of Object.keys(impl)) { Object.defineProperty(D.prototype, k, { value: impl[k], writable: true, enumerable: true, configurable: true }); } const o = Object.create(D.prototype); Object.defineProperty(this, '__ptImpl', { value: o, configurable: true }); return o; } } catch (e) {}
      Object.defineProperty(this, '__ptImpl', { value: impl, configurable: true });
      return impl;
    }
    // `document.all`: all elements in tree order. Chrome's is "undetectable"
    // (typeof undefined), which V8 does not give us, but indexing works.
    // Light tree only: shadow roots are excluded (the widget frame gave 96
    // elements vs Chrome's 12).
    get all() { return __allCollection(collect(this, () => true)); }
    get applets() { return __collection([]); }
    // The whole stack under the point, from the deepest to `<html>`.
    elementsFromPoint(x, y) {
      const out = [];
      for (let e = __elementFromPoint(x, y); e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) out.push(e);
      // A point inside the viewport always hits at least <html>.
      if (!out.length && this.documentElement && x >= 0 && y >= 0 && x < (globalThis.innerWidth || 0) && y < (globalThis.innerHeight || 0)) out.push(this.documentElement);
      return out;
    }
    get nodeName() { return '#document'; }
    // Children of <html> only, as the spec has it: a <body> anywhere else is
    // not the body (Chrome answers null), and no tree walk per read.
    get head() { return __htmlChild(this, 'head', null); }
    get body() { return __htmlChild(this, 'body', 'frameset'); }
    get title() { const t = __docTitle(this); return t ? __s_trim(t.textContent) : ''; }
    set title(v) {
      let t = __docTitle(this);
      if (!t) { t = this.createElement('title'); (this.head || this.documentElement || this).appendChild(t); }
      t.textContent = String(v);
    }
    // The document's live element collections. Missing, these are not a cosmetic
    // gap: Turnstile's loader answers its widget's `requestExtraParams` with a
    // report that reads `document.scripts.length`, and a `TypeError` there kills
    // the reply — which the widget waits for forever, silently, because a listener
    // that throws is swallowed by the event dispatch. `referrer` is read on the
    // same line and must be a string ('' for a direct load), not `undefined`.
    // Document collections are HTMLCollection, not arrays: `Array.isArray` is
    // false, and fingerprinters bucket arrays by their string value.
    get scripts() { return __collection(__docTags(this, 'script'), true); }
    get forms() { return __collection(__docTags(this, 'form'), true); }
    get images() { return __collection(__docTags(this, 'img'), true); }
    get embeds() { return __collection(__docTags(this, 'embed'), true); }
    get plugins() { return __collection(__docTags(this, 'embed'), true); }
    // `links` is `<a>`/`<area>` *with an href*, and `anchors` is `<a>` with a name.
    get links() {
      return __collection(__docTags(this, 'a').concat(__docTags(this, 'area'))
        .filter(e => __ptHasA(e, 'href')), true);
    }
    get anchors() { return __collection(__docTags(this, 'a').filter(e => __ptHasA(e, 'name')), true); }
    get styleSheets() { return __styleSheetList(__sheetOwners(this)); }
    // The declared charset, not always UTF-8: a page without a declaration is
    // parsed as windows-1252, and Chrome reports that.
    get characterSet() {
      if (this.__ptCharset) return this.__ptCharset;
      // Documents from a string (DOMParser) are always UTF-8.
      if (this.__ptContentType) return 'UTF-8';
      for (const m of __docTags(this, 'meta')) {
        const c = __ptGetA(m, 'charset');
        if (c) return __normEncoding(c);
        if (/^content-type$/i.test(__ptGetA(m, 'http-equiv') || '')) {
          const hit = /charset\s*=\s*"?([\w-]+)/i.exec(__ptGetA(m, 'content') || '');
          if (hit) return __normEncoding(hit[1]);
        }
      }
      // An empty document (`about:blank`, the challenge sandbox) is UTF-8.
      return this.URL === 'about:blank' ? 'UTF-8' : 'windows-1252';
    }
    get charset() { return this.characterSet; }
    get inputEncoding() { return this.characterSet; }
    get contentType() { return this.__ptContentType || this.__ptDocType || 'text/html'; }
    get xmlVersion() { return this.__ptXml ? '1.0' : null; }
    // A page without `<!DOCTYPE>` is in quirks mode: `BackCompat` and
    // `doctype === null`.
    get compatMode() {
      if (this.__ptXml) return 'CSS1Compat';
      if (this.__ptMode) return this.__ptMode === 'quirks' ? 'BackCompat' : 'CSS1Compat';
      return this.__ptDoctype ? 'CSS1Compat' : 'BackCompat';
    }
    get doctype() { return this.__ptDoctype || null; }
    get designMode() { return this.__ptDesign ? 'on' : 'off'; }
    set designMode(v) {
      const m = __s_toLowerCase(String(v));
      if (m !== 'on' && m !== 'off') return;
      try { Object.defineProperty(this, '__ptDesign', { value: m === 'on', writable: true, configurable: true, enumerable: false }); } catch (e) {}
    }
    // Chrome's format is MM/DD/YYYY HH:MM:SS, not a localised string.
    get lastModified() {
      const d = new Date(), p2 = (n) => __s_padStart(String(n), 2, '0');
      return `${p2(d.getMonth() + 1)}/${p2(d.getDate())}/${d.getFullYear()} ` +
             `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    }
    get webkitVisibilityState() { return this.visibilityState; }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    // A document's textContent is null.
    get textContent() { return null; }
    set textContent(v) {}

    // In a frame, `about:blank`'s referrer is the creator document.
    // For a srcdoc frame Chrome gives only the creator's origin ("http://host/").
    get referrer() { return this.__ptReferrer || (this.URL === 'about:blank' && globalThis.__pt_creatorURL) || (this.URL === 'about:srcdoc' && globalThis.__pt_creatorURL && (() => { try { return new URL(globalThis.__pt_creatorURL).origin + '/'; } catch (e) { return globalThis.__pt_creatorURL; } })()) || (this === globalThis.document && globalThis.__pt_referrer) || ''; }
    set referrer(v) { this.__ptReferrer = String(v); }

    // `document.location` is `window.location` — the same object, not a copy. Its
    // absence is not a missing nicety: `document.location.hostname` is how a great
    // deal of code asks where it is, and against `undefined` that throws. It is
    // what stopped Cloudflare's full-page challenge here, inside its own timer,
    // where nothing surfaced the error.
    // A windowless document (DOMParser, XHR) has `location` null.
    get location() { return this === globalThis.document ? globalThis.location : null; }
    set location(v) { try { globalThis.location.href = String(v); } catch (e) {} }
    get URL() { return (globalThis.location && globalThis.location.href) || 'about:blank'; }
    get documentURI() { return this.URL; }
    // `about:blank`'s base URL is the creator's (the spec fallback).
    // The document's base URL: its first `<base href>`, resolved against the
    // fallback (the URL, or the creator's for about:blank and srcdoc).
    // Remembered until the tree or the URL changes.
    __ptBaseURI() {
      const fallback = (this.URL === 'about:blank' || this.URL === 'about:srcdoc') && globalThis.__pt_creatorURL ? globalThis.__pt_creatorURL : this.URL;
      const memo = __baseMemo.get(this);
      if (memo && memo.seq === __layoutSeq && memo.fallback === fallback) return memo.base;
      let base = fallback;
      for (const b of __docTags(this, 'base')) {
        const h = __ptGetA(b, 'href');
        if (h == null) continue;
        try { base = new URL(String(h), fallback).href; } catch (e) {}
        break;
      }
      __baseMemo.set(this, { seq: __layoutSeq, fallback, base });
      return base;
    }
    get domain() { return (globalThis.location && globalThis.location.hostname) || globalThis.__pt_inheritedHost || ''; }
    set domain(v) { /* only ever narrowed to a parent domain; nothing to do here */ }

    // One jar with the network, as in a browser: the engine keeps `__ptCookie` to
    // what the jar holds for this document (HttpOnly left out), and a write goes
    // to the jar before the page's next request leaves.
    get cookie() { return this === globalThis.document ? this.__ptCookie : ''; }
    set cookie(v) {
      if (this !== globalThis.document) return;
      const raw = String(v);
      const parts = __s_split(raw, ';');
      const pair = __s_trim(parts[0]);
      const eq = __s_indexOf(pair, '=');
      const name = __s_trim(eq < 0 ? '' : __s_slice(pair, 0, eq));
      let gone = false;
      for (const p of __s_slice(parts, 1)) {
        const [k, ...rest] = __s_split(p, '=');
        const key = __s_toLowerCase(__s_trim(k)), val = __s_trim(rest.join('='));
        // Script cannot set an HttpOnly cookie, nor a Secure one on plain http.
        if (key === 'httponly') return;
        if (key === 'secure' && globalThis.location && globalThis.location.protocol !== 'https:') return;
        if (key === 'max-age' && Number(val) <= 0) gone = true;
        if (key === 'expires') { const t = Date.parse(val); if (!isNaN(t) && t <= Date.now()) gone = true; }
      }
      __cookieOps.push(raw);
      const jar = this.__ptCookie ? __s_split(this.__ptCookie, '; ') : [];
      const kept = jar.filter(c => (__s_indexOf(c, '=') < 0 ? '' : __s_slice(c, 0, __s_indexOf(c, '='))) !== name);
      if (!gone) kept.push(pair);
      this.__ptCookie = kept.join('; ');
    }

    createElement(tag) {
      // Tag name per XML rules: Chrome rejects `1x` and `a b` with
      // InvalidCharacterError.
      const raw = String(tag);
      if (!/^[A-Za-z_:\u00C0-\u{10FFFF}][A-Za-z0-9_:.\-\u00B7\u00C0-\u{10FFFF}]*$/u.test(raw)) {
        throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'createElement' on 'Document': The tag name provided ('" + raw + "') is not a valid name.", 'InvalidCharacterError');
      }
      // In an XML document the name is kept as is and the element is a plain Element.
      if (this.__ptXml) {
        const e = new Element(raw);
        e.__ptTag = raw; e.__ptLocal = raw;
        try { if (globalThis.Element && globalThis.Element.prototype) Object.setPrototypeOf(e, globalThis.Element.prototype); } catch (x) {}
        e.__ptDoc = this;
        return e;
      }
      const C = __customs.get(__s_toLowerCase(raw));
      if (globalThis.__pt_setPendingTag) __pt_setPendingTag(tag);
      const e = C ? new C() : new Element(tag);
      if (C) Object.defineProperty(e, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
      // The element sits on its interface step: `<canvas>` on
      // HTMLCanvasElement, an unknown tag on HTMLUnknownElement.
      if (!C && globalThis.__pt_elementProto) {
        try { Object.setPrototypeOf(e, __pt_elementProto(tag)); } catch (x) {}
      }
      e.__ptDoc = this;
      return e;
    }
    createElementNS(ns, qname) {
      const q = String(qname), colon = __s_indexOf(q, ':');
      const prefix = colon > 0 ? __s_slice(q, 0, colon) : null, tag = colon > 0 ? __s_slice(q, colon + 1) : q;
      const NS = ns === null || ns === undefined || ns === '' ? null : String(ns);
      const e = this.createElement(tag);
      e.__ptNS = NS;
      if (prefix) { e.__ptPrefix = prefix; e.__ptTag = q; }
      // Non-HTML element: name as written, not uppercased.
      if (NS !== 'http://www.w3.org/1999/xhtml') { e.__ptLocal = tag; e.__ptTag = q; }
      if (NS === 'http://www.w3.org/2000/svg' && globalThis.__pt_svgProto) {
        const proto = __pt_svgProto(String(tag));
        // SVG tag names are case-sensitive (`clipPath`, not `clippath`), and
        // SVG `tagName` is as written, not uppercase.
        if (proto) { try { Object.setPrototypeOf(e, proto); e.__ptNS = String(ns); e.__ptLocal = String(tag); e.__ptTag = q; } catch (x) {} }
      } else if (NS === 'http://www.w3.org/1998/Math/MathML' && typeof globalThis.MathMLElement === 'function') {
        try { Object.setPrototypeOf(e, MathMLElement.prototype); } catch (x) {}
      } else if (NS !== 'http://www.w3.org/1999/xhtml' && NS !== 'http://www.w3.org/2000/svg') {
        try { Object.setPrototypeOf(e, Element.prototype); } catch (x) {}
      }
      return e;
    }
    createTextNode(t) { const n = new Text(t); n.__ptDoc = this; return n; }
    createComment(t) { const n = new Comment(t); n.__ptDoc = this; return n; }
    createProcessingInstruction(target, data) {
      __needArgs(arguments.length, 2, 'createProcessingInstruction', 'Document');
      const t = String(target), d = String(data);
      const bad = (m) => __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'createProcessingInstruction' on 'Document': " + m, 'InvalidCharacterError');
      if (!__XML_NAME.test(t)) throw bad("The target provided ('" + t + "') is not a valid name.");
      if (__s_indexOf(d, '?>') >= 0) throw bad("The data provided ('" + d + "') contains '?>'.");
      return __makePI(this, t, d);
    }
    createDocumentFragment() { const f = new DocumentFragment(); f.__ptDoc = this; return f; }
    createEvent() { return new Event(''); }
    // A copy of a foreign node for this document. The Cloudflare challenge
    // puts template content into the body this way and then calls
    // `replaceChild` with the result.
    importNode(node, deep) {
      __needArgs(arguments.length, 1, 'importNode', 'Document');
      __needNode(node, 1, 'importNode', 'Document');
      if (node.__ptType === DOCUMENT_NODE) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'importNode' on 'Document': The node provided is a document, " +
          "which may not be imported.", 'NotSupportedError');
      }
      const copy = node.cloneNode(!!deep);
      __walkTree(copy, (n) => { n.__ptDoc = this; });
      return copy;
    }
    // The same node, now ours: its old parent no longer has it.
    adoptNode(node) {
      __needArgs(arguments.length, 1, 'adoptNode', 'Document');
      __needNode(node, 1, 'adoptNode', 'Document');
      if (node.__ptType === DOCUMENT_NODE) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'adoptNode' on 'Document': The node provided is a document, " +
          "which may not be adopted.", 'NotSupportedError');
      }
      if (node.__ptParent) node.__ptParent.removeChild(node);
      __walkTree(node, (n) => { n.__ptDoc = this; });
      return node;
    }

    // Walk from the document itself: <html> is a descendant too (otherwise
    // getElementsByTagName('*') was one short and an id on <html> was not found).
    getElementById(id) { const want = String(id); return firstMatch(this, (e) => __ptGetA(e, 'id') === want); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) { return __collection(__byClass(this, c)); }
    getElementsByName(n) {
      const want = String(n);
      return __staticNodeList(collect(this, (e) => e.__ptAttrs && e.__ptAttrs.get('name') === want));
    }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    querySelector(s) {
      __needArgs(arguments.length, 1, 'querySelector', 'Document');
      __checkSelector(s, 'querySelector', 'Document');
      return queryFirst(this, s);
    }
    querySelectorAll(s) {
      __needArgs(arguments.length, 1, 'querySelectorAll', 'Document');
      __checkSelector(s, 'querySelectorAll', 'Document');
      return __staticNodeList(query(this, s));
    }

    // document.write inserts parsed markup at the position of the script that
    // called it (tracked as `currentScript`), matching in-parse behaviour for the
    // common `<script>document.write(x)</script>` idiom. With no current script
    // (e.g. async), it appends to <body>. Dynamically written <script> tags are
    // inserted but not executed (our script list is fixed at parse time).
    write(...args) {
      const nodes = parseFragment(args.map((a) => String(__pt_ttSink('TrustedHTML', 'Document write', a, "Failed to execute 'write' on 'Document'"))).join(''), this);
      const cur = this.currentScript;
      if (cur && cur.__ptParent) {
        const ref = cur.nextSibling;
        for (const n of nodes) cur.__ptParent.insertBefore(n, ref);
      } else {
        const host = this.body || this.documentElement;
        if (host) for (const n of nodes) host.appendChild(n);
      }
    }
    writeln(...args) { this.write(args.join('') + '\n'); }
    open() { return this; }
    close() {}
    __ptShallowClone() { return new Document(); }
  }

  // ---- Event ----------------------------------------------------------------
  // Event state lives in one hidden bag (`__ptE`) exposed through prototype
  // accessors: a real `new MouseEvent('click')` reports no own properties, so
  // assigning fields to the instance would be an obvious tell.
  const evtAccessors = (Ctor, names) => {
    for (const n of names) {
      // Accessor literals are born named `get x`/`set x` (no dictionary).
      const { get, set } = Object.getOwnPropertyDescriptor({
        get [n]() { return this.__ptE[n]; },
        set [n](v) { this.__ptE[n] = v; },
      }, n);
      Object.defineProperty(Ctor.prototype, n, { get, set, configurable: true, enumerable: false });
    }
  };

  // `isTrusted` is an own property of each event ([LegacyUnforgeable]), not a
  // prototype accessor: Event.prototype enumeration does not show it, and on
  // the instance it is non-configurable.
  const __ptIsTrustedGet = (() => {
    const g = function () { return !!(this.__ptE && this.__ptE.isTrusted); };
    try { Object.defineProperty(g, 'name', { value: 'get isTrusted', configurable: true }); } catch (e) {}
    return globalThis.__pt_native ? __pt_native(g) : g;
  })();
  class Event {
    constructor(type, init) {
      init = init || {};
      Object.defineProperty(this, 'isTrusted', { get: __ptIsTrustedGet, set: undefined, enumerable: true, configurable: false });
      this.__ptE = {
        type, bubbles: !!init.bubbles, cancelable: !!init.cancelable,
        // `composed` is a regular field, false (not undefined) in Chrome.
        composed: !!init.composed,
        defaultPrevented: false, target: null, currentTarget: null,
        // Page-created events are untrusted; trusted ones come only from the
        // engine (input, load, message), which marks them with __ptTrust.
        eventPhase: 0, timeStamp: (globalThis.performance && performance.now()) || 0, isTrusted: false,
      };
      this.__ptStop = false; this.__ptStopImm = false;
    }
    preventDefault() { if (this.cancelable && !(this.__ptE && this.__ptE.__ptPassive)) this.__ptE.defaultPrevented = true; }
    stopPropagation() { this.__ptStop = true; }
    stopImmediatePropagation() { this.__ptStop = true; this.__ptStopImm = true; }
    // The path of the current dispatch; empty outside it, as in Chrome. Nodes
    // in a closed shadow tree are hidden from listeners outside it.
    composedPath() {
      const p = this.__ptE ? this.__ptE.__ptPathNow : this.__ptPathNow; if (!p) return [];
      const cur = this.currentTarget; const out = [];
      let hidden = false;
      for (let i = 0; i < p.length; i++) {
        const n = p[i];
        out.push(n);
        if (n.__ptType === 11 && n.mode === 'closed' && cur && cur !== n && !(n.contains && n.contains(cur))) hidden = true;
        if (hidden && n.__ptType === 11) { out.length = 0; hidden = false; }
      }
      return out;
    }
  }
  // Mark an event as engine-originated. Out of the page's reach: the __pt name
  // is hidden from enumeration and the getter is captured once.
  const __ptTrust = (ev) => {
    if (ev && ev.__ptE) ev.__ptE.isTrusted = true;
    else if (ev) { try { Object.defineProperty(ev, 'isTrusted', { value: true, configurable: true }); } catch (e) {} }
    return ev;
  };
  // The worker scope is set up by a separate script and marks its deliveries with this.
  try { Object.defineProperty(globalThis, '__pt_trustEvent', { value: __ptTrust, enumerable: false, configurable: true }); } catch (e) {}

  evtAccessors(Event, ['type', 'bubbles', 'cancelable', 'composed', 'defaultPrevented', 'target',
    'currentTarget', 'eventPhase', 'timeStamp']);
  // `srcElement` is the same as `target`.
  try { const g = function () { return this.__ptE.target; }; Object.defineProperty(g, 'name', { value: 'get srcElement', configurable: true }); Object.defineProperty(Event.prototype, 'srcElement', { get: g, configurable: true, enumerable: false }); } catch (e) {}

  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); this.__ptE.detail = (init && init.detail) || null; }
  }
  evtAccessors(CustomEvent, ['detail']);

  // WebGL context lost/restored event: the shape-table stub failed on the
  // init dictionary ('statusMessage').
  class WebGLContextEvent extends Event {
    constructor(type, init) { super(type, init); this.__ptE.statusMessage = init && init.statusMessage !== undefined ? String(init.statusMessage) : ''; }
  }
  evtAccessors(WebGLContextEvent, ['statusMessage']);

  class UIEvent extends Event {
    constructor(type, init) {
      super(type, init); init = init || {};
      this.__ptE.detail = init.detail || 0;
      this.__ptE.view = globalThis;
      // The device that produced the event: null for page-built events; engine
      // mouse input sets it (InputDeviceCapabilities, see __pt_mouse).
      this.__ptE.sourceCapabilities = init.sourceCapabilities || null;
      this.__ptE.which = init.which || 0;
    }
  }
  evtAccessors(UIEvent, ['detail', 'view', 'which', 'sourceCapabilities']);

  const MODS = ['ctrlKey', 'shiftKey', 'altKey', 'metaKey'];
  const modifierState = function (k) {
    return { Control: this.ctrlKey, Shift: this.shiftKey, Alt: this.altKey, Meta: this.metaKey }[k] || false;
  };

  class MouseEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      const x = init.clientX || 0, y = init.clientY || 0;
      Object.assign(this.__ptE, {
        clientX: x, clientY: y,
        screenX: init.screenX || x, screenY: init.screenY || y,
        pageX: x, pageY: y,
        offsetX: init.offsetX || 0, offsetY: init.offsetY || 0,
        button: init.button || 0, buttons: init.buttons || 0,
        ctrlKey: !!init.ctrlKey, shiftKey: !!init.shiftKey,
        altKey: !!init.altKey, metaKey: !!init.metaKey,
        relatedTarget: init.relatedTarget || null,
        // x/y equal clientX/Y; layerX/Y and offsets of a page-built event come
        // from its coordinates; which is button + 1 (legacy Blink).
        x, y, layerX: Math.trunc(x), layerY: Math.trunc(y),
        movementX: init.movementX || 0, movementY: init.movementY || 0,
        which: (init.button || 0) + 1,
      });
    }
    get fromElement() { const t = this.type; return t === 'mouseover' || t === 'mouseenter' || t === 'pointerover' || t === 'pointerenter' ? this.relatedTarget : this.target; }
    get toElement() { const t = this.type; return t === 'mouseout' || t === 'mouseleave' || t === 'pointerout' || t === 'pointerleave' ? this.relatedTarget : this.target; }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(MouseEvent, ['clientX', 'clientY', 'screenX', 'screenY', 'pageX', 'pageY',
    'offsetX', 'offsetY', 'button', 'buttons', 'relatedTarget', 'movementX', 'movementY',
    'x', 'y', 'layerX', 'layerY'].concat(MODS));

  class PointerEvent extends MouseEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      // Spec defaults: a page-built event in Chrome has `pointerId` 0, empty
      // `pointerType` and zero pressure. The input source sets real values.
      Object.assign(this.__ptE, {
        pointerId: init.pointerId === undefined ? 0 : init.pointerId,
        pointerType: init.pointerType === undefined ? '' : init.pointerType,
        isPrimary: !!init.isPrimary,
        width: init.width === undefined ? 1 : init.width,
        height: init.height === undefined ? 1 : init.height,
        pressure: init.pressure === undefined ? 0 : init.pressure,
        tangentialPressure: init.tangentialPressure || 0,
        tiltX: init.tiltX || 0,
        tiltY: init.tiltY || 0,
        twist: init.twist || 0,
        altitudeAngle: init.altitudeAngle === undefined ? Math.PI / 2 : init.altitudeAngle,
        azimuthAngle: init.azimuthAngle || 0,
        persistentDeviceId: init.persistentDeviceId || 0,
      });
    }
    // An untrusted event has no coalesced events, which gives it away.
    getCoalescedEvents() { return this.isTrusted ? [this] : []; }
    getPredictedEvents() { return []; }
  }
  evtAccessors(PointerEvent, ['pointerId', 'pointerType', 'isPrimary', 'width', 'height',
    'pressure', 'tangentialPressure', 'tiltX', 'tiltY', 'twist', 'altitudeAngle', 'azimuthAngle', 'persistentDeviceId']);

  class KeyboardEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        key: init.key || '', code: init.code || '',
        keyCode: init.keyCode || 0, which: init.keyCode || 0, charCode: init.charCode || 0,
        location: init.location || 0, repeat: !!init.repeat,
        ctrlKey: !!init.ctrlKey, shiftKey: !!init.shiftKey,
        altKey: !!init.altKey, metaKey: !!init.metaKey, isComposing: !!init.isComposing,
      });
    }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(KeyboardEvent, ['key', 'code', 'keyCode', 'which', 'charCode',
    'location', 'repeat', 'isComposing'].concat(MODS));

  class InputEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        data: init.data == null ? null : String(init.data),
        inputType: init.inputType || '', isComposing: !!init.isComposing,
        dataTransfer: init.dataTransfer || null,
      });
    }
  }
  evtAccessors(InputEvent, ['data', 'inputType', 'isComposing', 'dataTransfer']);

  class FocusEvent extends UIEvent {
    constructor(type, init) { super(type, init); this.__ptE.relatedTarget = (init && init.relatedTarget) || null; }
  }
  evtAccessors(FocusEvent, ['relatedTarget']);

  class MessageEvent extends Event {
    constructor(type, init) {
      super(type, init); init = init || {};
      this.__ptE.data = init.data !== undefined ? init.data : null;
      this.__ptE.origin = init.origin || '';
      this.__ptE.lastEventId = init.lastEventId || '';
      this.__ptE.source = init.source || null;
      this.__ptE.ports = init.ports || [];
      this.__ptE.userActivation = null;
    }
  }
  evtAccessors(MessageEvent, ['data', 'origin', 'lastEventId', 'source', 'ports', 'userActivation']);

  for (const [n, C] of [['UIEvent', UIEvent], ['MouseEvent', MouseEvent], ['PointerEvent', PointerEvent],
    ['KeyboardEvent', KeyboardEvent], ['InputEvent', InputEvent], ['FocusEvent', FocusEvent],
    ['MessageEvent', MessageEvent]]) {
    if (!globalThis[n]) globalThis[n] = C;
  }

  // ---- Web Workers (single-threaded shim) -----------------------------------
  // Real Chrome exposes Worker/OffscreenCanvas/SharedWorker; a missing `typeof
  // Worker` is a passive fingerprint tell. This runs the worker script in an
  // emulated global scope in the same isolate (no real threading), so `typeof
  // Worker === "function"` holds and compute-style workers (message in → work →
  // postMessage back) function. Not real parallelism, and blob: scripts need
  // URL.createObjectURL support to load.
  // A worker is a separate V8 context built by the engine (own scope,
  // prototypes, `self`). Only the port lives here: an outbound op queue and
  // message delivery back.
  const __workerOps = [];
  // `document.cookie` writes, for the engine to put in the jar (see Document).
  const __cookieOps = [];
  const __workers = new Map();
  let __nextWorkerId = 1;
  globalThis.__pt_drainWorkerQueue = () => __workerOps.splice(0);
  globalThis.__pt_drainCookieQueue = () => __cookieOps.splice(0);
  globalThis.__pt_setCookieMirror = (v) => { if (globalThis.document) globalThis.document.__ptCookie = v; };
  globalThis.__pt_workerMessage = (id, json) => {
    const W = __workers.get(id);
    if (!W || W.closed) return;
    let data = null;
    try { data = __pt_cloneDecode(json); } catch (e) {}
    if (W.shared) {
      // A shared worker answers through its port.
      const ev = __ptTrust(new MessageEvent('message', { data, origin: '', source: null, ports: [] }));
      const st = W.port.__pt;
      if (!st.started) st.queue.push(ev); else W.port.__ptDeliver(ev);
      return;
    }
    const ev = __ptTrust(new MessageEvent('message', { data, origin: '', source: null }));
    try { __ptEvSet(ev, 'target', W.worker); __ptEvSet(ev, 'currentTarget', W.worker); } catch (e) {}
    // Inside the handler `window.event` is the event; outside, nothing.
    const savedEvent = __ptTakeEvent(ev);
    let t0 = 0; try { t0 = performance.now(); } catch (e) {}
    try {
      try { if (typeof W.onmessage === 'function') W.onmessage.call(W.worker, ev); } catch (e) {}
      for (const h of (W.listeners.message || [])) { try { h.call(W.worker, ev); } catch (e) {} }
    } finally {
      try {
        const dt = performance.now() - t0;
        if (dt > 50 && typeof globalThis.__pt_noteLoaf === 'function') {
          const h = typeof W.onmessage === 'function' ? W.onmessage : (W.listeners.message || [])[0];
          __pt_noteLoaf(t0, dt, typeof W.onmessage === 'function' ? 'Worker.onmessage' : 'Worker.addEventListener:message', 'event-listener', h);
        }
      } catch (e) {}
      __ptDropEvent(savedEvent);
    }
  };
  globalThis.__pt_workerFailed = (id, message) => {
    const W = __workers.get(id);
    if (!W) return;
    const ev = new MessageEvent('error', {});
    ev.__ptE.message = String(message || 'worker failed');
    try { if (typeof W.onerror === 'function') W.onerror.call(W.worker, ev); } catch (e) {}
    for (const h of (W.listeners.error || [])) { try { h.call(W.worker, ev); } catch (e) {} }
  };

  // A worker's script address against the document's base URL (`<base href>`).
  const __workerSrc = (src) => {
    try { return new URL(src, (globalThis.document && document.baseURI) || (globalThis.location && location.href) || undefined).href; } catch (e) { return src; }
  };
  class Worker extends EventTarget {
    constructor(scriptURL, options) {
      super();
      const id = __nextWorkerId++;
      const W = { id, onmessage: null, onmessageerror: null, onerror: null, closed: false, listeners: {}, worker: this };
      Object.defineProperty(this, '__ptW', { value: W, enumerable: false });
      __workers.set(id, W);
      // The bytes are taken now, not when the engine gets round to the op: a
      // browser starts fetching the script inside `new Worker`, and the common
      // idiom is `const u = URL.createObjectURL(b); new Worker(u);
      // URL.revokeObjectURL(u)` — read it a round later and the blob is gone.
      const src = String(scriptURL);
      let body = null;
      if (__s_slice(src, 0, 5) === 'blob:' || __s_slice(src, 0, 5) === 'data:') {
        try { body = globalThis.__pt_localSource ? __pt_localSource(src) : null; } catch (e) {}
        // A blob URL of a foreign (or no) origin is refused in the
        // constructor; an own but empty one fails later with an error event.
        if (__s_slice(src, 0, 5) === 'blob:') {
          let o = 'null'; try { o = new URL(src).origin; } catch (e) {}
          const mine = (globalThis.location && location.origin) || 'null';
          if (o === 'null' || o !== mine) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to construct 'Worker': Script at '" + src + "' cannot be accessed from origin '" + mine + "'.", 'SecurityError');
        }
      }
      __workerOps.push({ op: 'open', id, src: __workerSrc(src), body, name: (options && options.name) || '' });
    }
    postMessage(data) {
      const W = this.__ptW;
      if (W.closed) return;
      let json = 'null';
      // Structured clone, not JSON, as in Chrome: bytes stay bytes, dates
      // stay dates.
      json = __pt_cloneEncode(data);
      __workerOps.push({ op: 'post', id: W.id, data: json });
    }
    terminate() {
      const W = this.__ptW;
      W.closed = true;
      __workers.delete(W.id);
      __workerOps.push({ op: 'close', id: W.id });
    }
    addEventListener(t, h) { const L = this.__ptW.listeners; (L[t] = L[t] || []).push(h); }
    removeEventListener(t, h) { const L = this.__ptW.listeners; if (L[t]) L[t] = L[t].filter((x) => x !== h); }
    dispatchEvent(ev) { (this.__ptW.listeners[ev.type] || []).forEach((h) => { try { h.call(this, ev); } catch (e) {} }); return true; }
  }
  for (const p of ['onmessage', 'onmessageerror', 'onerror']) {
    Object.defineProperty(Worker.prototype, p, {
      configurable: true,
      get() { return this.__ptW[p]; },
      set(v) { this.__ptW[p] = v; },
    });
  }
  // `Object.prototype.toString.call(new Worker(...))` is "[object Worker]".
  try { Object.defineProperty(Worker.prototype, Symbol.toStringTag, { value: 'Worker', configurable: true }); } catch (e) {}

  // A shared worker runs as a worker context of its own (one per page here;
  // the browser shares it between pages of the origin). Its `port` is a real
  // MessagePort whose messages travel on the worker's channel; the worker
  // side gets the other end in its `connect` event.
  class SharedWorker extends EventTarget {
    constructor(scriptURL, options) {
      super();
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to construct 'SharedWorker': 1 argument required, but only 0 present.");
      const id = __nextWorkerId++;
      const port = new globalThis.MessageChannel().port1;
      port.__pt.peer = null;
      port.__pt.remote = 'sw:' + id;
      const W = { id, shared: true, onerror: null, closed: false, listeners: {}, worker: this, port };
      Object.defineProperty(this, '__ptW', { value: W, enumerable: false });
      __workers.set(id, W);
      const src = String(scriptURL);
      let body = null;
      if (__s_slice(src, 0, 5) === 'blob:' || __s_slice(src, 0, 5) === 'data:') {
        try { body = globalThis.__pt_localSource ? __pt_localSource(src) : null; } catch (e) {}
      }
      const name = typeof options === 'string' ? options : (options && options.name !== undefined ? String(options.name) : '');
      __workerOps.push({ op: 'open', id, src: __workerSrc(src), body, name, shared: true });
    }
    get port() { return this.__ptW.port; }
    get onerror() { return this.__ptW.onerror; }
    set onerror(v) { this.__ptW.onerror = v; }
  }

  // OffscreenCanvas maps to a detached <canvas>, reusing its 2D/WebGL contexts.
  class OffscreenCanvas {
    constructor(width, height) {
      // Through references captured in advance, not page-visible names:
      // Chrome's `new OffscreenCanvas` touches neither
      // `document.createElement` nor `HTMLCanvasElement.prototype.getContext`.
      let c = globalThis.__pt_privateCanvas
        ? globalThis.__pt_privateCanvas(width, height)
        : (globalThis.document ? globalThis.document.createElement('canvas') : null);
      // Workers have no document but do have OffscreenCanvas (that is what it
      // is for there): a document-less canvas with the element's methods and
      // its own size, so `getContext('2d')` in a worker is not null.
      if (!c) {
        // The stand-in inherits the element prototype: canvas methods check the
        // brand and reject foreign objects, as in Chrome.
        const proto = globalThis.__pt_canvasProto;
        c = Object.create(proto || null);
        Object.defineProperty(c, 'localName', { value: 'canvas', writable: true, configurable: true });
        Object.defineProperty(c, 'width', { value: width | 0, writable: true, configurable: true });
        Object.defineProperty(c, 'height', { value: height | 0, writable: true, configurable: true });
      }
      c.width = width | 0; c.height = height | 0;
      Object.defineProperty(this, '__ptO', { value: { c, w: width | 0, h: height | 0 } });
    }
    get width() { return this.__ptO.w; }
    set width(v) {
      this.__ptO.w = v | 0;
      if (this.__ptO.c) this.__ptO.c.width = v | 0;
    }
    get height() { return this.__ptO.h; }
    set height(v) { this.__ptO.h = v | 0; if (this.__ptO.c) this.__ptO.c.height = v | 0; }
    getContext(type, attrs) {
      try { if (globalThis.__pt_canvasTrace) (globalThis.__pt_parentConsole || console).error('[canvas getContext offscreen ' + (this.width | 0) + 'x' + (this.height | 0) + '] ' + String(type) + ' ' + JSON.stringify(attrs === undefined ? null : attrs)); } catch (e) {}
      // Offscreen accepts its own set of names: `experimental-webgl` and the
      // like are refused.
      const t = String(type);
      if (t !== '2d' && t !== 'webgl' && t !== 'webgl2' && t !== 'bitmaprenderer' && t !== 'webgpu') {
        throw __pt_mkErr(TypeError, "Failed to execute 'getContext' on 'OffscreenCanvas': The provided value '"
          + t + "' is not a valid enum value of type OffscreenRenderingContextType.");
      }
      const c = this.__ptO.c;
      // The inner canvas knows its offscreen: `ctx.canvas` returns it, not the
      // hidden <canvas>, and context events (WebGL loss) go to it.
      if (c && !c.__ptOwner) { try { Object.defineProperty(c, '__ptOwner', { value: this, configurable: true }); } catch (e) {} }
      const orig = globalThis.__pt_canvasOrig;
      const get = (orig && orig.getContext) || (c && c.getContext);
      const g = c && get ? get.call(c, t, attrs) : null;
      // Offscreen 2D is a separate interface and pages read its name:
      // `OffscreenCanvasRenderingContext2D`, not `CanvasRenderingContext2D`.
      if (g && t === '2d' && globalThis.OffscreenCanvasRenderingContext2D) {
        try {
          const P = globalThis.OffscreenCanvasRenderingContext2D.prototype;
          if (P && Object.getPrototypeOf(g) !== P) {
            if (!P.__ptLinked) {
              const src = Object.getPrototypeOf(g);
              Object.setPrototypeOf(P, src);
              Object.defineProperty(P, '__ptLinked', { value: true });
              // Shape stubs give way to the real members: in Chrome they are
              // own members of the offscreen context.
              try {
                const S = globalThis.__pt_stubMembers;
                for (const k of Object.getOwnPropertyNames(P)) {
                  const d = Object.getOwnPropertyDescriptor(P, k);
                  const real = Object.getOwnPropertyDescriptor(src, k);
                  if (d && real && S && ((d.value && S.has(d.value)) || (d.get && S.has(d.get)))) Object.defineProperty(P, k, real);
                }
              } catch (e) {}
              if (!Object.getOwnPropertyDescriptor(P, Symbol.toStringTag)) {
                Object.defineProperty(P, Symbol.toStringTag,
                  { value: 'OffscreenCanvasRenderingContext2D', configurable: true });
              }
            }
            Object.setPrototypeOf(g, P);
          }
        } catch (e) {}
      }
      return g;
    }
    // A real image, not an empty `Blob`: pages measure the snapshot's length.
    convertToBlob(opts) {
      const c = this.__ptO.c;
      const type = (opts && opts.type) || 'image/png';
      const orig = globalThis.__pt_canvasOrig;
      const url = (orig && orig.toDataURL) || (c && c.toDataURL);
      try {
        if (c && url && globalThis.__pt_blobFromDataUrl) {
          return Promise.resolve(globalThis.__pt_blobFromDataUrl(
            url.call(c, type, opts && opts.quality)));
        }
      } catch (e) { return Promise.reject(e); }
      return Promise.resolve(new Blob([], { type }));
    }
    // A real ImageBitmap carrying the canvas pixels; otherwise `drawImage`
    // with it draws nothing.
    transferToImageBitmap() {
      const c = this.__ptO.c;
      // Built by the same helper as `createImageBitmap`: sizes on the
      // prototype, name tag and a working `close`, as in Chrome.
      if (globalThis.__pt_makeBitmap) {
        return globalThis.__pt_makeBitmap(c && c.__ptSurf, this.__ptO.w, this.__ptO.h);
      }
      const b = Object.create((globalThis.ImageBitmap && globalThis.ImageBitmap.prototype) || Object.prototype);
      Object.defineProperty(b, '__ptImageBitmap', { value: { surf: c && c.__ptSurf } });
      Object.defineProperty(b, 'width', { value: this.__ptO.w, enumerable: true });
      Object.defineProperty(b, 'height', { value: this.__ptO.h, enumerable: true });
      Object.defineProperty(b, 'close', { value: function close() {}, writable: true, configurable: true });
      return b;
    }
  }

  // Own methods captured before the page runs. Internal insertions must not go
  // through names a page can wrap: in Chrome neither `appendChild` inside
  // `innerHTML` nor `setAttribute` inside `new Image` is visible.
  const __ptInsert = Node.prototype.insertBefore;
  // A drop-down's options, in tree order (those in its optgroups too).
  function __ptSelOptions(sel) {
    const out = [];
    for (const k of (sel.__ptKids || [])) {
      if (k.__ptType !== ELEMENT_NODE) continue;
      if (k.__ptTag === 'OPTION') out.push(k);
      else if (k.__ptTag === 'OPTGROUP') for (const o of (k.__ptKids || [])) if (o.__ptType === ELEMENT_NODE && o.__ptTag === 'OPTION') out.push(o);
    }
    return out;
  }
  const __ptOptOn = (o) => !!(o.__ptSelected != null ? o.__ptSelected : __ptHasA(o, 'selected'));
  const __ptOptEnabled = (o) => !__ptHasA(o, 'disabled') && !(o.__ptParent && o.__ptParent.__ptTag === 'OPTGROUP' && __ptHasA(o.__ptParent, 'disabled'));
  const __ptDropDown = (sel) => !__ptHasA(sel, 'multiple') && !(parseInt(__ptGetA(sel, 'size'), 10) > 1);
  // The option a drop-down shows: the last one selected, else its first
  // enabled one.
  function __ptSelChosen(sel) {
    let last = null, first = null;
    for (const o of __ptSelOptions(sel)) {
      if (__ptOptOn(o)) last = o;
      else if (!first && __ptOptEnabled(o)) first = o;
    }
    return last || first;
  }
  // Inserting into a drop-down with nothing selected selects its first
  // enabled option, and that choice stays when options go in before it.
  function __ptSelReset(node) {
    const sel = node.__ptTag === 'OPTGROUP' ? node.__ptParent : node;
    if (!sel || sel.__ptTag !== 'SELECT' || !__ptDropDown(sel)) return;
    let first = null;
    for (const o of __ptSelOptions(sel)) {
      if (__ptOptOn(o)) return;
      if (!first && __ptOptEnabled(o)) first = o;
    }
    if (first) first.__ptSelected = true;
  }
  const __ptAdd = Node.prototype.appendChild;
  const __ptDrop = Node.prototype.removeChild;
  const __ptSetAttr = Element.prototype.setAttribute;
  const __ptAttachShadow = Element.prototype.attachShadow;
  const __ptCloneNode = Node.prototype.cloneNode;
  // Internal attribute access. Reflecting properties (`el.src`, `el.id`,
  // `style.color`, `classList`) do not call `getAttribute`/`setAttribute` in
  // Chrome; it is native work a page hook does not see.
  const __ptAttrGet = Element.prototype.getAttribute;
  const __ptAttrSet = Element.prototype.setAttribute;
  const __ptAttrHas = Element.prototype.hasAttribute;
  const __ptAttrDel = Element.prototype.removeAttribute;
  const __ptGetA = (el, n) => __ptAttrGet.call(el, n);
  const __ptSetA = (el, n, v) => __ptAttrSet.call(el, n, v);
  const __ptHasA = (el, n) => __ptAttrHas.call(el, n);
  const __ptDelA = (el, n) => __ptAttrDel.call(el, n);

  // A canvas for the engine's own use. Neither the page's
  // `document.createElement` nor `getContext` is involved: fingerprinters wrap
  // them and would see internal calls (`createImageBitmap`, WebGPU over GL)
  // that Chrome does not make.
  globalThis.__pt_privateCanvas = (w, h) => {
    const orig = globalThis.__pt_canvasOrig;
    let c = null;
    if (globalThis.document) {
      c = (orig && orig.createElement)
        ? orig.createElement.call(globalThis.document, 'canvas')
        : globalThis.document.createElement('canvas');
    } else {
      // The stand-in inherits the element prototype: its methods check the brand.
      const proto = globalThis.__pt_canvasProto;
      c = Object.create(proto || null);
      Object.defineProperty(c, 'localName', { value: 'canvas', writable: true, configurable: true });
      Object.defineProperty(c, 'width', { value: w | 0, writable: true, configurable: true });
      Object.defineProperty(c, 'height', { value: h | 0, writable: true, configurable: true });
    }
    if (c) { c.width = w | 0; c.height = h | 0; }
    return c;
  };
  globalThis.__pt_privateCtx = (c, type, attrs) => {
    if (!c) return null;
    const orig = globalThis.__pt_canvasOrig;
    const get = (orig && orig.getContext) || c.getContext;
    return get ? get.call(c, type, attrs) : null;
  };

  // Transfer to a worker: the method itself is installed later by the stealth
  // layer; the interface shape table would overwrite it with a stub here.
  globalThis.__pt_makeTransferred = (canvas) => {
    const off = Object.create(OffscreenCanvas.prototype);
    Object.defineProperty(off, '__ptO', {
      value: { c: canvas, w: canvas.width | 0, h: canvas.height | 0 },
    });
    return off;
  };

  globalThis.Worker = Worker;
  globalThis.SharedWorker = SharedWorker;
  globalThis.OffscreenCanvas = OffscreenCanvas;

  // ---- helpers: classList, dataset, style -----------------------------------
  function makeClassList(el, attr) {
    const name = attr || 'class';
    const get = () => __s_split(__ptGetA(el, name) || '', /\s+/).filter(Boolean);
    const set = (arr) => __ptSetA(el, name, arr.join(' '));
    // A real `DOMTokenList`, not a literal: iterable, indexable, named
    // (`[...el.classList]` is common).
    const proto = (globalThis.DOMTokenList && globalThis.DOMTokenList.prototype) || Object.prototype;
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'DOMTokenList', configurable: true });
      }
    } catch (e) {}
    const api = Object.create(proto);
    Object.assign(api, {
      contains: (c) => __s_includes(get(), c),
      add: (...cs) => { const s = get(); for (const c of cs) if (!__s_includes(s, c)) s.push(c); set(s); },
      remove: (...cs) => set(get().filter(c => !__s_includes(cs, c))),
      toggle: (c, force) => { const s = get(); const has = __s_includes(s, c);
        if (force === true || (force === undefined && !has)) { if (!has) s.push(c); set(s); return true; }
        set(s.filter(x => x !== c)); return false; },
      replace: (a, b) => { const s = get(); const i = __s_indexOf(s, a); if (i < 0) return false; s[i] = b; set(s); return true; },
      supports: () => true,
      item: (i) => get()[i] || null,
      forEach(fn, self) { get().forEach((v, i) => fn.call(self, v, i, api)); },
      entries() { return get().entries(); },
      keys() { return get().keys(); },
      values() { return get().values(); },
      toString: () => get().join(' '),
      [Symbol.iterator]() { return get()[Symbol.iterator](); },
    });
    Object.defineProperty(api, 'length', { get: () => get().length, configurable: true });
    Object.defineProperty(api, 'value', {
      get: () => get().join(' '), set: (v) => __ptSetA(el, name, String(v)), configurable: true,
    });
    // Live indexed keys: the list is read from the attribute on every access.
    return __ptProxy(api, {
      get(t, k, r) {
        if (typeof k === 'string' && /^\d+$/.test(k)) return get()[+k];
        return Reflect.get(t, k, r);
      },
      has(t, k) {
        if (typeof k === 'string' && /^\d+$/.test(k)) return +k < get().length;
        return Reflect.has(t, k);
      },
      ownKeys(t) {
        return get().map((_, i) => String(i)).concat(Reflect.ownKeys(t).filter((k) => typeof k !== 'string' || !/^\d+$/.test(k)));
      },
      getOwnPropertyDescriptor(t, k) {
        if (typeof k === 'string' && /^\d+$/.test(k)) {
          const v = get()[+k];
          return v === undefined ? undefined : { value: v, enumerable: true, configurable: true, writable: false };
        }
        return Reflect.getOwnPropertyDescriptor(t, k);
      },
    });
  }
  // ---- CSSOM ---------------------------------------------------------------
  // Real stylesheets: Cloudflare's collector reads `document.styleSheets`
  // hundreds of times early in stage two (rules, selectors, cssText).
  // Interface shapes and serialization from Chrome 148.
  //
  // Values are normalised where Chrome visibly does: `0` in a length property
  // becomes `0px`, selector combinators get spaces, a space follows the colon
  // in an @media condition.
  const CSS_LENGTH_PROPS = new Set([
    'width', 'height', 'min-width', 'min-height', 'max-width', 'max-height',
    'top', 'right', 'bottom', 'left', 'margin', 'margin-top', 'margin-right',
    'margin-bottom', 'margin-left', 'padding', 'padding-top', 'padding-right',
    'padding-bottom', 'padding-left', 'border-width', 'border-top-width',
    'border-right-width', 'border-bottom-width', 'border-left-width',
    'border-radius', 'font-size', 'letter-spacing', 'word-spacing', 'text-indent',
    'outline-width', 'column-gap', 'row-gap', 'gap', 'inset', 'border-spacing',
    'border', 'outline',
  ]);
  // Colours are not kept as written: `#f2f2f2` in cssText comes back as
  // `rgb(242, 242, 242)`. Checked against the Cloudflare widget stylesheet
  // (73 of 183 rules differed only by this).
  const __cssHex = (v) => __s_replace(v, /#([0-9a-fA-F]{3,8})\b/g, (m, h) => {
    const wide = h.length > 4;
    if (h.length !== 3 && h.length !== 4 && h.length !== 6 && h.length !== 8) return m;
    const at = (i) => wide ? parseInt(__s_slice(h, i * 2, i * 2 + 2), 16)
                           : parseInt(h[i] + h[i], 16);
    const [r, g, b] = [at(0), at(1), at(2)];
    if (h.length === 4 || h.length === 8) return __cssRgb(r, g, b, at(3));
    return 'rgb(' + r + ', ' + g + ', ' + b + ')';
  });
  // A colour as Chrome serializes a legacy one: `rgb(r, g, b)`, or `rgba(…)`
  // with the alpha byte in the fewest decimals that give it back (221 is
  // 0.867, 128 is 0.5).
  const __cssAlpha = (byte) => {
    const a2 = Math.round(byte / 255 * 100) / 100;
    return Math.round(a2 * 255) === byte ? a2 : Math.round(byte / 255 * 1000) / 1000;
  };
  const __cssRgb = (r, g, b, alphaByte) => (alphaByte == null || alphaByte === 255
    ? 'rgb(' + r + ', ' + g + ', ' + b + ')'
    : 'rgba(' + r + ', ' + g + ', ' + b + ', ' + __cssAlpha(alphaByte) + ')');
  // `rgb()`, `rgba()`, `hsl()`, `hsla()` in either syntax (commas, or spaces
  // and a slash) to that form; anything it cannot read stays as written.
  const __CSS_COLOR_FN = /\b(rgba?|hsla?)\(\s*([^()]*?)\s*\)/gi;
  const __cssColorFn = (v) => __s_replace(v, __CSS_COLOR_FN, (m, fn, args) => {
    const f = __s_toLowerCase(fn);
    let parts, alpha = null;
    if (__s_indexOf(args, ',') >= 0) {
      parts = __s_split(args, ',').map((x) => __s_trim(x));
      if (parts.length === 4) alpha = parts.pop();
    } else {
      const [main, a] = __s_split(args, '/').map((x) => __s_trim(x));
      parts = __s_split(main, /\s+/).filter(Boolean);
      if (a !== undefined) alpha = a;
    }
    if (parts.length !== 3) return m;
    const num = (x) => (/^-?(\d+\.?\d*|\.\d+)(e-?\d+)?%?$/i.test(x) ? parseFloat(x) : NaN);
    const clamp = (x) => Math.min(255, Math.max(0, Math.round(x)));
    let rgb;
    if (f[0] === 'r') {
      rgb = parts.map((x) => { const n = num(x); return __s_endsWith(x, '%') ? clamp(n * 2.55) : clamp(n); });
    } else {
      const hm = /^(-?[\d.]+)(deg|rad|grad|turn)?$/i.exec(parts[0]);
      if (!hm || !__s_endsWith(parts[1], '%') || !__s_endsWith(parts[2], '%')) return m;
      let h = parseFloat(hm[1]);
      const unit = __s_toLowerCase(hm[2] || 'deg');
      if (unit === 'rad') h = h * 180 / Math.PI; else if (unit === 'grad') h = h * 0.9; else if (unit === 'turn') h *= 360;
      h = ((h % 360) + 360) % 360;
      const sat = Math.min(1, Math.max(0, num(parts[1]) / 100)), lig = Math.min(1, Math.max(0, num(parts[2]) / 100));
      const k = (n) => (n + h / 30) % 12;
      const a = sat * Math.min(lig, 1 - lig);
      const ch = (n) => lig - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1));
      rgb = [ch(0), ch(8), ch(4)].map((x) => clamp(x * 255));
    }
    if (rgb.some((x) => Number.isNaN(x))) return m;
    let byte = 255;
    if (alpha != null) {
      const an = num(alpha);
      if (Number.isNaN(an)) return m;
      byte = Math.round(Math.min(1, Math.max(0, __s_endsWith(alpha, '%') ? an / 100 : an)) * 255);
    }
    return __cssRgb(rgb[0], rgb[1], rgb[2], byte);
  });
  // `.9` prints as `0.9`, inside functions too:
  // `cubic-bezier(.55, .085, …)` -> `cubic-bezier(0.55, 0.085, …)`.
  const __cssZero = (v) => __s_replace(v, /(^|[\s(,])(-?)\.(\d)/g, '$1$20.$3');

  // The `animation` shorthand is split into eight parts and always printed in
  // full, in spec order, with initial values filled in:
  // `spin 5s linear infinite` -> `5s linear 0s infinite normal none running spin`.
  const ANIM_TIMING = new Set(['ease', 'linear', 'ease-in', 'ease-out', 'ease-in-out',
                               'step-start', 'step-end']);
  const ANIM_DIR = new Set(['normal', 'reverse', 'alternate', 'alternate-reverse']);
  const ANIM_FILL = new Set(['none', 'forwards', 'backwards', 'both']);
  const ANIM_STATE = new Set(['running', 'paused']);
  const __cssTokens = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const c of v) {
      if (c === '(') depth++;
      else if (c === ')') depth--;
      if (/\s/.test(c) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
      cur += c;
    }
    if (cur) out.push(cur);
    return out;
  };
  const __cssAnimation = (v) => __s_split(v, ',').map((part) => {
    // Commas inside `cubic-bezier(…)` do not split the list; rejoin.
    return part;
  }).reduce((acc, part) => {
    const prev = acc[acc.length - 1];
    if (prev !== undefined && (__s_split(prev, '(').length !== __s_split(prev, ')').length)) {
      acc[acc.length - 1] = prev + ',' + part;
    } else acc.push(part);
    return acc;
  }, []).map((one) => {
    const t = __cssTokens(__s_trim(one));
    let dur = null, timing = null, delay = null, count = null;
    let dir = null, fill = null, state = null, name = null;
    for (const tok of t) {
      const low = __s_toLowerCase(tok);
      if (/^-?[\d.]+m?s$/.test(low)) { if (dur === null) dur = low; else if (delay === null) delay = low; continue; }
      if (timing === null && (ANIM_TIMING.has(low) || /^(cubic-bezier|steps|linear)\(/.test(low))) { timing = tok; continue; }
      if (count === null && (low === 'infinite' || /^[\d.]+$/.test(low))) { count = low; continue; }
      if (dir === null && ANIM_DIR.has(low)) { dir = low; continue; }
      if (fill === null && ANIM_FILL.has(low)) { fill = low; continue; }
      if (state === null && ANIM_STATE.has(low)) { state = low; continue; }
      if (name === null) name = tok;
    }
    // The initial duration is `auto`, not 0s: `animation: none` prints as
    // `auto ease 0s 1 normal none running none`.
    return [dur || 'auto', timing || 'ease', delay || '0s', count || '1',
            dir || 'normal', fill || 'none', state || 'running', name || 'none'].join(' ');
  }).join(', ');

  // Shadow serialization: colour first, then four lengths with units, `inset`
  // last, however the author wrote it.
  // Split a list on top-level commas (commas inside `rgb(…)` do not split).
  const __cssCommaParts = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const c of String(v)) {
      if (c === '(') depth++;
      else if (c === ')') depth--;
      if (c === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
      cur += c;
    }
    out.push(cur);
    return out;
  };

  const __cssShadow = (v) => __cssCommaParts(v).map((one) => {
    const parts = __ptCssParts(__s_trim(one));
    let colour = null, inset = false;
    const lens = [];
    for (const t of parts) {
      if (/^inset$/i.test(t)) { inset = true; continue; }
      if (/^[-\d.]/.test(t)) { lens.push(/^[-\d.]+$/.test(t) ? t + 'px' : t); continue; }
      colour = t;
    }
    if (!lens.length) return __s_trim(one);
    // Length count as written: `1px 2px` gets no blur added. A colour keyword
    // stays a keyword (`red`), but function notation is normalised:
    // `rgba(0,0,0,.1)` becomes `rgba(0, 0, 0, 0.1)`.
    const norm = colour && /^(rgba?|hsla?|hwb|color|lab|lch|oklab|oklch)\(/i.test(colour)
      && globalThis.__pt_cssColour ? globalThis.__pt_cssColour(colour) : colour;
    const out = [norm || colour || 'currentcolor', ...lens];
    if (inset) out.push('inset');
    return out.join(' ');
  }).join(', ');

  // Outline: colour, style, width, in that order.
  const __cssOutline = (v) => {
    const parts = __ptCssParts(__s_trim(v));
    let colour = null, style = null, width = null;
    for (const t of parts) {
      const low = __s_toLowerCase(t);
      if (CS_BORDER_STYLES.has(low)) { style = low; continue; }
      if (/^[-\d.]/.test(t) || CS_WIDTH_WORDS[low]) { width = /^[-\d.]+$/.test(t) ? t + 'px' : t; continue; }
      colour = t;
    }
    if (!style && !width) return v;
    return [colour || 'currentcolor', style || 'none', width || 'medium'].join(' ');
  };

  // Zeros inside transforms get units: `rotate(0)` prints as `rotate(0deg)`,
  // `translateY(0)` as `translateY(0px)`.
  const __cssTransform = (v) => __s_replace(v, /([a-zA-Z]+)\(([^()]*)\)/g, (m, fn, args) => {
    const low = __s_toLowerCase(fn);
    const unit = /^(rotate|rotatex|rotatey|rotatez|rotate3d|skew|skewx|skewy)$/.test(low) ? 'deg'
      : /^(translate|translatex|translatey|translatez|translate3d|perspective)$/.test(low) ? 'px'
      : null;
    if (!unit) return m;
    const out = __s_split(args, ',').map((a, i) => {
      const t = __s_trim(a);
      if (!/^-?\d+(?:\.\d+)?$/.test(t)) return t;
      // The first three numbers of `rotate3d` are the axis, unitless.
      if (low === 'rotate3d' && i < 3) return t;
      if (low === 'translate3d' && i === 2) return t + 'px';
      return t + unit;
    });
    return fn + '(' + out.join(', ') + ')';
  });

  /// Family list as Chrome prints it: names with spaces in double quotes,
  /// single quotes turned to double, the rest as is.
  const __cssFamilies = (v) => __cssCommaParts(v).map((one) => {
    const t = __s_trim(one);
    if (!t) return t;
    const q = t[0];
    if (q === '"' || q === "'") {
      const inner = __s_slice(t, 1, t.length - (t[t.length - 1] === q ? 1 : 0));
      return '"' + inner + '"';
    }
    return /\s/.test(t) ? '"' + t + '"' : t;
  }).join(', ');

  // Property names: built-ins are case-insensitive, custom ones (`--*`) are
  // not (`var(--Wide)` must find `--Wide`).
  const __cssKey = (p) => {
    const s = __s_trim(String(p));
    return __s_charCodeAt(s, 0) === 45 && __s_charCodeAt(s, 1) === 45 ? s : __s_toLowerCase(s);
  };
  // Numbers in values print with six significant digits: `scale(1.000998)`
  // becomes `scale(1.001)`, `138.828125px` becomes `138.828px`. Quoted strings,
  // URLs and digits inside words (`translate3d`, `#ff8800`) are untouched.
  const __cssNum1 = (t) => {
    const n = Number(t);
    if (!isFinite(n)) return t;
    return String(Number(n.toPrecision(6)));
  };
  // Transform as a matrix: `scale(1.000998)` -> [a, b, c, d, e, f].
  const __parseTransform = (str) => {
    const src = __s_trim(String(str || ''));
    if (!src || src === 'none') return null;
    let M = [1, 0, 0, 1, 0, 0];
    let any = false;
    const mul = (n) => {
      const [a, b, c, d, e, f] = M; const [a2, b2, c2, d2, e2, f2] = n;
      M = [a * a2 + c * b2, b * a2 + d * b2, a * c2 + c * d2, b * c2 + d * d2, a * e2 + c * f2 + e, b * e2 + d * f2 + f];
    };
    const re = /([a-zA-Z0-9]+)\s*\(([^)]*)\)/g;
    let m;
    while ((m = re.exec(src))) {
      const fn = __s_toLowerCase(m[1]);
      const v = __s_split(m[2], /[\s,]+/).filter(Boolean).map((x) => parseFloat(x));
      if (v.some((x) => !isFinite(x))) return null;
      any = true;
      const rad = (x) => (x || 0) * Math.PI / 180;
      switch (fn) {
        case 'matrix': if (v.length !== 6) return null; mul(v); break;
        case 'scale': mul([v[0], 0, 0, v.length > 1 ? v[1] : v[0], 0, 0]); break;
        case 'scalex': mul([v[0], 0, 0, 1, 0, 0]); break;
        case 'scaley': mul([1, 0, 0, v[0], 0, 0]); break;
        case 'scale3d': mul([v[0], 0, 0, v[1], 0, 0]); break;
        case 'translate': mul([1, 0, 0, 1, v[0] || 0, v[1] || 0]); break;
        case 'translatex': mul([1, 0, 0, 1, v[0] || 0, 0]); break;
        case 'translatey': mul([1, 0, 0, 1, 0, v[0] || 0]); break;
        case 'translate3d': mul([1, 0, 0, 1, v[0] || 0, v[1] || 0]); break;
        case 'rotate': { const c = Math.cos(rad(v[0])), sn = Math.sin(rad(v[0])); mul([c, sn, -sn, c, 0, 0]); break; }
        case 'skewx': mul([1, 0, Math.tan(rad(v[0])), 1, 0, 0]); break;
        case 'skewy': mul([1, Math.tan(rad(v[0])), 0, 1, 0, 0]); break;
        default: return null;
      }
    }
    return any ? M : null;
  };
  const __cssNumbers = (v) => __s_replace(v, /("[^"]*"|'[^']*'|url\([^)]*\))|(?<![A-Za-z0-9_#.\-])([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)(?=[A-Za-z%]*(?![A-Za-z0-9_.#\-]))/g,
    (m, q, num) => (q ? q : __cssNum1(num)));
  const __cssValue = (prop, value) => {
    const r = __cssValueRaw(prop, value);
    if ((__s_charCodeAt(prop, 0) === 45 && __s_charCodeAt(prop, 1) === 45) || prop === 'unicode-range') return r;
    try { return __cssNumbers(r); } catch (e) { return r; }
  };
  const __CSS_COLOR_PROP = /(^|-)(color|fill|stroke|background|border|outline|shadow|column-rule|text-decoration|caret|accent)(-|$)/;
  const __CSS_NAMED_COLORS = new Set(['aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black',
    'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate', 'coral',
    'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod', 'darkgray', 'darkgreen',
    'darkgrey', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid', 'darkred', 'darksalmon',
    'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet', 'deeppink',
    'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen', 'fuchsia', 'gainsboro',
    'ghostwhite', 'gold', 'goldenrod', 'gray', 'green', 'greenyellow', 'grey', 'honeydew', 'hotpink', 'indianred', 'indigo',
    'ivory', 'khaki', 'lavender', 'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan',
    'lightgoldenrodyellow', 'lightgray', 'lightgreen', 'lightgrey', 'lightpink', 'lightsalmon', 'lightseagreen',
    'lightskyblue', 'lightslategray', 'lightslategrey', 'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen',
    'magenta', 'maroon', 'mediumaquamarine', 'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen',
    'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred', 'midnightblue', 'mintcream',
    'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive', 'olivedrab', 'orange', 'orangered', 'orchid',
    'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred', 'papayawhip', 'peachpuff', 'peru', 'pink', 'plum',
    'powderblue', 'purple', 'rebeccapurple', 'red', 'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown',
    'seagreen', 'seashell', 'sienna', 'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen',
    'steelblue', 'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow',
    'yellowgreen']);
  // A family list as Chrome writes it: a name that is one identifier bare, any
  // other name quoted (words, a leading digit, a quoted keyword such as
  // "serif"), strings kept as they are inside.
  const __FONT_KEYWORDS = new Set(['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui', 'emoji', 'math',
    'fangsong', 'ui-serif', 'ui-sans-serif', 'ui-monospace', 'ui-rounded', 'inherit', 'initial', 'unset', 'revert',
    'revert-layer', 'default']);
  const __cssFontFamily = (value) => {
    const out = [];
    let i = 0;
    const v = String(value);
    while (i < v.length) {
      while (i < v.length && /[\s,]/.test(v[i])) i++;
      if (i >= v.length) break;
      let name = '', quoted = false;
      if (v[i] === '"' || v[i] === "'") {
        const q = v[i++];
        quoted = true;
        while (i < v.length && v[i] !== q) { if (v[i] === '\\' && i + 1 < v.length) i++; name += v[i++]; }
        i++;
        while (i < v.length && v[i] !== ',') i++;
      } else {
        const start = i;
        while (i < v.length && v[i] !== ',') i++;
        name = __s_replace(__s_trim(__s_slice(v, start, i)), /\s+/g, ' ');
      }
      const ident = /^-?[_a-zA-Z\u0080-\uffff][_a-zA-Z0-9\u0080-\uffff-]*$/.test(name);
      const keep = quoted && __FONT_KEYWORDS.has(__s_toLowerCase(name));
      out.push(ident && !keep ? name : '"' + __s_replace(name, /["\\]/g, '\\$&') + '"');
    }
    return out.join(', ');
  };
  const __cssValueRaw = (prop, value) => {
    // Custom property values are stored as written.
    if (__s_charCodeAt(prop, 0) === 45 && __s_charCodeAt(prop, 1) === 45) return __s_trim(String(value));
    if (prop === 'font-family' && __s_indexOf(String(value), 'var(') < 0) return __cssFontFamily(value);
    let v = __cssZero(__cssColorFn(__cssHex(__s_replace(__s_trim(String(value)), /\s+/g, ' '))));
    // `url(x)` prints quoted, as Chrome serializes it.
    if (__s_indexOf(v, 'url(') >= 0) v = __s_replace(v, __CSS_URL_ANY, (m, a, b, c) => 'url("' + __s_replace(a !== undefined ? a : b !== undefined ? b : c, /["\\]/g, '\\$&') + '")');
    // A font source list: `format()` and `local()` take strings.
    if (prop === 'src') {
      v = __s_replace(v, /\b(format|tech)\(\s*'([^']*)'\s*\)/gi, (m, f, x) => f + '("' + x + '")');
      v = __s_replace(v, /\blocal\(\s*(?:'([^']*)'|"([^"]*)"|([^)]*?))\s*\)/gi, (m, a, b, c) => 'local("' + __s_trim(a !== undefined ? a : b !== undefined ? b : c) + '")');
      v = __s_replace(v, /\s*,\s*/g, ', ');
    }
    // Colour keywords print in lower case in properties that take a colour
    // (a font family named `Red` keeps its case).
    if (__CSS_COLOR_PROP.test(prop)) {
      v = __s_replace(v, /(^|[\s,(])([A-Za-z]+)(?=$|[\s,)])/g, (m, pre, w) => {
        const low = __s_toLowerCase(w);
        return low !== w && (low === 'currentcolor' || low === 'transparent' || __CSS_NAMED_COLORS.has(low)) ? pre + low : m;
      });
    }
    if (prop === 'animation') return __cssAnimation(v);
    if (prop === 'box-shadow' || prop === 'text-shadow') return __cssShadow(v);
    if (prop === 'outline') return __cssOutline(v);
    if (prop === 'transform') return __cssTransform(v);
    // A slash in grid shorthands prints with spaces around it.
    if (prop === 'grid-area' || prop === 'grid-row' || prop === 'grid-column') {
      return __s_replace(v, /\s*\/\s*/g, ' / ');
    }
    // A single-keyword transform-origin gets a second value.
    if (prop === 'transform-origin' && /^[a-z%\d.-]+$/i.test(v) && !/\s/.test(v)) {
      return v + ' center';
    }
    // A comma list prints with a space after each comma.
    if (prop === 'stroke-dasharray') return __s_replace(v, /\s*,\s*/g, ', ');
    // The initial `transition-property` is not printed.
    if (prop === 'transition') return __s_replace(v, /^all\s+/i, '');
    // Background prints in its own order: image first, colour last; a bare
    // URL gets quoted.
    if (prop === 'background') {
      const parts = __ptCssParts(v);
      const image = [], rest = [];
      let colour = null;
      for (const t of parts) {
        if (/^url\(/i.test(t)) {
          image.push(__s_replace(t, /^url\(\s*(['"]?)(.*?)\1\s*\)$/i, (m, q, u) => 'url("' + u + '")'));
        } else if (/^(linear-gradient|radial-gradient|conic-gradient|image-set|-webkit-)/i.test(t)) image.push(t);
        else if (__ptIsColour(t)) colour = t;
        else rest.push(t);
      }
      if (!image.length && !colour) return v;
      return [...image, ...rest, ...(colour ? [colour] : [])].join(' ');
    }
    // In the font shorthand the slash gets spaces, and the family list follows
    // the same rules as the longhand.
    if (prop === 'font') {
      const spaced = __s_replace(v, /\s*\/\s*/g, ' / ');
      const at = __s_search(spaced, /(?:^|\s)(?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large)(?:\s*\/\s*\S+)?\s+/);
      if (at < 0) return spaced;
      const m = /(?:^|\s)(?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large)(?:\s*\/\s*\S+)?\s+/.exec(spaced);
      const head = __s_slice(spaced, 0, m.index + m[0].length);
      return head + __cssFamilies(__s_slice(spaced, m.index + m[0].length));
    }
    // Family list: space after commas, multi-word names in double quotes
    // (single quotes become double).
    if (prop === 'font-family') return __cssFamilies(v);
    // Shorthand parts equal to their initial value are not printed:
    // `flex-flow: column nowrap` comes back as `column`.
    if (prop === 'flex-flow') v = __s_replace(v, /\s+nowrap$/, '');
    if (!CSS_LENGTH_PROPS.has(prop)) return v;
    // Top level only: a bare 0 in `border: 0` is a length, but the 3 in
    // `rgb(178, 15, 3)` is not, and adding `px` breaks the colour.
    let depth = 0, out = '', tok = '';
    const flush = () => {
      if (tok && depth === 0 && /^-?\d+(?:\.\d+)?$/.test(tok)) out += tok + 'px';
      else out += tok;
      tok = '';
    };
    for (const c of v) {
      if (c === '(') { flush(); depth++; out += c; continue; }
      if (c === ')') { tok += c; out += tok; tok = ''; depth--; continue; }
      if (/\s/.test(c) && depth === 0) { flush(); out += c; continue; }
      tok += c;
    }
    flush();
    // A box shorthand prints as few values as say the same.
    if (__CSS_BOX.has(prop) && __s_indexOf(out, '(') < 0) {
      const p4 = __s_split(__s_trim(out), ' ');
      if (p4.length >= 2 && p4.length <= 4) {
        const t = p4[0], r = p4[1], b = p4[2] !== undefined ? p4[2] : t, l = p4[3] !== undefined ? p4[3] : r;
        out = l !== r ? [t, r, b, l].join(' ') : b !== t ? [t, r, b].join(' ') : r !== t ? [t, r].join(' ') : t;
      }
    }
    return out;
  };
  const __CSS_URL_ANY = /url\(\s*(?:'([^']*)'|"([^"]*)"|([^)"'\s]*))\s*\)/gi;
  const __CSS_BOX = new Set(['margin', 'padding', 'inset', 'border-width', 'scroll-margin', 'scroll-padding']);
  // A selector list as Chrome prints it (CSSOM "serialize a selector"):
  // names re-escaped, attribute values as double-quoted strings, An+B in
  // its shortest form, pseudo names lowercased, `:before` as `::before`, a
  // universal selector dropped where other simple selectors follow. With
  // `display`, type and attribute names are lowercased too (an HTML
  // document's `selectorText`); the cascade keeps their case for SVG names.
  // The regex version this replaces spaced `~=` like a combinator, and the
  // rule then had no key and restyled the whole page when added.
  const __SEL_LIST_ARGS = new Set(['is', 'not', 'where', 'has', 'matches', '-webkit-any', 'host', 'host-context', 'slotted', 'cue']);
  function __cssIdentOut(v) {
    let out = '';
    for (let k = 0; k < v.length; k++) {
      const c = __s_charCodeAt(v, k), ch = v[k];
      if (c === 0) out += '�';
      else if ((c >= 1 && c <= 0x1f) || c === 0x7f || (c >= 48 && c <= 57 && (k === 0 || (k === 1 && v[0] === '-')))) out += '\\' + c.toString(16) + ' ';
      else if (k === 0 && ch === '-' && v.length === 1) out += '\\-';
      else if (c >= 0x80 || ch === '-' || ch === '_' || (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122)) out += ch;
      else out += '\\' + ch;
    }
    return out;
  }
  function __cssStringOut(v) {
    let out = '"';
    for (let k = 0; k < v.length; k++) {
      const c = __s_charCodeAt(v, k), ch = v[k];
      if (c === 0) out += '�';
      else if ((c >= 1 && c <= 0x1f) || c === 0x7f) out += '\\' + c.toString(16) + ' ';
      else if (ch === '"' || ch === '\\') out += '\\' + ch;
      else out += ch;
    }
    return out + '"';
  }
  const __nthOut = (ab) => {
    const [a, b] = ab;
    if (a === 0) return String(b);
    const an = a === 1 ? 'n' : a === -1 ? '-n' : a + 'n';
    return b > 0 ? an + '+' + b : b < 0 ? an + String(b) : an;
  };
  // Comments go (outside strings) and U+0000 reads as U+FFFD, as the CSS
  // tokenizer has it.
  const __selPre = (t) => {
    if (__s_indexOf(t, '/*') < 0 && __s_indexOf(t, '\0') < 0) return t;
    return __s_replace(t, /("(?:[^"\\]|\\[\s\S])*"?|'(?:[^'\\]|\\[\s\S])*'?)|\/\*[\s\S]*?(?:\*\/|$)|\0/g,
      (m, str) => (str !== undefined ? __s_replace(str, /\0/g, '\ufffd') : m === '\0' ? '\ufffd' : ''));
  };
  function __selSerialize(text, display) {
    const s = __selPre(String(text)), n = s.length;
    let i = 0;
    const ws = (c) => c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f';
    const skipWs = () => { while (i < n && ws(s[i])) i++; };
    const nameStart = (k) => {
      const c = s[k];
      if (c === undefined) return false;
      if (c === '\\') return s[k + 1] !== undefined && s[k + 1] !== '\n';
      return __s_charCodeAt(s, k) >= 0x80 || c === '-' || c === '_' || /[a-zA-Z0-9]/.test(c);
    };
    const escape = () => {
      // At a backslash: the escaped code point.
      i++;
      if (i >= n) return '�';
      let hex = '';
      while (hex.length < 6 && i < n && /[0-9a-fA-F]/.test(s[i])) hex += s[i++];
      if (hex) {
        if (i < n && ws(s[i])) { if (s[i] === '\r' && s[i + 1] === '\n') i++; i++; }
        const c = parseInt(hex, 16);
        return c === 0 || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) ? '�' : String.fromCodePoint(c);
      }
      return s[i++];
    };
    const ident = () => {
      let v = '';
      while (i < n && nameStart(i)) v += s[i] === '\\' ? escape() : s[i++];
      return v;
    };
    const string = () => {
      const q = s[i++];
      let v = '';
      while (i < n && s[i] !== q) {
        if (s[i] === '\\') { if (s[i + 1] === '\n') { i += 2; continue; } v += escape(); } else v += s[i++];
      }
      i++;
      return v;
    };
    // Up to the `)` closing the current function, nesting and strings kept.
    const rawArg = () => {
      const start = i;
      let depth = 0;
      while (i < n) {
        const c = s[i];
        if (c === '\\') { i += 2; continue; }
        if (c === '"' || c === "'") { string(); continue; }
        if (c === '(') depth++;
        else if (c === ')') { if (depth === 0) break; depth--; }
        i++;
      }
      return __s_slice(s, start, i);
    };
    const lowName = (v) => (display ? __s_toLowerCase(v) : v);
    const attr = () => {
      i++;
      skipWs();
      let ns = '', name;
      if (s[i] === '*' && s[i + 1] === '|') { ns = '*|'; i += 2; name = ident(); }
      else if (s[i] === '|') { i++; name = ident(); }
      else {
        name = ident();
        if (s[i] === '|' && s[i + 1] !== '=') { ns = __cssIdentOut(name) + '|'; i++; name = ident(); }
      }
      skipWs();
      let op = '';
      if (s[i] === '=') { op = '='; i++; }
      else if (s[i + 1] === '=' && '~|^$*'.includes(s[i])) { op = s[i] + '='; i += 2; }
      let out = '[' + ns + __cssIdentOut(lowName(name));
      if (op) {
        skipWs();
        const v = s[i] === '"' || s[i] === "'" ? string() : ident();
        skipWs();
        const flag = nameStart(i) ? __s_toLowerCase(ident()) : '';
        skipWs();
        out += op + __cssStringOut(v) + (flag ? ' ' + flag : '');
      }
      if (s[i] === ']') i++;
      return out + ']';
    };
    const pseudo = () => {
      i++;
      let el = false;
      if (s[i] === ':') { el = true; i++; }
      const low = __s_toLowerCase(ident());
      if (!el && __SEL_LEGACY_PE.has(low)) el = true;
      const pre = el ? '::' : ':';
      if (s[i] !== '(') return pre + low;
      i++;
      let inner;
      if (__SEL_LIST_ARGS.has(low)) { skipWs(); inner = list(true); }
      else {
        const raw = __s_trim(rawArg());
        inner = raw;
        if (/^nth-/.test(low)) {
          const m = /^(.*?)\s+of\s+(.*)$/.exec(raw);
          const ab = __nthParse(m ? m[1] : raw);
          if (ab) inner = __nthOut(ab) + (m ? ' of ' + __selSerialize(m[2], display) : '');
        }
      }
      if (s[i] === ')') i++;
      return pre + low + '(' + inner + ')';
    };
    const compound = () => {
      let type = null;
      if (s[i] === '*' || s[i] === '|' || nameStart(i)) {
        let first = s[i] === '*' ? (i++, '*') : s[i] === '|' ? null : ident();
        if (s[i] === '|' && s[i + 1] !== '=') {
          i++;
          const local = s[i] === '*' ? (i++, '*') : ident();
          const t = local === '*' ? '*' : __cssIdentOut(lowName(local));
          type = first === '*' ? t : (first === null ? '' : __cssIdentOut(first)) + '|' + t;
        } else type = first === '*' ? '*' : __cssIdentOut(lowName(first));
      }
      let rest = '';
      for (;;) {
        const c = s[i];
        if (c === '.') { i++; rest += '.' + __cssIdentOut(ident()); }
        else if (c === '#') { i++; rest += '#' + __cssIdentOut(ident()); }
        else if (c === '[') rest += attr();
        else if (c === ':') rest += pseudo();
        else if (c === '&') { i++; rest += '&'; }
        else break;
      }
      if (type === '*' && rest) type = '';
      return (type || '') + rest;
    };
    const complex = (inParens) => {
      let out = '', gap = false;
      while (i < n) {
        const c = s[i];
        if (c === ',' || (inParens && c === ')')) break;
        if (ws(c)) { i++; gap = true; continue; }
        if (c === '>' || c === '+' || c === '~') {
          i++;
          out = out ? out + ' ' + c + ' ' : c + ' ';
          gap = false;
          continue;
        }
        const start = i;
        const part = compound();
        if (i === start) { out += c; i++; continue; }
        if (gap && out && out[out.length - 1] !== ' ') out += ' ';
        gap = false;
        out += part;
      }
      return __s_trim(out);
    };
    const list = (inParens) => {
      const parts = [];
      for (;;) {
        skipWs();
        parts.push(complex(inParens));
        if (s[i] === ',') { i++; continue; }
        break;
      }
      return parts.join(', ');
    };
    try { return list(false); } catch (e) { return __s_trim(s); }
  }
  const __cssSelector = (sel) => __selSerialize(sel, false);
  const __cssPrelude = (p) => __s_replace(__s_replace(__s_trim(String(p)), /\s+/g, ' '), /:\s*/g, ': ');

  // Parsing: prelude up to `{` or `;`, then the body with nesting depth.
  // Strings and comments are skipped, or `content: "}"` splits the rule.
  // Whether a quote is escaped: count consecutive backslashes, not one.
  // `content:"\\"` is a one-backslash string and the quote after it closes it
  // (getting this wrong lost 760 of ~1000 chess.com rules).
  const __cssEscaped = (text, i) => {
    let n = 0;
    while (i - 1 - n >= 0 && text[i - 1 - n] === '\\') n++;
    return (n & 1) === 1;
  };

  function __cssParse(text) {
    const out = [];
    const n = text.length;
    let i = 0;
    while (i < n) {
      while (i < n && /\s/.test(text[i])) i++;
      if (i >= n) break;
      if (__s_startsWith(text, '/*', i)) { const e = __s_indexOf(text, '*/', i + 2); i = e < 0 ? n : e + 2; continue; }
      const start = i;
      let depth = 0, q = null;
      while (i < n) {
        const c = text[i];
        if (q) { if (c === q && !__cssEscaped(text, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (depth === 0 && (c === '{' || c === ';')) break;
        i++;
      }
      const prelude = __s_trim(__s_slice(text, start, i));
      if (i >= n) { if (prelude) out.push({ prelude, statement: true }); break; }
      if (text[i] === ';') { i++; if (prelude) out.push({ prelude, statement: true }); continue; }
      i++;                                    // past '{'
      const bodyStart = i;
      let d = 1;
      q = null;
      while (i < n && d > 0) {
        const c = text[i];
        if (q) { if (c === q && !__cssEscaped(text, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '{') d++;
        else if (c === '}') d--;
        i++;
      }
      out.push({ prelude, body: __s_slice(text, bodyStart, d === 0 ? i - 1 : i) });
    }
    return out;
  }

  function __cssDecls(body) {
    const map = new Map();
    let i = 0;
    const n = body.length;
    while (i < n) {
      const start = i;
      let depth = 0, q = null;
      while (i < n) {
        const c = body[i];
        if (q) { if (c === q && !__cssEscaped(body, i)) q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (c === ';' && depth === 0) break;
        i++;
      }
      const decl = __s_trim(__s_slice(body, start, i));
      i++;
      if (!decl) continue;
      const colon = __s_indexOf(decl, ':');
      if (colon <= 0) continue;
      const prop = __cssKey(__s_slice(decl, 0, colon));
      // A property written twice moves to the later position: Chrome removes
      // and re-appends on overwrite. `!important` is the declaration's
      // priority, not part of its value.
      if (prop) {
        let raw = __s_slice(decl, colon + 1);
        const im = /!\s*important\s*$/i.exec(raw);
        if (im) raw = __s_slice(raw, 0, im.index);
        // A later normal declaration does not undo an earlier important one.
        if (!im && map.__ptImp && map.__ptImp.has(prop)) continue;
        map.delete(prop);
        map.set(prop, __cssValue(prop, raw));
        if (im) __cssImp(map).add(prop);
        else if (map.__ptImp) map.__ptImp.delete(prop);
      }
    }
    return map;
  }

  // A rule's declaration block: the same interface as `el.style`, backed by
  // the rule's map instead of an element attribute.
  // CSS property names as Chrome 148 has them on every style declaration: own
  // properties, in this order. Every fingerprinter enumerates them; they
  // reveal the engine and version. Chrome dropped the -epub-* names; the
  // challenge enumerates computed style whole.
  const CSS_PROPS = ["accentColor","additiveSymbols","alignContent","alignItems","alignSelf","alignmentBaseline","all","anchorName","anchorScope","animation","animationComposition","animationDelay","animationDirection","animationDuration","animationFillMode","animationIterationCount","animationName","animationPlayState","animationRange","animationRangeEnd","animationRangeStart","animationTimeline","animationTimingFunction","animationTrigger","appRegion","appearance","ascentOverride","aspectRatio","backdropFilter","backfaceVisibility","background","backgroundAttachment","backgroundBlendMode","backgroundClip","backgroundColor","backgroundImage","backgroundOrigin","backgroundPosition","backgroundPositionX","backgroundPositionY","backgroundRepeat","backgroundSize","basePalette","baselineShift","baselineSource","blockSize","border","borderBlock","borderBlockColor","borderBlockEnd","borderBlockEndColor","borderBlockEndStyle","borderBlockEndWidth","borderBlockStart","borderBlockStartColor","borderBlockStartStyle","borderBlockStartWidth","borderBlockStyle","borderBlockWidth","borderBottom","borderBottomColor","borderBottomLeftRadius","borderBottomRightRadius","borderBottomStyle","borderBottomWidth","borderCollapse","borderColor","borderEndEndRadius","borderEndStartRadius","borderImage","borderImageOutset","borderImageRepeat","borderImageSlice","borderImageSource","borderImageWidth","borderInline","borderInlineColor","borderInlineEnd","borderInlineEndColor","borderInlineEndStyle","borderInlineEndWidth","borderInlineStart","borderInlineStartColor","borderInlineStartStyle","borderInlineStartWidth","borderInlineStyle","borderInlineWidth","borderLeft","borderLeftColor","borderLeftStyle","borderLeftWidth","borderRadius","borderRight","borderRightColor","borderRightStyle","borderRightWidth","borderShape","borderSpacing","borderStartEndRadius","borderStartStartRadius","borderStyle","borderTop","borderTopColor","borderTopLeftRadius","borderTopRightRadius","borderTopStyle","borderTopWidth","borderWidth","bottom","boxDecorationBreak","boxShadow","boxSizing","breakAfter","breakBefore","breakInside","bufferedRendering","captionSide","caretAnimation","caretColor","caretShape","clear","clip","clipPath","clipRule","color","colorInterpolation","colorInterpolationFilters","colorRendering","colorScheme","columnCount","columnFill","columnGap","columnHeight","columnRule","columnRuleBreak","columnRuleColor","columnRuleInset","columnRuleInsetCap","columnRuleInsetCapEnd","columnRuleInsetCapStart","columnRuleInsetEnd","columnRuleInsetJunction","columnRuleInsetJunctionEnd","columnRuleInsetJunctionStart","columnRuleInsetStart","columnRuleStyle","columnRuleVisibilityItems","columnRuleWidth","columnSpan","columnWidth","columnWrap","columns","contain","containIntrinsicBlockSize","containIntrinsicHeight","containIntrinsicInlineSize","containIntrinsicSize","containIntrinsicWidth","container","containerName","containerType","content","contentVisibility","cornerBlockEndShape","cornerBlockStartShape","cornerBottomLeftShape","cornerBottomRightShape","cornerBottomShape","cornerEndEndShape","cornerEndStartShape","cornerInlineEndShape","cornerInlineStartShape","cornerLeftShape","cornerRightShape","cornerShape","cornerStartEndShape","cornerStartStartShape","cornerTopLeftShape","cornerTopRightShape","cornerTopShape","counterIncrement","counterReset","counterSet","cursor","cx","cy","d","descentOverride","direction","display","dominantBaseline","dynamicRangeLimit","emptyCells","fallback","fieldSizing","fill","fillOpacity","fillRule","filter","flex","flexBasis","flexDirection","flexFlow","flexGrow","flexLineCount","flexShrink","flexWrap","float","floodColor","floodOpacity","font","fontDisplay","fontFamily","fontFeatureSettings","fontKerning","fontLanguageOverride","fontOpticalSizing","fontPalette","fontSize","fontSizeAdjust","fontStretch","fontStyle","fontSynthesis","fontSynthesisSmallCaps","fontSynthesisStyle","fontSynthesisWeight","fontVariant","fontVariantAlternates","fontVariantCaps","fontVariantEastAsian","fontVariantEmoji","fontVariantLigatures","fontVariantNumeric","fontVariantPosition","fontVariationSettings","fontWeight","forcedColorAdjust","gap","grid","gridArea","gridAutoColumns","gridAutoFlow","gridAutoRows","gridColumn","gridColumnEnd","gridColumnGap","gridColumnStart","gridGap","gridRow","gridRowEnd","gridRowGap","gridRowStart","gridTemplate","gridTemplateAreas","gridTemplateColumns","gridTemplateRows","height","hyphenateCharacter","hyphenateLimitChars","hyphens","imageOrientation","imageRendering","inherits","initialLetter","initialValue","inlineSize","inset","insetBlock","insetBlockEnd","insetBlockStart","insetInline","insetInlineEnd","insetInlineStart","interactivity","interestDelay","interestDelayEnd","interestDelayStart","interpolateSize","isolation","justifyContent","justifyItems","justifySelf","left","letterSpacing","lightingColor","lineBreak","lineGapOverride","lineHeight","listStyle","listStyleImage","listStylePosition","listStyleType","margin","marginBlock","marginBlockEnd","marginBlockStart","marginBottom","marginInline","marginInlineEnd","marginInlineStart","marginLeft","marginRight","marginTop","marker","markerEnd","markerMid","markerStart","mask","maskClip","maskComposite","maskImage","maskMode","maskOrigin","maskPosition","maskRepeat","maskSize","maskType","mathDepth","mathShift","mathStyle","maxBlockSize","maxHeight","maxInlineSize","maxWidth","minBlockSize","minHeight","minInlineSize","minWidth","mixBlendMode","navigation","negative","objectFit","objectPosition","objectViewBox","offset","offsetAnchor","offsetDistance","offsetPath","offsetPosition","offsetRotate","opacity","order","orphans","outline","outlineColor","outlineOffset","outlineStyle","outlineWidth","overflow","overflowAnchor","overflowBlock","overflowClipMargin","overflowInline","overflowWrap","overflowX","overflowY","overlay","overrideColors","overscrollBehavior","overscrollBehaviorBlock","overscrollBehaviorInline","overscrollBehaviorX","overscrollBehaviorY","pad","padding","paddingBlock","paddingBlockEnd","paddingBlockStart","paddingBottom","paddingInline","paddingInlineEnd","paddingInlineStart","paddingLeft","paddingRight","paddingTop","page","pageBreakAfter","pageBreakBefore","pageBreakInside","pageMarginSafety","pageOrientation","paintOrder","perspective","perspectiveOrigin","placeContent","placeItems","placeSelf","pointerEvents","position","positionAnchor","positionArea","positionTry","positionTryFallbacks","positionTryOrder","positionVisibility","prefix","printColorAdjust","quotes","r","range","readingFlow","readingOrder","resize","result","right","rotate","rowGap","rowRule","rowRuleBreak","rowRuleColor","rowRuleInset","rowRuleInsetCap","rowRuleInsetCapEnd","rowRuleInsetCapStart","rowRuleInsetEnd","rowRuleInsetJunction","rowRuleInsetJunctionEnd","rowRuleInsetJunctionStart","rowRuleInsetStart","rowRuleStyle","rowRuleVisibilityItems","rowRuleWidth","rubyAlign","rubyOverhang","rubyPosition","rule","ruleBreak","ruleColor","ruleInset","ruleInsetCap","ruleInsetEnd","ruleInsetJunction","ruleInsetStart","ruleOverlap","ruleStyle","ruleVisibilityItems","ruleWidth","rx","ry","scale","scrollBehavior","scrollInitialTarget","scrollMargin","scrollMarginBlock","scrollMarginBlockEnd","scrollMarginBlockStart","scrollMarginBottom","scrollMarginInline","scrollMarginInlineEnd","scrollMarginInlineStart","scrollMarginLeft","scrollMarginRight","scrollMarginTop","scrollMarkerGroup","scrollPadding","scrollPaddingBlock","scrollPaddingBlockEnd","scrollPaddingBlockStart","scrollPaddingBottom","scrollPaddingInline","scrollPaddingInlineEnd","scrollPaddingInlineStart","scrollPaddingLeft","scrollPaddingRight","scrollPaddingTop","scrollSnapAlign","scrollSnapStop","scrollSnapType","scrollTargetGroup","scrollTimeline","scrollTimelineAxis","scrollTimelineName","scrollbarColor","scrollbarGutter","scrollbarWidth","shapeImageThreshold","shapeMargin","shapeOutside","shapeRendering","size","sizeAdjust","speak","speakAs","src","stopColor","stopOpacity","stroke","strokeDasharray","strokeDashoffset","strokeLinecap","strokeLinejoin","strokeMiterlimit","strokeOpacity","strokeWidth","suffix","symbols","syntax","system","tabSize","tableLayout","textAlign","textAlignLast","textAnchor","textAutospace","textBox","textBoxEdge","textBoxTrim","textCombineUpright","textDecoration","textDecorationColor","textDecorationLine","textDecorationSkipInk","textDecorationStyle","textDecorationThickness","textEmphasis","textEmphasisColor","textEmphasisPosition","textEmphasisStyle","textFit","textIndent","textJustify","textOrientation","textOverflow","textRendering","textShadow","textSizeAdjust","textSpacingTrim","textTransform","textUnderlineOffset","textUnderlinePosition","textWrap","textWrapMode","textWrapStyle","timelineScope","timelineTrigger","timelineTriggerActivationRange","timelineTriggerActivationRangeEnd","timelineTriggerActivationRangeStart","timelineTriggerActiveRange","timelineTriggerActiveRangeEnd","timelineTriggerActiveRangeStart","timelineTriggerName","timelineTriggerSource","top","touchAction","transform","transformBox","transformOrigin","transformStyle","transition","transitionBehavior","transitionDelay","transitionDuration","transitionProperty","transitionTimingFunction","translate","triggerScope","types","unicodeBidi","unicodeRange","userSelect","vectorEffect","verticalAlign","viewTimeline","viewTimelineAxis","viewTimelineInset","viewTimelineName","viewTransitionClass","viewTransitionGroup","viewTransitionName","viewTransitionScope","visibility","webkitAlignContent","webkitAlignItems","webkitAlignSelf","webkitAnimation","webkitAnimationDelay","webkitAnimationDirection","webkitAnimationDuration","webkitAnimationFillMode","webkitAnimationIterationCount","webkitAnimationName","webkitAnimationPlayState","webkitAnimationTimingFunction","webkitAppRegion","webkitAppearance","webkitBackfaceVisibility","webkitBackgroundClip","webkitBackgroundOrigin","webkitBackgroundSize","webkitBorderAfter","webkitBorderAfterColor","webkitBorderAfterStyle","webkitBorderAfterWidth","webkitBorderBefore","webkitBorderBeforeColor","webkitBorderBeforeStyle","webkitBorderBeforeWidth","webkitBorderBottomLeftRadius","webkitBorderBottomRightRadius","webkitBorderEnd","webkitBorderEndColor","webkitBorderEndStyle","webkitBorderEndWidth","webkitBorderHorizontalSpacing","webkitBorderImage","webkitBorderRadius","webkitBorderStart","webkitBorderStartColor","webkitBorderStartStyle","webkitBorderStartWidth","webkitBorderTopLeftRadius","webkitBorderTopRightRadius","webkitBorderVerticalSpacing","webkitBoxAlign","webkitBoxDecorationBreak","webkitBoxDirection","webkitBoxFlex","webkitBoxOrdinalGroup","webkitBoxOrient","webkitBoxPack","webkitBoxReflect","webkitBoxShadow","webkitBoxSizing","webkitClipPath","webkitColumnBreakAfter","webkitColumnBreakBefore","webkitColumnBreakInside","webkitColumnCount","webkitColumnGap","webkitColumnRule","webkitColumnRuleColor","webkitColumnRuleStyle","webkitColumnRuleWidth","webkitColumnSpan","webkitColumnWidth","webkitColumns","webkitFilter","webkitFlex","webkitFlexBasis","webkitFlexDirection","webkitFlexFlow","webkitFlexGrow","webkitFlexShrink","webkitFlexWrap","webkitFontFeatureSettings","webkitFontSmoothing","webkitHyphenateCharacter","webkitJustifyContent","webkitLineBreak","webkitLineClamp","webkitLocale","webkitLogicalHeight","webkitLogicalWidth","webkitMarginAfter","webkitMarginBefore","webkitMarginEnd","webkitMarginStart","webkitMask","webkitMaskBoxImage","webkitMaskBoxImageOutset","webkitMaskBoxImageRepeat","webkitMaskBoxImageSlice","webkitMaskBoxImageSource","webkitMaskBoxImageWidth","webkitMaskClip","webkitMaskComposite","webkitMaskImage","webkitMaskOrigin","webkitMaskPosition","webkitMaskPositionX","webkitMaskPositionY","webkitMaskRepeat","webkitMaskSize","webkitMaxLogicalHeight","webkitMaxLogicalWidth","webkitMinLogicalHeight","webkitMinLogicalWidth","webkitOpacity","webkitOrder","webkitPaddingAfter","webkitPaddingBefore","webkitPaddingEnd","webkitPaddingStart","webkitPerspective","webkitPerspectiveOrigin","webkitPerspectiveOriginX","webkitPerspectiveOriginY","webkitPrintColorAdjust","webkitRtlOrdering","webkitRubyPosition","webkitShapeImageThreshold","webkitShapeMargin","webkitShapeOutside","webkitTapHighlightColor","webkitTextCombine","webkitTextDecorationsInEffect","webkitTextEmphasis","webkitTextEmphasisColor","webkitTextEmphasisPosition","webkitTextEmphasisStyle","webkitTextFillColor","webkitTextOrientation","webkitTextSecurity","webkitTextSizeAdjust","webkitTextStroke","webkitTextStrokeColor","webkitTextStrokeWidth","webkitTransform","webkitTransformOrigin","webkitTransformOriginX","webkitTransformOriginY","webkitTransformOriginZ","webkitTransformStyle","webkitTransition","webkitTransitionDelay","webkitTransitionDuration","webkitTransitionProperty","webkitTransitionTimingFunction","webkitUserDrag","webkitUserModify","webkitUserSelect","webkitWritingMode","whiteSpace","whiteSpaceCollapse","widows","width","willChange","wordBreak","wordSpacing","wordWrap","writingMode","x","y","zIndex","zoom"];

  const __cssMaps = new WeakMap();
  // Declaration -> its map as written (shorthands kept). The cascade needs it
  // so `padding: var(--p)` is expanded after substitution, not before.
  const __declRaw = new WeakMap();
  // Methods and `length` live on the prototype; own properties are the CSS
  // property names, all 703, in Chrome's order. There is one builder,
  // `__inlineStyleProto`: rule, attribute and computed style share a
  // prototype, and two builders overwrote each other's members.
  const __shapeStyleProto = () => __inlineStyleProto();

  // What shorthands expand to. `style.length` counts longhands, not written
  // names: `border: none` has 17, `font` 19. From Chrome 151 by enumerating the
  // declaration.
  const CSS_LONGHANDS = {
    'margin': ['margin-top','margin-right','margin-bottom','margin-left'],
    'padding': ['padding-top','padding-right','padding-bottom','padding-left'],
    'border': ['border-top-width','border-right-width','border-bottom-width','border-left-width','border-top-style','border-right-style','border-bottom-style','border-left-style','border-top-color','border-right-color','border-bottom-color','border-left-color','border-image-source','border-image-slice','border-image-width','border-image-outset','border-image-repeat'],
    'border-width': ['border-top-width','border-right-width','border-bottom-width','border-left-width'],
    'border-style': ['border-top-style','border-right-style','border-bottom-style','border-left-style'],
    'border-color': ['border-top-color','border-right-color','border-bottom-color','border-left-color'],
    'border-image': ['border-image-source','border-image-slice','border-image-width','border-image-outset','border-image-repeat'],
    'border-radius': ['border-top-left-radius','border-top-right-radius','border-bottom-right-radius','border-bottom-left-radius'],
    'background': ['background-image','background-position-x','background-position-y','background-size','background-repeat','background-attachment','background-origin','background-clip','background-color'],
    'background-position': ['background-position-x','background-position-y'],
    'font': ['font-style','font-variant-caps','font-variant-ligatures','font-variant-numeric','font-variant-east-asian','font-variant-alternates','font-size-adjust','font-language-override','font-kerning','font-optical-sizing','font-feature-settings','font-variation-settings','font-variant-position','font-variant-emoji','font-weight','font-stretch','font-size','line-height','font-family'],
    'flex': ['flex-grow','flex-shrink','flex-basis'],
    'flex-flow': ['flex-direction','flex-wrap'],
    'overflow': ['overflow-x','overflow-y'],
    'inset': ['top','right','bottom','left'],
    'gap': ['row-gap','column-gap'],
    'outline': ['outline-color','outline-style','outline-width'],
    'grid-area': ['grid-row-start','grid-column-start','grid-row-end','grid-column-end'],
    'grid-template': ['grid-template-rows','grid-template-columns','grid-template-areas'],
    'transition': ['transition-behavior','transition-duration','transition-timing-function','transition-delay','transition-property'],
    'animation': ['animation-duration','animation-timing-function','animation-delay','animation-iteration-count','animation-direction','animation-fill-mode','animation-play-state','animation-name','animation-timeline','animation-range-start','animation-range-end'],
    'place-content': ['align-content','justify-content'],
    'place-items': ['align-items','justify-items'],
    'text-decoration': ['text-decoration-line','text-decoration-thickness','text-decoration-style','text-decoration-color'],
    'list-style': ['list-style-position','list-style-image','list-style-type'],
    'mask': ['mask-image','-webkit-mask-position-x','-webkit-mask-position-y','mask-size','mask-repeat','mask-origin','mask-clip','mask-composite','mask-mode'],
    'columns': ['column-width','column-count','column-height','column-wrap'],
  };
  // Chrome reassembles shorthands when it can, but not a `border` whose parts
  // are all initial: it cannot tell "set to initial" from "unset" and prints
  // longhands. Checked on eleven values: exactly `none` and
  // `medium none currentcolor` expand; `0`, `solid`, `red`, `1px solid red` do not.
  const BORDER_INITIAL = { width: 'medium', style: 'none', color: 'currentcolor' };
  const __borderParts = (v) => {
    const out = { width: null, style: null, color: null };
    for (const tok of __s_split(__s_trim(String(v)), /\s+/)) {
      const t = __s_toLowerCase(tok);
      if (/^(none|hidden|dotted|dashed|solid|double|groove|ridge|inset|outset)$/.test(t)) out.style = t;
      else if (/^(thin|medium|thick)$/.test(t) || /^-?[\d.]+(px|em|rem|pt|%)?$/.test(t)) out.width = t;
      else out.color = t;
    }
    return out;
  };
  const __borderAllInitial = (v) => {
    const p = __borderParts(v);
    return (p.width || BORDER_INITIAL.width) === BORDER_INITIAL.width
        && (p.style || BORDER_INITIAL.style) === BORDER_INITIAL.style
        && (p.color || BORDER_INITIAL.color) === BORDER_INITIAL.color;
  };
  /// Name/value pairs for printing: as in the declaration, with `border`
  /// expanded if it had to be.
  // Four sides collapsed as Chrome does: one value if all equal, two if
  // opposites match, and so on.
  const __cssFour = (t, r, b, l) => {
    if (t === r && r === b && b === l) return t;
    if (t === b && r === l) return t + ' ' + r;
    if (r === l) return t + ' ' + r + ' ' + b;
    return t + ' ' + r + ' ' + b + ' ' + l;
  };

  // Families Chrome reassembles from longhands.
  const __CSS_BOX_FAMILIES = [
    ['margin', ['margin-top', 'margin-right', 'margin-bottom', 'margin-left']],
    ['padding', ['padding-top', 'padding-right', 'padding-bottom', 'padding-left']],
    ['border-width', ['border-top-width', 'border-right-width', 'border-bottom-width', 'border-left-width']],
    ['border-style', ['border-top-style', 'border-right-style', 'border-bottom-style', 'border-left-style']],
    ['border-color', ['border-top-color', 'border-right-color', 'border-bottom-color', 'border-left-color']],
  ];

  /// Declarations as Chrome serializes them: it stores longhands and rebuilds
  /// shorthands on output, so `padding: 1px` plus `padding-left: 9px` prints
  /// as `padding: 1px 1px 1px 9px`, and a `border` with one side overridden
  /// splits into its parts.
  // The `!important` name set lives with the declaration map, which is rebuilt
  // on every attribute change.
  const __cssImp = (m) => {
    if (!m.__ptImp) { try { Object.defineProperty(m, '__ptImp', { value: new Set(), enumerable: false, configurable: true }); } catch (e) { return new Set(); } }
    return m.__ptImp;
  };
  const __cssImportantIn = (v) => typeof v === 'string' && /!\s*important\s*$/i.test(v);
  // The exact value is kept next to the printed one: Chrome stores the parsed
  // number and only prints six digits. Layout and text scaling use the exact
  // value; the page reads the printed one.
  const __cssPrecise = (m) => {
    if (!m.__ptPrecise) { try { Object.defineProperty(m, '__ptPrecise', { value: new Map(), enumerable: false, configurable: true }); } catch (e) { return new Map(); } }
    return m.__ptPrecise;
  };
  const __cssStore = (m, k, v) => {
    const raw = __cssValueRaw(k, v);
    let shown = raw;
    if (!((__s_charCodeAt(k, 0) === 45 && __s_charCodeAt(k, 1) === 45) || k === 'unicode-range')) { try { shown = __cssNumbers(raw); } catch (e) {} }
    m.set(k, shown);
    const pm = __cssPrecise(m);
    if (shown !== raw) pm.set(k, raw); else pm.delete(k);
  };
  const __cssDrop = (m, k) => { m.delete(k); if (m.__ptImp) m.__ptImp.delete(k); if (m.__ptPrecise) m.__ptPrecise.delete(k); };
  const __cssPreciseGet = (m, k) => (m.__ptPrecise && m.__ptPrecise.has(k) ? m.__ptPrecise.get(k) : m.get(k));
  const __styleText = (m) => {
    const imp = m.__ptImp;
    const important = (k) => {
      if (!imp || !imp.size) return false;
      if (imp.has(k)) return true;
      for (const sh of imp) if (__s_includes(CSS_LONGHANDS[sh] || [], k)) return true;
      return false;
    };
    return __styleEntries(m).map(([k, v]) => `${k}: ${v}${important(k) ? ' !important' : ''};`).join(' ');
  };
  const __styleEntries = (m) => {
    // Which longhands are written separately (the only reason to split a
    // shorthand), counting written shorthands too: `border` is split when
    // `border-width` is present, not only `border-top-width`.
    const written = new Set();
    for (const k of m.keys()) {
      written.add(k);
      for (const n of (CSS_LONGHANDS[k] || [])) written.add(n);
    }
    const order = [];
    const seen = new Map();
    const put = (k, v) => {
      if (seen.has(k)) order[seen.get(k)] = null;
      seen.set(k, order.length);
      order.push([k, v]);
    };
    for (const [k, v] of m) {
      if (k === 'border' && __borderAllInitial(v)) {
        put('border-width', 'medium'); put('border-style', 'none');
        put('border-color', 'currentcolor'); put('border-image', 'none');
        continue;
      }
      const list = CSS_LONGHANDS[k];
      const overridden = list && list.some((n) => {
        if (!written.has(n)) return false;
        // Its own expansion does not count.
        return ![...m.keys()].every((other) => other === k
          || !(other === n || __s_includes(CSS_LONGHANDS[other] || [], n)));
      });
      const pairs = overridden && typeof __ptExpand === 'function' ? __ptExpand(k, v) : null;
      if (pairs && pairs.length) {
        for (const [lk, lv] of pairs) put(lk, lv);
        if (k === 'border') put('border-image', 'none');
        continue;
      }
      put(k, v);
    }
    let live = order.filter(Boolean);
    // Reassemble: the shorthand takes the place of its first part.
    for (const [short, parts] of __CSS_BOX_FAMILIES) {
      const at = parts.map((n) => live.findIndex(([k]) => k === short || k === n));
      if (at.some((i) => i < 0)) continue;
      const vals = parts.map((n) => (live.find(([k]) => k === n) || [])[1]);
      if (vals.some((x) => x == null)) continue;
      const first = Math.min(...at);
      const merged = [short, __cssFour(vals[0], vals[1], vals[2], vals[3])];
      live = live.map((e, i) => (i === first ? merged : (__s_includes(parts, e[0]) ? null : e)))
        .filter(Boolean);
    }
    return live;
  };

  /// Value of a longhand written via a shorthand: after
  /// `style.border = '1px solid'`, `style.borderTopWidth` is `1px`.
  // Reverse index: which shorthands contain this longhand. Without it each
  // lookup scanned the whole map (~450 entries for computed style), costing
  // ~2.5 ms per full style enumeration.
  let __SHORTS_OF = null;
  const __shortsOf = (key) => {
    if (!__SHORTS_OF) {
      __SHORTS_OF = Object.create(null);
      for (const short of Object.keys(CSS_LONGHANDS)) {
        for (const long of CSS_LONGHANDS[short]) {
          (__SHORTS_OF[long] || (__SHORTS_OF[long] = [])).push(short);
        }
      }
    }
    return __SHORTS_OF[key];
  };

  const __longhandFrom = (m, key) => {
    const shorts = __shortsOf(key);
    if (shorts) {
      for (const short of shorts) {
        const value = m.get(short);
        if (value == null) continue;
        const pairs = typeof __ptExpand === 'function' ? __ptExpand(short, value) : null;
        if (!pairs) continue;
        for (const [k, v] of pairs) if (k === key) return v;
      }
    }
    // And the reverse: a shorthand assembled from longhands. `border: 1px
    // solid` gives `solid` for `borderStyle` since all four sides match;
    // mismatched sides are not printed as a shorthand.
    const own = CSS_LONGHANDS[key];
    if (own && !m.has(key)) {
      let same = null;
      for (const n of own) {
        const v = m.get(n) || __longhandFrom(m, n);
        if (!v) return '';
        if (same == null) same = v;
        else if (same !== v) return '';
      }
      if (same != null) return same;
    }
    return '';
  };

  /// Names a declaration enumerates: shorthands expanded, in order of
  /// appearance, no duplicates, as in Chrome.
  const __styleNames = (m) => {
    const out = [];
    for (const k of m.keys()) for (const n of (CSS_LONGHANDS[k] || [k])) if (!__s_includes(out, n)) out.push(n);
    return out;
  };

  // A stylesheet rule's declaration: the same shape as an element's `style`
  // (own data properties, shared accessors keyed by `this`), backed by the
  // rule's declaration map, which the cascade reads directly. Per-instance
  // accessors cost two closures per property, ~700 per rule.
  function __cssDeclaration(map) {
    const dash = (p) => __s_replace(String(p), /[A-Z]/g, (c) => '-' + __s_toLowerCase(c));
    const target = Object.create(__inlineStyleProto(), __styleDescs());
    __cssMaps.set(target, map);
    let indexed = 0;
    const reindex = (names) => {
      for (let i = 0; i < names.length; i++) {
        try { Object.defineProperty(target, String(i), { value: names[i], enumerable: true, configurable: true }); } catch (e) {}
      }
      for (let i = names.length; i < indexed; i++) { try { delete target[String(i)]; } catch (e) {} }
      indexed = names.length;
    };
    const read = () => map;
    const write = (m) => {
      // Edited in place: the rule keeps its map.
      if (m !== map) {
        map.clear();
        for (const [k, v] of m) map.set(k, v);
        const imp = __cssImp(map);
        imp.clear();
        if (m.__ptImp) for (const k of m.__ptImp) imp.add(k);
      }
      reindex(__styleNames(map));
      // Any cascade may differ now.
      __styleAllStale = true;
      __markDirty();
    };
    __cssReaders.set(target, { read, write, el: null });
    reindex(__styleNames(map));
    const px = __ptProxy(target, {
      ...__declTraps((t, p) => { const k = dash(p); return map.get(k) || __longhandFrom(map, k); }),
      get: (t, p) => {
        if (typeof p === 'string' && EPUB_SET.has(p)) return undefined;
        if (typeof p === 'string' && !(p in t)) {
          const k = dash(p);
          return map.get(k) || __longhandFrom(map, k);
        }
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (p === 'cssText') { t.cssText = v; return true; }
        const k = dash(String(p));
        if (__cssImportantIn(v)) return true;
        if (v === '' || v == null) __cssDrop(map, k); else { __cssStore(map, k, v); __cssImp(map).delete(k); }
        write(map); return true;
      },
    });
    __declRaw.set(px, read);
    return px;
  }

  const __ruleListProto = {
    get [Symbol.toStringTag]() { return 'CSSRuleList'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __cssRuleList(arr) {
    const list = Object.create(__link('CSSRuleList', __ruleListProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }

  const __mediaListProto = {
    get [Symbol.toStringTag]() { return 'MediaList'; },
    get mediaText() { return this.__ptMedia.join(', '); },
    set mediaText(v) { this.__ptMedia = __s_split(String(v), ',').map((s) => __s_trim(s)).filter(Boolean); },
    get length() { return this.__ptMedia.length; },
    item(i) { return this.__ptMedia[i] != null ? this.__ptMedia[i] : null; },
    appendMedium(m) { if (!__s_includes(this.__ptMedia, String(m))) this.__ptMedia.push(String(m)); },
    deleteMedium(m) { this.__ptMedia = this.__ptMedia.filter((x) => x !== String(m)); },
    toString() { return this.mediaText; },
  };
  function __mediaList(text) {
    const m = Object.create(__link('MediaList', __mediaListProto));
    Object.defineProperty(m, '__ptMedia', {
      value: __s_split(String(text || ''), ',').map((s) => __s_trim(s)).filter(Boolean),
      writable: true, enumerable: false,
    });
    return m;
  }

  // Rules. Type numbers match CSSRule in Chrome.
  const RULE_TYPE = { style: 1, charset: 2, import: 3, media: 4, 'font-face': 5,
                      page: 6, keyframes: 7, keyframe: 8, supports: 12 };
  const __ruleProtos = new Map();
  const __ruleProto = (name) => {
    let p = __ruleProtos.get(name);
    if (p) return p;
    const base = globalThis[name] && globalThis[name].prototype;
    p = base || Object.prototype;
    try {
      if (base && !Object.getOwnPropertyDescriptor(base, Symbol.toStringTag)) {
        Object.defineProperty(base, Symbol.toStringTag, { value: name, configurable: true });
      }
    } catch (e) {}
    __ruleProtos.set(name, p);
    return p;
  };
  // CSSOM objects carry no own properties in Chrome: every member is an
  // accessor on the interface prototype. Their state lives here. A rule's
  // declarations, selector and text are worked out on first read: GitHub
  // ships 15 000 rules, and building them all cost half a second.
  const __cssom = new WeakMap();
  const __om = (o) => {
    const s = __cssom.get(o);
    if (!s) throw __pt_mkErr(TypeError, 'Illegal invocation');
    return s;
  };
  const __ruleDecls = (st) => st.decls || (st.decls = __cssDecls(st.body || ''));
  const __ruleSel = (st) => (st.sel != null ? st.sel : (st.sel = __cssSelector(st.prelude || '')));
  const __ruleSelText = (st) => (st.selText != null ? st.selText : (st.selText = __selSerialize(__ruleSel(st), true)));
  const __ruleStyle = (st) => st.style || (st.style = __cssDeclaration(__ruleDecls(st)));
  const __ruleList = (st) => st.list || (st.list = __cssRuleList(st.kids || []));
  const __declsText = (m) => __styleEntries(m)
    .map(([k, v]) => k + ': ' + v + (m.__ptImp && m.__ptImp.has(k) ? ' !important' : '') + ';').join(' ');
  // A rule with children prints on several lines, one per child, indented two
  // spaces. `@keyframes` keeps a space after the opening brace, `@media` does
  // not, as in Chrome.
  const __cssGroup = (prelude, kids, pad) => prelude + ' {' + (pad ? ' ' : '') + '\n'
    + kids.map((k) => '  ' + __s_replace(__ruleText(__cssom.get(k)), /\n/g, '\n  ')).join('\n')
    + '\n}';
  function __ruleText(st) {
    switch (st.kind) {
      case 'style': { const b = __declsText(__ruleDecls(st)); return __ruleSelText(st) + ' { ' + (b ? b + ' ' : '') + '}'; }
      case 'font-face': return '@font-face { ' + __declsText(__ruleDecls(st)) + ' }';
      case 'keyframe': return st.keyText + ' { ' + __declsText(__ruleDecls(st)) + ' }';
      case 'media': case 'supports': return __cssGroup(st.at + ' ' + st.cond, st.kids, false);
      case 'layer-block': return __cssGroup('@layer' + (st.name ? ' ' + st.name : ''), st.kids, false);
      case 'keyframes': return __cssGroup('@keyframes ' + st.name, st.kids, true);
      case 'container': return __cssGroup('@container ' + st.cond, st.kids, false);
      case 'page': { const b = __declsText(__ruleDecls(st)); return '@page' + (st.sel ? ' ' + st.sel : '') + ' { ' + (b ? b + ' ' : '') + '}'; }
      case 'property': {
        const m = __ruleDecls(st), out = [];
        for (const k of ['syntax', 'inherits', 'initial-value']) if (m.has(k)) out.push(k + ': ' + __propertyDescriptor(k, m.get(k)) + ';');
        return '@property ' + st.name + ' { ' + (out.length ? out.join(' ') + ' ' : '') + '}';
      }
      case 'counter-style': { const b = __declsText(__ruleDecls(st)); return '@counter-style ' + st.name + ' { ' + (b ? b + ' ' : '') + '}'; }
      default: return st.text;
    }
  }
  // `@property` descriptors: the syntax is a string in double quotes.
  const __propertyDescriptor = (k, v) => {
    v = __s_trim(String(v));
    if (k === 'syntax') { const m = /^(['"])(.*)\1$/.exec(v); return '"' + (m ? m[2] : v) + '"'; }
    return v;
  };
  // Keyframe selectors: `from` is 0%, `to` 100%, a list is comma-spaced.
  const __keyText = (p) => __s_split(__s_trim(String(p)), ',').map((x) => {
    const t = __s_toLowerCase(__s_trim(x));
    return t === 'from' ? '0%' : t === 'to' ? '100%' : t;
  }).join(', ');
  // A media query list: one space around `and`, `: ` in features, `, `
  // between queries.
  const __mediaText = (q) => __s_replace(__s_replace(__s_replace(__s_trim(String(q)), /\s+/g, ' '), /\s*:\s*/g, ': '), /\s*,\s*/g, ', ');
  // A selector or a rule list changed through the CSSOM: the rule list and
  // every cascade are rebuilt.
  const __cssomChanged = () => { __importGen++; __markDirty(); };
  // `insertRule` on a sheet or a grouping rule: Chrome's index checks.
  const __ruleInsert = (st, text, index, owner, sheet, parent, iface) => {
    const list = st.kids || st.rules;
    const at = index === undefined ? 0 : Number(index) >>> 0;
    if (at > list.length) {
      throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'insertRule' on '" + iface + "': The index provided (" + at + ') is larger than the maximum index (' + list.length + ').', 'IndexSizeError');
    }
    const parsed = __cssParse(String(text))[0];
    const rule = parsed && __makeRule(parsed, sheet, parent);
    if (!rule) {
      throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'insertRule' on '" + iface + "': Failed to parse the rule '" + String(text) + "'.", 'SyntaxError');
    }
    const next = list.slice();
    next.splice(at, 0, rule);
    if (st.kids) st.kids = next; else st.rules = next;
    st.list = null;
    __cssomChanged();
    return at;
  };
  const __ruleDelete = (st, index, iface) => {
    const list = st.kids || st.rules;
    const at = Number(index) >>> 0;
    if (at >= list.length) {
      throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'deleteRule' on '" + iface + "': The index provided (" + at + ') is larger than the maximum index (' + Math.max(0, list.length - 1) + ').', 'IndexSizeError');
    }
    const next = list.slice();
    next.splice(at, 1);
    if (st.kids) st.kids = next; else st.rules = next;
    st.list = null;
    __cssomChanged();
  };
  // A sheet made with `new CSSStyleSheet()` gets its state on first use.
  const __sheetOm = (o) => {
    let s = __cssom.get(o);
    if (s) return s;
    const P = globalThis.CSSStyleSheet && globalThis.CSSStyleSheet.prototype;
    if (!P || o === null || typeof o !== 'object' || o === P || !Object.prototype.isPrototypeOf.call(P, o)) {
      throw __pt_mkErr(TypeError, 'Illegal invocation');
    }
    s = { owner: null, href: null, title: null, media: __mediaList(''), parent: null, ownerRule: null,
          disabled: false, text: null, rules: [], list: null, imports: Promise.resolve() };
    __cssom.set(o, s);
    return s;
  };
  const __sheetRuleList = (st) => st.list || (st.list = __cssRuleList(st.rules));
  const __cssomMembers = {
    CSSRule: {
      get type() { return __om(this).type; },
      get cssText() { return __ruleText(__om(this)); },
      set cssText(v) { __om(this); },
      get parentRule() { return __om(this).parent; },
      get parentStyleSheet() { return __om(this).sheet; },
    },
    CSSStyleRule: {
      get selectorText() { return __ruleSelText(__om(this)); },
      set selectorText(v) {
        const st = __om(this);
        const sel = __cssSelector(String(v));
        if (!sel || !__selCompiled(sel)) return;
        st.sel = sel;
        st.selText = null;
        __cssomChanged();
      },
      get style() { return __ruleStyle(__om(this)); },
      set style(v) { __ruleStyle(__om(this)).cssText = String(v); },
      get cssRules() { return __ruleList(__om(this)); },
      insertRule() { __om(this); return 0; },
      deleteRule() { __om(this); },
    },
    CSSGroupingRule: {
      get cssRules() { return __ruleList(__om(this)); },
      insertRule(rule, index) { const st = __om(this); return __ruleInsert(st, rule, index, this, st.sheet, this, 'CSSGroupingRule'); },
      deleteRule(index) { __ruleDelete(__om(this), index, 'CSSGroupingRule'); },
    },
    CSSConditionRule: {
      get conditionText() { return __om(this).cond; },
    },
    CSSMediaRule: {
      get media() { const st = __om(this); return st.media || (st.media = __mediaList(st.cond)); },
    },
    CSSImportRule: {
      get href() { return __om(this).href; },
      get media() { return __om(this).media; },
      get styleSheet() { return __om(this).styleSheet; },
      get layerName() { return __om(this).layer; },
      get supportsText() { __om(this); return null; },
    },
    CSSFontFaceRule: {
      get style() { return __ruleStyle(__om(this)); },
    },
    CSSKeyframesRule: {
      get name() { return __om(this).name; },
      set name(v) { __om(this).name = String(v); },
      get cssRules() { return __ruleList(__om(this)); },
      get length() { return __om(this).kids.length; },
      appendRule() { __om(this); },
      deleteRule() { __om(this); },
      findRule() { __om(this); return null; },
    },
    CSSKeyframeRule: {
      get keyText() { return __om(this).keyText; },
      set keyText(v) { __om(this).keyText = __keyText(v); },
      get style() { return __ruleStyle(__om(this)); },
    },
    CSSLayerBlockRule: {
      get name() { return __om(this).name; },
    },
    CSSContainerRule: {
      get containerName() { return __om(this).containerName; },
      get containerQuery() { return __om(this).containerQuery; },
    },
    CSSPageRule: {
      get selectorText() { return __om(this).sel || ''; },
      get style() { return __ruleStyle(__om(this)); },
    },
    CSSPropertyRule: {
      get name() { return __om(this).name; },
      get syntax() { const m = __ruleDecls(__om(this)); return m.has('syntax') ? __s_slice(__propertyDescriptor('syntax', m.get('syntax')), 1, -1) : ''; },
      get inherits() { const m = __ruleDecls(__om(this)); return __s_toLowerCase(__s_trim(String(m.get('inherits') || ''))) === 'true'; },
      get initialValue() { const m = __ruleDecls(__om(this)); return m.has('initial-value') ? __s_trim(String(m.get('initial-value'))) : null; },
    },
    CSSCounterStyleRule: {
      get name() { return __om(this).name; },
    },
    CSSLayerStatementRule: {
      get nameList() { const st = __om(this); return st.frozen || (st.frozen = Object.freeze(st.names.slice())); },
    },
    StyleSheet: {
      get type() { __sheetOm(this); return 'text/css'; },
      get href() { return __sheetOm(this).href; },
      get ownerNode() { return __sheetOm(this).owner; },
      get parentStyleSheet() { return __sheetOm(this).parent; },
      get title() { return __sheetOm(this).title; },
      get media() { return __sheetOm(this).media; },
      get disabled() { return __sheetOm(this).disabled; },
      set disabled(v) { const st = __sheetOm(this); if (st.disabled !== !!v) { st.disabled = !!v; __cssomChanged(); } },
    },
    CSSStyleSheet: {
      get [Symbol.toStringTag]() { return 'CSSStyleSheet'; },
      get ownerRule() { return __sheetOm(this).ownerRule; },
      get cssRules() { return __sheetRuleList(__sheetOm(this)); },
      get rules() { return __sheetRuleList(__sheetOm(this)); },
      insertRule(text, index) { return __ruleInsert(__sheetOm(this), text, index, this, this, null, 'CSSStyleSheet'); },
      deleteRule(index) { __ruleDelete(__sheetOm(this), index, 'CSSStyleSheet'); },
      addRule(sel, decl, index) {
        const st = __sheetOm(this);
        __ruleInsert(st, sel + ' { ' + (decl || '') + ' }', index === undefined ? st.rules.length : index, this, this, null, 'CSSStyleSheet');
        return -1;
      },
      removeRule(index) { __ruleDelete(__sheetOm(this), index === undefined ? 0 : index, 'CSSStyleSheet'); },
      replaceSync(text) {
        const st = __sheetOm(this);
        st.rules = __topRules(String(text), this, true);
        st.list = null;
        __cssomChanged();
      },
      replace(text) { this.replaceSync(text); return Promise.resolve(this); },
    },
  };
  // Members go onto the interface prototypes once, when the first sheet is
  // made (after the bootstrap has shaped them).
  let __cssomLinked = false;
  const __cssomLink = () => {
    if (__cssomLinked) return;
    __cssomLinked = true;
    for (const name of Object.keys(__cssomMembers)) __link(name, __cssomMembers[name]);
  };
  const __newRule = (iface, st) => {
    __cssomLink();
    const r = Object.create(__ruleProto(iface));
    __cssom.set(r, st);
    return r;
  };

  function __makeRule(parsed, sheet, parent) {
    const prelude = parsed.prelude || '';
    const at = __s_charCodeAt(prelude, 0) === 64 ? __s_toLowerCase(__s_split(prelude, /[\s({]/)[0]) : '';
    const base = (kind, type) => ({ kind, type, sheet, parent: parent || null });

    if (at === '@import') {
      const href = __s_slice(/url\(\s*["']?([^"')]*)["']?\s*\)|["']([^"']*)["']/.exec(prelude) || [], 1).find((x) => x !== undefined) || '';
      let media = __s_trim(__s_replace(__s_slice(prelude, 7), /^\s*(url\(\s*(["']?)[^)]*?\2\s*\)|"[^"]*"|'[^']*')/i, ''));
      // `layer` or `layer(name)` puts the imported rules in a cascade layer.
      let layer = null;
      const lm = /^layer(?:\(\s*([^)]*?)\s*\))?(?=\s|$)/i.exec(media);
      if (lm) { layer = lm[1] || ''; media = __s_trim(__s_slice(media, lm[0].length)); }
      const st = base('import', RULE_TYPE.import);
      Object.assign(st, { href, layer, media: __mediaList(media), styleSheet: null,
        text: '@import url("' + href + '")' + (lm ? ' ' + lm[0] : '') + (media ? ' ' + media : '') + ';' });
      return __newRule('CSSImportRule', st);
    }
    if (at === '@layer') {
      const names = __s_trim(__s_slice(prelude, 6));
      if (parsed.statement || parsed.body == null) {
        const list = __s_split(names, ',').map((x) => __s_trim(x)).filter(Boolean);
        const st = base('layer-statement', 0);
        Object.assign(st, { names: list, text: '@layer ' + list.join(', ') + ';' });
        return __newRule('CSSLayerStatementRule', st);
      }
      const st = base('layer-block', 0);
      st.name = names;
      const r = __newRule('CSSLayerBlockRule', st);
      st.kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r)).filter(Boolean);
      return r;
    }
    if (at === '@media' || at === '@supports') {
      const st = base(at === '@media' ? 'media' : 'supports', at === '@media' ? RULE_TYPE.media : RULE_TYPE.supports);
      // A media query is normalized; a supports condition stays as written.
      const raw = __s_trim(__s_slice(prelude, at.length));
      Object.assign(st, { at, cond: at === '@media' ? __mediaText(raw) : raw });
      const r = __newRule(at === '@media' ? 'CSSMediaRule' : 'CSSSupportsRule', st);
      st.kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r)).filter(Boolean);
      return r;
    }
    if (at === '@keyframes' || at === '@-webkit-keyframes') {
      const st = base('keyframes', RULE_TYPE.keyframes);
      st.name = __s_trim(__s_slice(prelude, at.length));
      const r = __newRule('CSSKeyframesRule', st);
      st.kids = __cssParse(parsed.body || '').map((p) => {
        const k = base('keyframe', RULE_TYPE.keyframe);
        Object.assign(k, { parent: r, keyText: __keyText(p.prelude), body: p.body || '' });
        return __newRule('CSSKeyframeRule', k);
      });
      // A keyframes rule reads its keyframes by index, as own properties.
      for (let i = 0; i < st.kids.length; i++) {
        Object.defineProperty(r, String(i), { value: st.kids[i], enumerable: true, configurable: true });
      }
      return r;
    }
    if (at === '@font-face') {
      const st = base('font-face', RULE_TYPE['font-face']);
      st.body = parsed.body || '';
      return __newRule('CSSFontFaceRule', st);
    }
    if (at === '@container') {
      const st = base('container', 0);
      const raw = __s_trim(__s_slice(prelude, at.length));
      // An optional name, then the query.
      const nm = /^(?!not\b|\()([-\w]+)\s+/i.exec(raw);
      st.containerName = nm ? nm[1] : '';
      st.containerQuery = __mediaText(nm ? __s_slice(raw, nm[0].length) : raw);
      st.cond = (st.containerName ? st.containerName + ' ' : '') + st.containerQuery;
      const r = __newRule('CSSContainerRule', st);
      st.kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r)).filter(Boolean);
      return r;
    }
    if ((at === '@page' || at === '@property' || at === '@counter-style') && !parsed.statement) {
      const kind = at === '@page' ? 'page' : at === '@property' ? 'property' : 'counter-style';
      const st = base(kind, at === '@page' ? RULE_TYPE.page : at === '@counter-style' ? 11 : 0);
      const rest = __s_trim(__s_slice(prelude, at.length));
      if (kind === 'page') st.sel = __s_replace(rest, /\s+/g, ' '); else st.name = rest;
      st.body = parsed.body || '';
      return __newRule(kind === 'page' ? 'CSSPageRule' : kind === 'property' ? 'CSSPropertyRule' : 'CSSCounterStyleRule', st);
    }
    if (at) {
      // Chrome reads `@charset` and drops it; it is not in the rule list.
      if (/^@charset\b/i.test(prelude)) return null;
      const st = base('other', RULE_TYPE.charset);
      st.text = prelude + (parsed.statement ? ';' : ' { }');
      return __newRule('CSSRule', st);
    }
    const st = base('style', RULE_TYPE.style);
    st.prelude = prelude;
    st.body = parsed.body || '';
    st.sel = null;
    return __newRule('CSSStyleRule', st);
  }

  // A sheet's top-level rules. `@import` counts only before every other rule
  // (`@charset` aside), `@layer` statements included once an import was seen;
  // a constructed sheet takes none.
  const __topRules = (text, sheet, constructed) => {
    const out = [];
    let lead = true, imported = false;
    for (const p of __cssParse(text)) {
      const r = __makeRule(p, sheet, null);
      if (!r) continue;
      const kind = __cssom.get(r).kind;
      if (kind === 'import') { if (!lead || constructed) continue; imported = true; }
      else if (kind !== 'layer-statement' || imported) lead = false;
      out.push(r);
    }
    return out;
  };
  // A sheet's rules for the engine: its state, never the page-facing list.
  const __sheetRules = (sheet) => { const st = sheet && __cssom.get(sheet); return st && !st.disabled ? st.rules : null; };
  // The sheet's own address, or the nearest importing sheet's (the base a
  // `url()` in it resolves against).
  const __sheetHref = (sheet) => {
    for (let st = sheet && __cssom.get(sheet); st; st = st.parent && __cssom.get(st.parent)) if (st.href) return st.href;
    return null;
  };
  // A sheet lives on its element: pages compare
  // `document.styleSheets[0] === document.styleSheets[0]`, and rules are
  // rebuilt only when the text changes.
  globalThis.__pt_sheetFor = (owner) => __sheetFor(owner);
  // Where `<meta http-equiv="refresh">` sends the document, for the engine.
  // A browser does this natively; read with the engine's own helpers so the
  // page sees no `getAttribute` or string calls after load.
  globalThis.__pt_metaRefresh = () => {
    for (const m of __docTags(document, 'meta')) {
      if (__s_toLowerCase(__ptGetA(m, 'http-equiv') || '') !== 'refresh') continue;
      const c = __ptGetA(m, 'content') || '';
      const i = __s_indexOf(__s_toLowerCase(c), 'url=');
      if (i < 0) continue;
      return __s_replace(__s_replace(__s_trim(__s_slice(c, i + 4)), /^['"]/, ''), /['"]$/, '');
    }
    return '';
  };
  function __sheetFor(owner) {
    __cssomLink();
    const text = owner.__ptLocal === 'style'
      ? String(owner.textContent || '')
      : String(owner.__ptSheetText || '');
    let sheet = owner.__ptSheet;
    if (!sheet) {
      sheet = Object.create(__ruleProto('CSSStyleSheet'));
      Object.defineProperty(owner, '__ptSheet', { value: sheet, writable: true, enumerable: false });
      __cssom.set(sheet, {
        owner, href: owner.__ptLocal === 'link' ? (owner.href || null) : null,
        title: __ptGetA(owner, 'title'), media: __mediaList(__ptGetA(owner, 'media') || ''),
        parent: null, ownerRule: null, disabled: false, text: null, rules: [], list: null, imports: Promise.resolve(),
      });
    }
    const st = __cssom.get(sheet);
    if (st.text !== text) {
      st.text = text;
      st.rules = __topRules(text, sheet, false);
      st.list = null;
      __startImports(sheet, st.rules, 0);
    }
    return sheet;
  }

  // `@import`: Chrome fetches every import as soon as the sheet is parsed
  // (media or not), as a style request with the importing sheet as referrer;
  // the imported rules sit in the cascade at the rule's place. `done` settles
  // when the whole import tree has arrived, which the owner's `load` and the
  // document's wait for.
  let __importGen = 0;
  const __IMPORT_DEPTH = 16;
  function __startImports(sheet, rules, depth) {
    let list = null;
    for (const r of rules) {
      const kind = __cssom.get(r).kind;
      if (kind === 'import') (list || (list = [])).push(r);
      else if (kind !== 'layer-statement') break;   // imports only lead a sheet
    }
    const done = list && depth < __IMPORT_DEPTH && typeof globalThis.__pt_subresourceText === 'function'
      ? Promise.all(list.map((r) => __loadImport(sheet, r, depth)))
      : Promise.resolve();
    const st = __cssom.get(sheet);
    if (list && depth === 0 && st.owner && st.owner.__ptLocal === 'style') {
      const rel = __holdDcl(st.owner);
      done.then(rel, rel);
    }
    st.imports = done;
    return done;
  }
  function __loadImport(sheet, rule, depth) {
    const from = __cssom.get(sheet).href || null;
    const rst = __cssom.get(rule);
    let abs;
    try { abs = new URL(rst.href, from || document.baseURI).href; } catch (e) { return Promise.resolve(); }
    // A cycle loads nothing more: the browser drops an import of a sheet already
    // on the chain.
    for (let s2 = __cssom.get(sheet); s2; s2 = s2.parent && __cssom.get(s2.parent)) if (s2.href === abs) return Promise.resolve();
    const rel = __holdLoad('import ' + abs);
    return __pt_subresourceText(abs, 'css', from)
      .then((text) => {
        if (typeof text !== 'string') return null;
        const child = Object.create(__ruleProto('CSSStyleSheet'));
        const cst = { owner: null, href: abs, title: null, media: rst.media, parent: sheet, ownerRule: rule,
                      disabled: false, text, rules: [], list: null, imports: Promise.resolve() };
        __cssom.set(child, cst);
        cst.rules = __topRules(text, child, false);
        rst.styleSheet = child;
        __importGen++;
        __markDirty();
        return __startImports(child, cst.rules, depth + 1);
      })
      .then(() => { rel(); }, () => { rel(); });
  }
  const __sheetListProto = {
    get [Symbol.toStringTag]() { return 'StyleSheetList'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __styleSheetList(owners) {
    const list = Object.create(__link('StyleSheetList', __sheetListProto));
    for (let i = 0; i < owners.length; i++) list[i] = __sheetFor(owners[i]);
    Object.defineProperty(list, '__ptLen', { value: owners.length, enumerable: false, configurable: true });
    return list;
  }

  function makeDataset(el) {
    const target = {};
    for (const k of el.getAttributeNames()) if (__s_startsWith(k, 'data-'))
      target[camel(__s_slice(k, 5))] = __ptGetA(el, k);
    return __ptProxy(target, {
      get: (t, p) => __ptGetA(el, 'data-' + dash(String(p))) ?? undefined,
      set: (t, p, v) => { __ptSetA(el, 'data-' + dash(String(p)), v); return true; },
      has: (t, p) => __ptHasA(el, 'data-' + dash(String(p))),
    });
  }
  const camel = (s) => __s_replace(s, /-([a-z])/g, (_, c) => __s_toUpperCase(c));
  const dash = (s) => __s_replace(s, /[A-Z]/g, (c) => '-' + __s_toLowerCase(c));
  // `el.style` and the `style` attribute are two views of one store.
  // The inline style is a CSSStyleDeclaration too: `el.style` and
  // `getComputedStyle(el)` share an interface, and fingerprinters read its name.
  const __styleProto = () => {
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    return proto;
  };
  const __cssReaders = new WeakMap();
  // Inline declaration prototype: the same ten members as Chrome.
  const __inlineStyleProto = () => {
    const proto = __styleProto();
    if (proto.__ptInlineShaped) return proto;
    try { Object.defineProperty(proto, '__ptInlineShaped', { value: true }); } catch (e) {}
    // A declaration is either inline (backed by the element's attribute) or a
    // stylesheet rule (backed by a parsed declaration map). Both share members
    // on one prototype, so both are handled here; handling only one made the
    // result depend on which was built first.
    const st = (o) => {
      const own = __cssReaders.get(o);
      if (own) return own;
      const map = __cssMaps.get(o);
      if (!map) return null;
      // A rule's declarations changed: every cascade may differ.
      return { read: () => map, write: () => { __styleAllStale = true; }, computed: false, map, el: null };
    };
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const def = (name, value) => {
      const m = ({ [name](...a) { return value.apply(this, a); } })[name];
      try { Object.defineProperty(m, 'length', { value: value.length, configurable: true }); } catch (e) {}
      try { Object.defineProperty(proto, name, { value: nat(m, name), writable: true, enumerable: true, configurable: true }); } catch (e) {}
    };
    const acc = (name, get, set) => {
      try { Object.defineProperty(proto, name, { get: nat(get, 'get ' + name), set: set ? nat(set, 'set ' + name) : undefined, enumerable: true, configurable: true }); } catch (e) {}
    };
    def('getPropertyValue', function getPropertyValue(p) {
      const s = st(this); if (!s) return '';
      const k = __cssKey(p);
      const m = s.computed ? s.map : s.read();
      // Vendor-prefixed names are also asked with a leading dash, and a
      // longhand may be written via a shorthand (`border-top-width` from
      // `border`). `-epub-…` is just another name: computed
      // `-epub-word-break` answers like `word-break`.
      const alias = s.computed ? EPUB_ALIAS[k] : null;
      if (alias) return m.get(alias) || __longhandFrom(m, alias) || '';
      return m.get(k) || (__s_charCodeAt(k, 0) === 45 ? m.get(__s_slice(k, 1)) || '' : '')
        || __longhandFrom(m, k);
    });
    def('getPropertyPriority', function getPropertyPriority(p) {
      const s = st(this); if (!s || s.computed) return '';
      const m = s.read(), k = __cssKey(p), imp = m.__ptImp;
      if (!imp || !imp.size) return '';
      if (imp.has(k)) return 'important';
      for (const sh of imp) if (__s_includes(CSS_LONGHANDS[sh] || [], k)) return 'important';
      return '';
    });
    def('setProperty', function setProperty(p, v, prio) {
      const s = st(this); if (!s) return;
      if (s.computed) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'setProperty' on 'CSSStyleDeclaration': These styles are computed, and therefore the '" + __cssKey(p) + "' property is read-only.", 'NoModificationAllowedError');
      // Priority is either empty or `important`; anything else makes Chrome
      // silently reject the whole call, as does `!important` inside the value.
      const pr = prio == null ? '' : __s_toLowerCase(__s_trim(String(prio)));
      if (pr !== '' && pr !== 'important') return;
      if (__cssImportantIn(v)) return;
      const m = s.read(), k = __cssKey(p);
      // An empty value removes the property rather than leaving `opacity: `,
      // a string Chrome never produces (the widget frame reads its `style`
      // tens of thousands of times).
      if (v === '' || v == null) __cssDrop(m, k);
      else { __cssStore(m, k, v); if (pr === 'important') __cssImp(m).add(k); else __cssImp(m).delete(k); }
      s.write(m);
    });
    def('removeProperty', function removeProperty(p) {
      const s = st(this); if (!s) return '';
      if (s.computed) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'removeProperty' on 'CSSStyleDeclaration': These styles are computed, and therefore the '" + __cssKey(p) + "' property is read-only.", 'NoModificationAllowedError');
      const m = s.read(), k = __cssKey(p), had = m.get(k) || '';
      __cssDrop(m, k); s.write(m); return had;
    });
    def('item', function item(i) {
      const s = st(this); if (!s) return '';
      return s.computed ? (s.names[i] || '') : (__styleNames(s.read())[i] || '');
    });
    acc('length', function length() {
      const s = st(this); if (!s) return 0;
      return s.computed ? s.names.length : __styleNames(s.read()).length;
    });
    acc('parentRule', function parentRule() { return null; });
    acc('cssFloat',
      function cssFloat() { const s = st(this); return s ? (s.read().get('float') || '') : ''; },
      function cssFloat(v) { const s = st(this); if (!s) return; const m = s.read(); m.set('float', String(v)); s.write(m); });
    acc('cssText',
      function cssText() {
        const s = st(this); if (!s) return '';
        // Empty for computed style, as in Chrome.
        if (s.computed) return '';
        return __styleText(s.read());
      },
      function cssText(v) {
        const s = st(this); if (!s) return;
        if (s.computed) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to set the 'cssText' property on 'CSSStyleDeclaration': These styles are computed, and therefore read-only.", 'NoModificationAllowedError');
        if (s.el && s.el.setAttribute) __ptSetA(s.el, 'style', String(v));
        __markDirty(s.el || null);
      });
    try {
      Object.defineProperty(proto, Symbol.iterator, {
        value: function* () { const s = st(this); if (!s) return; for (const k of (s.computed ? s.names : __styleNames(s.read()))) yield k; },
        writable: true, configurable: true,
      });
    } catch (e) {}
    return proto;
  };

  // Descriptors for the 700+ CSS properties are built once and shared: they
  // reach their declaration through `this`. Per-element accessors made each
  // `el.style` read cost ~0.5 ms.
  // Nine -epub- names: Chrome lists them among the declaration's own keys, but
  // they have no descriptor, `in` says no and reading gives `undefined`. That
  // is a V8 interceptor's shape, reproducible only with traps; real properties
  // would break both `in` and the descriptor.
  const EPUB_NAMES = ['epubCaptionSide', 'epubTextCombine', 'epubTextEmphasis',
    'epubTextEmphasisColor', 'epubTextEmphasisStyle', 'epubTextOrientation',
    'epubTextTransform', 'epubWordBreak', 'epubWritingMode'];
  const EPUB_SET = new Set(EPUB_NAMES);
  // What each answers for computed `getPropertyValue('-epub-…')`: they are
  // aliases of ordinary properties.
  const EPUB_ALIAS = {
    '-epub-caption-side': 'caption-side', '-epub-text-combine': 'text-combine-upright',
    '-epub-text-emphasis': 'text-emphasis', '-epub-text-emphasis-color': 'text-emphasis-color',
    '-epub-text-emphasis-style': 'text-emphasis-style', '-epub-text-orientation': 'text-orientation',
    '-epub-text-transform': 'text-transform', '-epub-word-break': 'word-break',
    '-epub-writing-mode': 'writing-mode',
  };
  // Names are inserted where Chrome has them, right after `emptyCells`.
  const __withEpub = (keys) => {
    const at = __s_indexOf(keys, 'emptyCells');
    if (at < 0) return keys;
    return __s_slice(keys, 0, at + 1).concat(EPUB_NAMES, __s_slice(keys, at + 1));
  };
  // Declaration properties are data properties, not accessors: `color`'s
  // descriptor holds `value: "red"`, no `get`/`set`. CSS property names are
  // kept as a set: they are asked thousands of times (1200 names per
  // enumeration), so identifying a name must be one lookup, not `Reflect`.
  let __CSS_PROP_SET = null;
  const __cssPropSet = () => (__CSS_PROP_SET || (__CSS_PROP_SET = new Set(CSS_PROPS)));
  const __declTraps = (valueOf) => ({
    ownKeys: (t) => __withEpub(Reflect.ownKeys(t)),
    getOwnPropertyDescriptor: (t, p) => {
      if (typeof p === 'string') {
        if (EPUB_SET.has(p)) return undefined;
        if (__cssPropSet().has(p)) {
          return { value: valueOf(t, p), writable: true, enumerable: true, configurable: true };
        }
      }
      return Reflect.getOwnPropertyDescriptor(t, p);
    },
  });

  let __STYLE_DESCS = null;
  const __styleDescs = () => {
    if (__STYLE_DESCS) return __STYLE_DESCS;
    const d = {};
    for (const name of CSS_PROPS) {
      const key = dash(name);
      d[name] = {
        get() {
          const s = __cssReaders.get(this);
          if (!s) return '';
          const m = s.computed ? s.map : s.read();
          return m.get(key) || __longhandFrom(m, key);
        },
        set(v) {
          const s = __cssReaders.get(this);
          if (!s || s.computed) return;
          const m = s.read();
          if (__cssImportantIn(v)) return;
          if (v === '' || v == null) __cssDrop(m, key); else { __cssStore(m, key, v); __cssImp(m).delete(key); }
          s.write(m);
        },
        enumerable: true, configurable: true,
      };
    }
    __STYLE_DESCS = d;
    return d;
  };

  // A `style` attribute's declarations as a map, priority kept beside it:
  // `getPropertyValue` answers without `!important`, `getPropertyPriority`
  // with it.
  function __parseStyleText(text) {
    const m = new Map();
    for (const part of __s_split(text, ';')) {
      const i = __s_indexOf(part, ':');
      if (i < 0) continue;
      const k = __cssKey(__s_slice(part, 0, i));
      let v = __s_trim(__s_slice(part, i + 1));
      const im = /!\s*important\s*$/i.exec(v);
      if (im) v = __s_trim(__s_slice(v, 0, im.index));
      if (k) { m.set(k, v); if (im) __cssImp(m).add(k); }
    }
    return m;
  }
  // Read-only parses for the engine, by attribute text: siblings often carry
  // the same text. Cleared whole when large.
  let __styleTextParsed = new Map();
  function __styleTextMap(text) {
    let m = __styleTextParsed.get(text);
    if (m === undefined) {
      if (__styleTextParsed.size >= 4096) __styleTextParsed = new Map();
      m = __parseStyleText(text);
      __styleTextParsed.set(text, m);
    }
    return m;
  }

  function makeStyle(el) {
    let cachedText = null, cachedMap = new Map();
    const read = () => {
      const text = String((el && el.getAttribute && __ptGetA(el, 'style')) || '');
      if (text === cachedText) return cachedMap;
      const m = __parseStyleText(text);
      cachedText = text; cachedMap = m;
      return m;
    };
    let indexed = 0;
    // Indexed properties are own and enumerated first (`0`, `1`, then
    // `accentColor`); integer keys come first in JS anyway.
    const reindex = (names) => {
      for (let i = 0; i < names.length; i++) {
        try { Object.defineProperty(target, String(i), { value: names[i], enumerable: true, configurable: true }); } catch (e) {}
      }
      for (let i = names.length; i < indexed; i++) { try { delete target[String(i)]; } catch (e) {} }
      indexed = names.length;
    };
    const write = (m) => {
      // The trailing semicolon is required; Chrome adds it.
      const text = __styleText(m);
      cachedText = text; cachedMap = m;
      // A rule's declarations changed through CSSOM: every cascade may differ.
      if (!el) __styleAllStale = true;
      if (el && el.setAttribute) __ptSetA(el, 'style', text);
      reindex(__styleNames(m));
      __markDirty(el || null);
    };
    // Chrome's shape: methods and `length` on the prototype; own properties are
    // the CSS property names, all 703, in the same order.
    const target = Object.create(__inlineStyleProto(), __styleDescs());
    __cssReaders.set(target, { read, write, el });
    reindex(__styleNames(read()));
    const px = __ptProxy(target, {
      ...__declTraps((t, p) => { const m = read(), k = dash(p); return m.get(k) || __longhandFrom(m, k); }),
      get: (t, p) => {
        if (typeof p === 'string' && EPUB_SET.has(p)) return undefined;
        if (typeof p === 'string' && !(p in t)) {
          const m = read(), k = dash(p);
          return m.get(k) || __longhandFrom(m, k);
        }
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (p === 'cssText') { t.cssText = v; return true; }
        // Through the setter trap, same rules as the setter: an empty value
        // removes the property.
        const m = read(), k = dash(String(p));
        // Chrome rejects a value with `!important` set via a property.
        if (__cssImportantIn(v)) return true;
        if (v === '' || v == null) __cssDrop(m, k); else { __cssStore(m, k, v); __cssImp(m).delete(k); }
        write(m); return true;
      },
    });
    __declRaw.set(px, read);
    return px;
  }

  // ---- tree walking ---------------------------------------------------------
  // The engine uses an array internally (concat/filter); pages get a collection.
  function __docTags(doc, t) { return doc.documentElement ? __tags(doc.documentElement, t) : []; }
  const __baseMemo = new WeakMap();
  function __tags(root, t) {
    // By internal name, not `tagName`: internal walks must not use
    // page-visible accessors, which a page can wrap and log.
    const local = __s_toLowerCase(String(t));
    return collect(root, (e) => t === '*' || e.__ptLocal === local);
  }
  function __tagsNS(root, ns, local) {
    const L = String(local), N = ns === null ? null : String(ns);
    return collect(root, (e) => (L === '*' || e.__ptLocal === L || e.__ptLocal === L)
      && (N === '*' || (e.namespaceURI || null) === (N === '' ? null : N)));
  }
  function collect(root, pred) {
    const out = []; walk(root, e => { if (pred(e)) out.push(e); });
    out.item = (i) => out[i] || null; return out;
  }
  /// Whether an element has a stylesheet. A `<link>` only with `stylesheet` in
  /// `rel` and a non-empty `href`: chess.com keeps
  /// `<link rel="stylesheet" data-href=…>` in reserve, which Chrome does not
  /// list, and Turnstile's api.js sends the sheet count to the widget.
  function __ptHasSheet(e) {
    if (e.__ptLocal === 'style') return true;
    if (e.__ptLocal !== 'link') return false;
    const rel = __s_split(__s_toLowerCase(String(__ptGetA(e, 'rel') || '')), /[\t\n\f\r ]+/);
    if (__s_indexOf(rel, 'stylesheet') < 0 || __s_indexOf(rel, 'alternate') >= 0) return false;
    return !!__s_trim(String(__ptGetA(e, 'href') || ''));
  }
  /// Stylesheet owners in document order.
  function __sheetOwners(root) {
    const own = [];
    walk(root, (c) => { if (__ptHasSheet(c)) own.push(c); });
    return own;
  }

  // Stops at the first match in tree order.
  // Recursion is faster on the trees pages have; below `__WALK_DEPTH`
  // levels the rest of the walk goes on an explicit stack.
  function firstMatch(node, pred) { return __firstMatchRec(node.__ptKids, pred, 0); }
  function __firstMatchRec(kids, pred, depth) {
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      if (c.__ptType !== ELEMENT_NODE) continue;
      if (pred(c)) return c;
      const k = c.__ptKids;
      if (k && k.length) {
        const r = depth < __WALK_DEPTH ? __firstMatchRec(k, pred, depth + 1) : __firstMatchDeep(c, pred);
        if (r) return r;
      }
    }
    return null;
  }
  function __firstMatchDeep(node, pred) {
    const st = [node.__ptKids, 0];
    while (st.length) {
      const top = st.length - 2;
      const kids = st[top], i = st[top + 1];
      if (i >= kids.length) { st.length = top; continue; }
      st[top + 1] = i + 1;
      const c = kids[i];
      if (c.__ptType !== ELEMENT_NODE) continue;
      if (pred(c)) return c;
      st.push(c.__ptKids || __NO_NODES, 0);
    }
    return null;
  }
  const __isHtmlEl = (e) => e.__ptNS === undefined || e.__ptNS === 'http://www.w3.org/1999/xhtml';
  function __htmlChild(doc, a, b) {
    const de = doc.documentElement;
    if (!de || de.__ptLocal !== 'html' || !__isHtmlEl(de)) return null;
    for (const c of de.__ptKids) {
      if (c.__ptType === ELEMENT_NODE && (c.__ptLocal === a || c.__ptLocal === b) && __isHtmlEl(c)) return c;
    }
    return null;
  }
  const __docTitle = (doc) => (doc.documentElement ? firstMatch(doc.documentElement, (e) => e.__ptLocal === 'title') : null);
  // Class names split on ASCII whitespace only, as in Chrome (a no-break
  // space is part of the name); the element side is the cached class set.
  function __byClass(root, c) {
    const cs = __s_split(String(c), /[\t\n\f\r ]+/).filter(Boolean);
    if (!cs.length) return [];
    return collect(root, (e) => {
      const set = __ptClassSet(e);
      if (set === null) return false;
      for (let i = 0; i < cs.length; i++) if (!set.has(cs[i])) return false;
      return true;
    });
  }
  // Elements below `node` in tree order, without a stack frame per level
  // (Chrome queries trees tens of thousands deep): (children, next index)
  // runs over the live child lists.
  function walk(node, visit) { __walkRec(node.__ptKids || __NO_NODES, visit, 0); }
  function __walkRec(kids, visit, depth) {
    for (let i = 0; i < kids.length; i++) {
      const c = kids[i];
      if (c.__ptType !== ELEMENT_NODE) continue;
      visit(c);
      const k = c.__ptKids;
      if (k && k.length) { if (depth < __WALK_DEPTH) __walkRec(k, visit, depth + 1); else __walkDeep(c, visit); }
    }
  }
  function __walkDeep(node, visit) {
    const st = [node.__ptKids || __NO_NODES, 0];
    while (st.length) {
      const top = st.length - 2;
      const kids = st[top], i = st[top + 1];
      if (i >= kids.length) { st.length = top; continue; }
      st[top + 1] = i + 1;
      const c = kids[i];
      if (c.__ptType === ELEMENT_NODE) { visit(c); st.push(c.__ptKids || __NO_NODES, 0); }
    }
  }

  // ---- selector engine ------------------------------------------------------
  // Full selector parsing: simple, compound, all four combinators and
  // pseudo-classes (chess.com puts all its variables in `:root { … }`).
  const __selCache = new Map();
  const __SEL_NEVER = () => false;
  const __SEL_ANY = () => true;

  /// Selector list -> top-level parts (commas inside parens, brackets and
  /// quotes do not split).
  function __selSplit(s) {
    const out = [];
    let depth = 0, q = null, start = 0;
    s = String(s);
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '\\') { i++; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (c === ',' && depth === 0) { out.push(__s_slice(s, start, i)); start = i + 1; }
    }
    out.push(__s_slice(s, start));
    return out.map((x) => __s_trim(x));
  }

  // Name code points: [A-Za-z0-9_-] and everything from U+00A0 up.
  // What matching read around an element, kept on its parent: 1 the
  // children's positions from the start (`:first-child`, `:nth-child`), 8
  // from the end (`:last-child`, `:nth-last-child`), 2 their earlier
  // siblings (`+`, `~`, `:nth-child(of S)`); on the element itself, 4 its
  // children (`:empty`). 16 when such a read was left of a selector's
  // subject (`li:first-child a`, `.a + div p`) or inside `:has()`: then
  // what is below the children depends on it too. 64 when `:has(+ x)` or
  // `:has(~ x)` read later siblings: earlier ones depend on them. A change
  // of children or an attribute restyles past the element only where these
  // say a rule looked (Blink keeps the same "affected by" flags).
  let __matchDeep = false;
  const __kidDeps = new WeakMap();
  const __kidMark = (p, bit) => {
    if (!p) return;
    if (__matchDeep) bit |= 16;
    const f = __kidDeps.get(p) | 0;
    if ((f & bit) !== bit) __kidDeps.set(p, f | bit);
  };
  const __selNameCh = (c) => c >= 0xa0 || (c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 95 || c === 45;
  // Match tests are built here, outside the parser: a closure made inside it
  // would keep the whole parse scope alive for every rule.
  const __tLocal = (n) => (e) => e.__ptLocal === n;
  const __tTag = (low, n) => (e) => e.__ptLocal === low || (e.__ptNS && e.__ptNS !== 'http://www.w3.org/1999/xhtml' && e.__ptLocal === n);
  // The attribute, not `e.id`: a page-visible getter behind a brand check.
  const __tId = (n) => (e) => __ptGetA(e, 'id') === n;
  const __tClass = (n) => (e) => { const set = __ptClassSet(e); return set !== null && set.has(n); };
  const __tScope = (e, ctx) => !!(ctx && ctx.scope) && e === ctx.scope;
  const __tAll = (tests) => {
    const n = tests.length;
    return (e, ctx) => { for (let k = 0; k < n; k++) if (!tests[k](e, ctx)) return false; return true; };
  };
  function __tAttr(nm, name, op, want, ci) {
    return (e) => {
      let a = __ptGetA(e, nm);
      if (a == null && nm !== name) a = __ptGetA(e, name);
      if (a == null) return false;
      if (!op) return true;
      if (ci) a = __s_toLowerCase(a);
      switch (op) {
        case '=': return a === want;
        case '^=': return want !== '' && __s_startsWith(a, want);
        case '$=': return want !== '' && __s_endsWith(a, want);
        case '*=': return want !== '' && __s_indexOf(a, want) >= 0;
        case '~=': return want !== '' && !/\s/.test(want) && __s_indexOf(__s_split(a, /[\t\n\f\r ]+/), want) >= 0;
        case '|=': return a === want || __s_startsWith(a, want + '-');
      }
      return false;
    };
  }

  function __selParse(src) {
    let i = 0;
    const s = String(src);
    const ws = () => { const a = i; while (i < s.length && /\s/.test(s[i])) i++; return i > a; };
    const identStart = (c) => c != null && (c === '\\' || (__selNameCh(__s_charCodeAt(c, 0)) && !/[0-9]/.test(c)));
    // Runs of plain characters are sliced, not appended one by one: a name
    // built char by char stays a chain of cons strings as long as the rule.
    const ident = () => {
      let out = '', a = i;
      while (i < s.length) {
        if (s[i] === '\\') {
          out += __s_slice(s, a, i);
          const hex = /^[0-9a-fA-F]{1,6}\s?/.exec(__s_slice(s, i + 1, i + 8));
          if (hex) { out += String.fromCodePoint(parseInt(hex[0], 16) || 0xfffd); i += 1 + hex[0].length; }
          else { out += s[i + 1] || ''; i += 2; }
          a = i;
        } else if (__selNameCh(__s_charCodeAt(s, i))) i++;
        else break;
      }
      return out === '' ? __s_slice(s, a, i) : out + __s_slice(s, a, i);
    };
    const fail = () => { throw new SyntaxError('selector'); };
    // Paren content as a string, respecting nesting and quotes.
    const paren = () => {
      if (s[i] !== '(') fail();
      let depth = 1, q = null; const a = ++i;
      for (; i < s.length; i++) {
        const c = s[i];
        if (c === '\\') { i++; continue; }
        if (q) { if (c === q) q = null; continue; }
        if (c === '"' || c === "'") q = c;
        else if (c === '(') depth++;
        else if (c === ')' && --depth === 0) break;
      }
      if (depth) fail();
      return __s_slice(s, a, i++);
    };
    const compound = () => {
      const tests = [];
      const spec = [0, 0, 0];
      const toks = [];
      let any = false;
      for (;;) {
        const c = s[i];
        if (c === '*') {
          i++; any = true;
          if (s[i] === '|') { i++; if (s[i] === '*') i++; else { spec[2]++; tests.push(__tLocal(__s_toLowerCase(ident()))); } }
          continue;
        }
        if (c === '|') { i++; continue; }
        if (identStart(c)) {
          if (any || tests.length) break;
          let n = ident(), ns = false;
          if (s[i] === '|' && s[i + 1] !== '=') { ns = true; i++; if (s[i] === '*') { i++; any = true; continue; } n = ident(); }
          const low = __s_toLowerCase(n);
          if (!ns) toks.push('t' + low);
          spec[2]++; any = true;
          tests.push(__tTag(low, n));
          continue;
        }
        if (c === '#') { i++; const n = ident(); if (!n) fail(); spec[0]++; toks.push('i' + n); tests.push(__tId(n)); any = true; continue; }
        if (c === '.') {
          i++; const n = ident(); if (!n) fail(); spec[1]++; toks.push('c' + n);
          tests.push(__tClass(n));
          any = true; continue;
        }
        if (c === '[') {
          i++; ws();
          let name = ident(), ns = false;
          if (s[i] === '|' && s[i + 1] !== '=') { ns = true; i++; name = ident(); }
          if (!ns && name) toks.push('a' + __s_toLowerCase(name));
          ws();
          let op = null, val = '', flag = '';
          if (s[i] === ']') i++;
          else {
            const m = /^([~^$*|]?=)/.exec(__s_slice(s, i));
            if (!m) fail();
            op = m[1]; i += op.length; ws();
            if (s[i] === '"' || s[i] === "'") {
              const q = s[i++]; let v = '';
              while (i < s.length && s[i] !== q) { if (s[i] === '\\') { v += s[i + 1] || ''; i += 2; } else v += s[i++]; }
              i++; val = v;
            } else val = ident();
            ws();
            if (/[isIS]/.test(s[i] || '') && !/[\w-]/.test(s[i + 1] || '')) { flag = __s_toLowerCase(s[i]); i++; ws(); }
            if (s[i] !== ']') fail();
            i++;
          }
          spec[1]++; any = true;
          const nm = __s_toLowerCase(name);
          const ci = flag === 'i';
          const want = ci ? __s_toLowerCase(val) : val;
          tests.push(__tAttr(nm, name, op, want, ci));
          continue;
        }
        if (c === ':' && s[i + 1] === ':') {
          // Pseudo-element: never matches an element.
          i += 2; ident(); if (s[i] === '(') paren();
          spec[2]++; any = true; tests.push(__SEL_NEVER);
          continue;
        }
        if (c === ':') {
          i++;
          const name = __s_toLowerCase(ident());
          if (!name) fail();
          // Legacy single-colon pseudo-elements.
          if (/^(before|after|first-line|first-letter)$/.test(name)) { spec[2]++; any = true; tests.push(__SEL_NEVER); continue; }
          const arg = s[i] === '(' ? paren() : null;
          const r = __selPseudo(name, arg);
          spec[0] += r.spec[0]; spec[1] += r.spec[1]; spec[2] += r.spec[2];
          tests.push(r.test); any = true;
          continue;
        }
        if (c === '&') { i++; any = true; spec[1]++; tests.push(__tScope); continue; }
        break;
      }
      if (!any) fail();
      const n = tests.length;
      // A pseudo-element or a state this engine never has: the compound can
      // never match (only `:not()` turns that around, and it is its own test).
      const test = n === 0 ? __SEL_ANY : tests.includes(__SEL_NEVER) ? __SEL_NEVER : n === 1 ? tests[0] : __tAll(tests.slice());
      return { test, spec, toks };
    };
    // Complex selector; `relative` is for `:has()`, which may start with a
    // combinator.
    const complex = (relative) => {
      const comps = [], combs = [], toks = [];
      const spec = [0, 0, 0];
      ws();
      let lead = null;
      if (relative && /[>+~]/.test(s[i] || '')) { lead = s[i++]; ws(); }
      for (;;) {
        const c = compound();
        comps.push(c.test);
        toks.push(c.toks);
        spec[0] += c.spec[0]; spec[1] += c.spec[1]; spec[2] += c.spec[2];
        const had = ws();
        if (i >= s.length) break;
        const ch = s[i];
        if (ch === '>' || ch === '+' || ch === '~') { i++; ws(); combs.push(ch); continue; }
        if (ch === ',' || ch === ')') break;
        if (had) { combs.push(' '); continue; }
        fail();
      }
      // Tokens every match needs among the subject's ancestors. A compound
      // left of a descendant or child combinator is an ancestor of the
      // subject even past a sibling one (in `.a b + c` the `.a` holds `b`,
      // and `c` beside it); a compound left of `+`/`~` is a sibling and is
      // skipped. A relative selector (`:has()`) keeps to the first run.
      const need = [];
      for (let k = comps.length - 2; k >= 0; k--) {
        if (combs[k] === ' ' || combs[k] === '>') need.push(...toks[k]);
        else if (relative) break;
      }
      let never = false;
      for (let k = 0; k < comps.length; k++) if (comps[k] === __SEL_NEVER) never = true;
      return { comps: comps.slice(), combs: combs.slice(), spec, lead, needH: need.length ? need.map(__bloomHash) : null, never };
    };
    const list = (relative) => {
      const out = [];
      for (;;) {
        out.push(complex(relative));
        ws();
        if (s[i] === ',') { i++; continue; }
        break;
      }
      if (i < s.length) fail();
      return out.slice();
    };
    return list(false);
  }

  const __parentEl = (e) => { const p = e.__ptParent; return p && p.__ptType === ELEMENT_NODE ? p : null; };
  // `doc.documentElement` without the page-facing accessor.
  const __docElement = (d) => {
    const kids = d && d.__ptKids;
    if (kids) for (let i = 0; i < kids.length; i++) if (kids[i].__ptType === ELEMENT_NODE) return kids[i];
    return null;
  };

  // Ancestor filter, as browsers do it: a 1024-bit set of the tag, id, class
  // and attribute-name tokens on an element's ancestors (tags and attribute
  // names lowercased on both sides). A rule whose ancestor compounds need a
  // token the set lacks cannot match and is not tested. Must agree with the
  // matcher: ancestors by `__parentEl`, classes by `__ptClassSet`.
  function __bloomHash(t) {
    let x = 2166136261;
    for (let i = 0; i < t.length; i++) { x ^= __s_charCodeAt(t, i); x = Math.imul(x, 16777619); }
    return x >>> 0;
  }
  const __BLOOM_NONE = new Int32Array(32);
  let __passBloom = new WeakMap();
  function __bloomAdd(b, t) { const h = __bloomHash(t); b[(h >>> 5) & 31] |= 1 << (h & 31); }
  function __ancBloom(el) {
    const p = __parentEl(el);
    if (!p) return __BLOOM_NONE;
    const b = __passBloom.get(p);
    if (b) return b;
    // Ancestors' filters first, from the top, without a frame per level.
    const chain = [];
    for (let a = __parentEl(p); a && !__passBloom.get(a); a = __parentEl(a)) chain.push(a);
    for (let i = chain.length - 1; i >= 0; i--) __ancBloomOf(chain[i]);
    return __ancBloomOf(p);
  }
  // The filter of the ancestors of `p`'s children: `p`'s own on top of its
  // parent's (already kept when called from `__ancBloom`).
  function __ancBloomOf(p) {
    const b = Int32Array.from(__ancBloom(p));
    __bloomAdd(b, 't' + __s_toLowerCase(String(p.__ptLocal || '')));
    if (p.__ptAttrs) for (const name of p.__ptAttrs.keys()) __bloomAdd(b, 'a' + __s_toLowerCase(String(name)));
    const id = __ptGetA(p, 'id');
    if (id) __bloomAdd(b, 'i' + id);
    const set = __ptClassSet(p);
    if (set) for (const c of set) if (c) __bloomAdd(b, 'c' + c);
    __passBloom.set(p, b);
    return b;
  }
  function __bloomMayMatch(list, b) {
    for (const cx of list) {
      const need = cx.needH;
      if (!need) return true;
      let ok = true;
      for (let k = 0; k < need.length; k++) {
        const h = need[k];
        if (!(b[(h >>> 5) & 31] & (1 << (h & 31)))) { ok = false; break; }
      }
      if (ok) return true;
    }
    return false;
  }
  const __prevEl = (e) => { let p = e.previousSibling; while (p && p.__ptType !== ELEMENT_NODE) p = p.previousSibling; return p; };
  const __nextEl = (e) => { let p = e.nextSibling; while (p && p.__ptType !== ELEMENT_NODE) p = p.nextSibling; return p; };

  function __selMatchComplex(el, cx, idx, ctx) {
    const deep = __matchDeep, last = cx.comps.length - 1;
    if (idx !== last) __matchDeep = true;
    const ok = cx.comps[idx](el, ctx);
    __matchDeep = deep;
    if (!ok) return false;
    if (idx === 0) {
      if (!cx.lead && !cx.anchored) return true;
      // `:has(> a)`: the anchor itself is on the left.
      const a = ctx.hasAnchor;
      const comb = cx.lead || ' ';
      if (comb === '>') return __parentEl(el) === a;
      if (comb === ' ') { for (let p = __parentEl(el); p; p = __parentEl(p)) if (p === a) return true; return false; }
      __kidMark(el.__ptParent, 64);
      if (comb === '+') return __prevEl(el) === a;
      for (let p = __prevEl(el); p; p = __prevEl(p)) if (p === a) return true;
      return false;
    }
    const comb = cx.combs[idx - 1];
    if (comb === '>') { const p = __parentEl(el); return !!p && __selMatchComplex(p, cx, idx - 1, ctx); }
    if (comb === ' ') {
      for (let p = __parentEl(el); p; p = __parentEl(p)) if (__selMatchComplex(p, cx, idx - 1, ctx)) return true;
      return false;
    }
    __kidMark(el.__ptParent, idx !== last ? 18 : 2);
    if (comb === '+') { const p = __prevEl(el); return !!p && __selMatchComplex(p, cx, idx - 1, ctx); }
    for (let p = __prevEl(el); p; p = __prevEl(p)) if (__selMatchComplex(p, cx, idx - 1, ctx)) return true;
    return false;
  }

  function __selCompiled(sel) {
    const key = String(sel);
    let hit = __selCache.get(key);
    if (hit !== undefined) return hit;
    try { hit = __selParse(key); } catch (e) { hit = null; }
    if (__selCache.size > 50000) __selCache.clear();
    __selCache.set(key, hit);
    return hit;
  }
  const __selAny = (list, e, ctx) => {
    for (const cx of list) if (__selMatchComplex(e, cx, cx.comps.length - 1, ctx)) return true;
    return false;
  };
  const __maxSpec = (list) => list.reduce((m, cx) => {
    const a = cx.spec, b = m;
    return (a[0] - b[0] || a[1] - b[1] || a[2] - b[2]) > 0 ? a : b;
  }, [0, 0, 0]);
  // The list in `:is()`/`:where()` is forgiving: an invalid part drops out
  // instead of failing the whole.
  const __selForgiving = (arg) => {
    const out = [];
    for (const part of __selSplit(arg)) {
      if (!part) continue;
      const c = __selCompiled(part);
      if (c) out.push(...c);
    }
    return out;
  };
  // An+B from `:nth-child()`.
  function __nthParse(t) {
    t = __s_replace(__s_toLowerCase(__s_trim(t)), /\s+/g, '');
    if (t === 'odd') return [2, 1];
    if (t === 'even') return [2, 0];
    let m = /^([+-]?\d*)n([+-]\d+)?$/.exec(t);
    if (m) {
      const a = m[1] === '' || m[1] === '+' ? 1 : m[1] === '-' ? -1 : parseInt(m[1], 10);
      return [a, m[2] ? parseInt(m[2], 10) : 0];
    }
    if ((m = /^[+-]?\d+$/.exec(t))) return [0, parseInt(t, 10)];
    return null;
  }
  const __nthOk = (ab, pos) => {
    const [a, b] = ab;
    if (a === 0) return pos === b;
    const n = (pos - b) / a;
    return Number.isInteger(n) && n >= 0;
  };
  const __FORM_CTL = new Set(['button', 'input', 'select', 'textarea', 'optgroup', 'option', 'fieldset']);
  const __TEXTISH = /^(text|search|url|tel|email|password|date|month|week|time|datetime-local|number)$/;
  const __inputType = (e) => __s_toLowerCase(String(__ptGetA(e, 'type') || 'text'));
  const __isDisabled = (e) => {
    if (!__FORM_CTL.has(e.__ptLocal)) return false;
    if (__ptHasA(e, 'disabled')) return true;
    for (let p = __parentEl(e); p; p = __parentEl(p)) {
      if (p.__ptLocal === 'fieldset' && __ptHasA(p, 'disabled')) {
        // Except what is inside the first legend.
        const legend = [...p.children].find((k) => k.__ptLocal === 'legend');
        if (!(legend && legend.contains(e))) return true;
      }
    }
    return false;
  };
  const __valueOf = (e) => { try { return String(e.value == null ? '' : e.value); } catch (x) { return ''; } };
  const __isInvalid = (e) => {
    const t = e.__ptLocal;
    if (t === 'form' || t === 'fieldset') {
      let bad = false;
      walk(e, (k) => { if (!bad && __isInvalid(k)) bad = true; });
      return bad;
    }
    if (!(t === 'input' || t === 'select' || t === 'textarea' || t === 'button')) return false;
    return __candidate(e) && !__validity(e).valid;
  };

  function __selPseudo(name, arg) {
    const B = [0, 1, 0];
    const doc = () => globalThis.document;
    const sib = (e, dir, same) => {
      let n = 1;
      for (let p = dir < 0 ? __prevEl(e) : __nextEl(e); p; p = dir < 0 ? __prevEl(p) : __nextEl(p)) {
        if (!same || p.__ptLocal === e.__ptLocal) n++;
      }
      return n;
    };
    switch (name) {
      case 'root': return { spec: B, test: (e) => !!e.__ptDoc && e === __docElement(e.__ptDoc) };
      case 'scope': return { spec: B, test: (e, ctx) => (ctx && ctx.scope && ctx.scope.__ptType === ELEMENT_NODE ? e === ctx.scope : !!e.__ptDoc && e === __docElement(e.__ptDoc)) };
      case 'is': case 'matches': case '-webkit-any': case 'where': {
        const list = __selForgiving(arg || '');
        return { spec: name === 'where' ? [0, 0, 0] : __maxSpec(list),
          test: list.every((cx) => cx.never) ? __SEL_NEVER : (e, ctx) => __selAny(list, e, ctx) };
      }
      case 'not': {
        const list = __selCompiled(arg || '');
        if (!list) throw new SyntaxError('selector');
        return { spec: __maxSpec(list), test: (e, ctx) => !__selAny(list, e, ctx) };
      }
      case 'has': {
        const parts = __selSplit(arg || '');
        const rel = [];
        for (const p of parts) {
          let one;
          try { one = __selParseRelative(p); } catch (x) { one = null; }
          if (one) rel.push(one);
        }
        if (!rel.length) throw new SyntaxError('selector');
        return {
          spec: __maxSpec(rel),
          test: (e) => {
            for (const cx of rel) {
              const ctx = { hasAnchor: e };
              const lead = cx.lead || ' ';
              const scope = lead === '+' || lead === '~' ? __parentEl(e) : e;
              if (!scope) continue;
              let found = false;
              const deep = __matchDeep;
              __matchDeep = true;
              try { walk(scope, (k) => { if (!found && __selMatchComplex(k, cx, cx.comps.length - 1, ctx)) found = true; }); } finally { __matchDeep = deep; }
              if (found) return true;
            }
            return false;
          },
        };
      }
      case 'first-child': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 1); return !__prevEl(e) && !!e.__ptParent; } };
      case 'last-child': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 8); return !__nextEl(e) && !!e.__ptParent; } };
      case 'only-child': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 9); return !__prevEl(e) && !__nextEl(e) && !!e.__ptParent; } };
      case 'first-of-type': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 1); return sib(e, -1, true) === 1; } };
      case 'last-of-type': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 8); return sib(e, 1, true) === 1; } };
      case 'only-of-type': return { spec: B, test: (e) => { __kidMark(e.__ptParent, 9); return sib(e, -1, true) === 1 && sib(e, 1, true) === 1; } };
      case 'nth-child': case 'nth-last-child': case 'nth-of-type': case 'nth-last-of-type': {
        let expr = String(arg || ''), of = null;
        const m = /^(.*?)\s+of\s+(.*)$/i.exec(expr);
        if (m && /child/.test(name)) { expr = m[1]; of = __selCompiled(m[2]); if (!of) throw new SyntaxError('selector'); }
        const ab = __nthParse(expr);
        if (!ab) throw new SyntaxError('selector');
        const last = /last/.test(name), type = /type/.test(name);
        const spec = of ? [B[0] + __maxSpec(of)[0], B[1] + __maxSpec(of)[1], __maxSpec(of)[2]] : B;
        return {
          spec,
          test: (e, ctx) => {
            if (!e.__ptParent) return false;
            __kidMark(e.__ptParent, (last ? 8 : 1) | (of ? 2 : 0));
            if (of && !__selAny(of, e, ctx)) return false;
            let n = 1;
            for (let p = last ? __nextEl(e) : __prevEl(e); p; p = last ? __nextEl(p) : __prevEl(p)) {
              if (type ? p.__ptLocal === e.__ptLocal : !of || __selAny(of, p, ctx)) n++;
            }
            return __nthOk(ab, n);
          },
        };
      }
      case 'empty': return { spec: B, test: (e) => { __kidMark(e, 4); return !(e.__ptKids || []).some((k) => k.__ptType === ELEMENT_NODE || ((k.__ptType === TEXT_NODE || k.__ptType === 4) && k.data !== '')); } };
      case 'checked': return { spec: B, test: (e) => (e.__ptLocal === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && !!e.checked) || (e.__ptLocal === 'option' && !!e.selected) };
      case 'indeterminate': return { spec: B, test: (e) => e.__ptLocal === 'input' && __inputType(e) === 'checkbox' && !!e.indeterminate };
      case 'default': return { spec: B, test: (e) => (e.__ptLocal === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && __ptHasA(e, 'checked')) || (e.__ptLocal === 'option' && __ptHasA(e, 'selected')) };
      case 'disabled': return { spec: B, test: (e) => __isDisabled(e) };
      case 'enabled': return { spec: B, test: (e) => __FORM_CTL.has(e.__ptLocal) && !__isDisabled(e) };
      case 'required': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.__ptLocal) && __ptHasA(e, 'required') };
      case 'optional': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.__ptLocal) && !__ptHasA(e, 'required') };
      case 'read-write': case 'read-only': {
        const rw = (e) => {
          if (e.__ptLocal === 'textarea') return !__ptHasA(e, 'readonly') && !__isDisabled(e);
          if (e.__ptLocal === 'input') return __TEXTISH.test(__inputType(e)) && !__ptHasA(e, 'readonly') && !__isDisabled(e);
          for (let p = e; p; p = __parentEl(p)) {
            const v = __ptGetA(p, 'contenteditable');
            if (v != null) return v !== 'false';
          }
          return false;
        };
        return { spec: B, test: name === 'read-write' ? rw : (e) => !rw(e) };
      }
      case 'placeholder-shown': return { spec: B, test: (e) => (e.__ptLocal === 'input' || e.__ptLocal === 'textarea') && __ptHasA(e, 'placeholder') && __valueOf(e) === '' };
      case 'valid': return { spec: B, test: (e) => /^(input|select|textarea|form|fieldset)$/.test(e.__ptLocal) && !__isInvalid(e) };
      case 'invalid': return { spec: B, test: (e) => __isInvalid(e) };
      case 'link': case 'any-link': case '-webkit-any-link': return { spec: B, test: (e) => (e.__ptLocal === 'a' || e.__ptLocal === 'area') && __ptHasA(e, 'href') };
      case 'focus': return { spec: B, test: (e) => { const d = e.__ptDoc; return !!d && d.__ptActive === e; } };
      case 'focus-within': return { spec: B, test: (e) => { const d = e.__ptDoc; const a = d && d.__ptActive; return !!a && (a === e || e.contains(a)); } };
      case 'target': return { spec: B, test: (e) => { try { const h = decodeURIComponent(__s_slice(String(globalThis.location && globalThis.location.hash || ''), 1)); return !!h && e.id === h; } catch (x) { return false; } } };
      case 'lang': {
        const want = __s_toLowerCase(__s_replace(__s_trim(String(arg || '')), /^["']|["']$/g, ''));
        return { spec: B, test: (e) => {
          for (let p = e; p; p = __parentEl(p)) {
            const v = __ptGetA(p, 'lang');
            if (v != null) { const l = __s_toLowerCase(v); return l === want || __s_startsWith(l, want + '-'); }
          }
          return false;
        } };
      }
      case 'dir': {
        const want = __s_toLowerCase(__s_trim(String(arg || '')));
        return { spec: B, test: (e) => {
          for (let p = e; p; p = __parentEl(p)) {
            const v = __s_toLowerCase(String(__ptGetA(p, 'dir') || ''));
            if (v === 'ltr' || v === 'rtl') return v === want;
          }
          return want === 'ltr';
        } };
      }
      case 'open': return { spec: B, test: (e) => (e.__ptLocal === 'details' || e.__ptLocal === 'dialog') && __ptHasA(e, 'open') };
      case 'defined': return { spec: B, test: (e) => __s_indexOf(e.__ptLocal, '-') < 0 || !!(globalThis.customElements && globalThis.customElements.get && globalThis.customElements.get(e.__ptLocal)) };
      case 'host': case 'host-context': case 'state':
        return { spec: B, test: __SEL_NEVER };
    }
    // Anything else is a state we never have (`:hover`, `:active`,
    // `:visited`, `:autofill`, `:fullscreen`, `:modal`…) or a prefixed name:
    // no match, but no error either.
    return { spec: B, test: __SEL_NEVER };
  }
  function __selParseRelative(src) {
    // Relative selector: same parse, with a leading combinator anchored on
    // the left.
    const t = __s_trim(String(src));
    const lead = /^[>+~]/.test(t) ? t[0] : null;
    const body = lead ? __s_slice(t, 1) : t;
    const parsed = __selParse(body);
    if (parsed.length !== 1) throw new SyntaxError('selector');
    const cx = parsed[0];
    cx.lead = lead; cx.anchored = true;
    return cx;
  }

  // A selector Chrome cannot parse is an error, not an empty result:
  // `document.querySelector('<<<')` throws SyntaxError with an exact text.
  // Parsed per the selector grammar: a name after `#`/`.` is an identifier
  // (not a digit), pseudo-classes and pseudo-elements from Chrome's known set,
  // `:nth-*` is an+b, `:has()` non-empty; two combinators in a row and an
  // unknown namespace prefix are errors; an unclosed `[` at the end is closed
  // implicitly.
  // An escape is up to six hex digits and one optional white space (`#\31 23`
  // is id "123"), else any one character.
  const __SEL_IDENT = /^(?:-?(?:[_a-zA-Z\u00A0-\uFFFF]|\\[0-9a-fA-F]{1,6}[ \t\n\r\f]?|\\[^\n]|\\$)(?:[-_a-zA-Z0-9\u00A0-\uFFFF]|\\[0-9a-fA-F]{1,6}[ \t\n\r\f]?|\\[^\n]|\\$)*|--(?:[-_a-zA-Z0-9\u00A0-\uFFFF]|\\[0-9a-fA-F]{1,6}[ \t\n\r\f]?|\\[^\n]|\\$)*)/;
  const __SEL_PC_PLAIN = new Set(['-webkit-any-link', '-webkit-autofill', '-webkit-drag', '-webkit-full-page-media', '-webkit-full-screen', '-webkit-full-screen-ancestor', '-webkit-scrollbar', 'active', 'active-view-transition', 'any-link', 'autofill', 'checked', 'corner-present', 'current', 'decrement', 'default', 'defined', 'disabled', 'double-button', 'empty', 'enabled', 'end', 'first-child', 'first-of-type', 'focus', 'focus-visible', 'focus-within', 'fullscreen', 'future', 'horizontal', 'host', 'hover', 'in-range', 'increment', 'indeterminate', 'interest-source', 'interest-target', 'invalid', 'last-child', 'last-of-type', 'link', 'modal', 'no-button', 'only-child', 'only-of-type', 'open', 'optional', 'out-of-range', 'past', 'picture-in-picture', 'placeholder-shown', 'popover-open', 'read-only', 'read-write', 'required', 'root', 'scope', 'single-button', 'start', 'target', 'target-current', 'user-invalid', 'user-valid', 'valid', 'vertical', 'visited', 'window-inactive', 'xr-overlay']);
  const __SEL_PC_FUNC = new Set(['active-view-transition-type', 'dir', 'has', 'host', 'host-context', 'is', 'lang', 'not', 'nth-child', 'nth-last-child', 'nth-last-of-type', 'nth-of-type', 'state', 'where', '-webkit-any']);
  const __SEL_PE_PLAIN = new Set(['after', 'backdrop', 'before', 'checkmark', 'column', 'cue', 'details-content', 'file-selector-button', 'first-letter', 'first-line', 'grammar-error', 'marker', 'picker-icon', 'placeholder', 'scroll-marker', 'scroll-marker-group', 'search-text', 'selection', 'spelling-error', 'target-text', 'view-transition', '-webkit-calendar-picker-indicator', '-webkit-color-swatch', '-webkit-color-swatch-wrapper', '-webkit-date-and-time-value', '-webkit-datetime-edit', '-webkit-datetime-edit-ampm-field', '-webkit-datetime-edit-day-field', '-webkit-datetime-edit-fields-wrapper', '-webkit-datetime-edit-hour-field', '-webkit-datetime-edit-millisecond-field', '-webkit-datetime-edit-minute-field', '-webkit-datetime-edit-month-field', '-webkit-datetime-edit-second-field', '-webkit-datetime-edit-text', '-webkit-datetime-edit-week-field', '-webkit-datetime-edit-year-field', '-webkit-details-marker', '-webkit-file-upload-button', '-webkit-inner-spin-button', '-webkit-input-placeholder', '-webkit-media-controls', '-webkit-media-controls-current-time-display', '-webkit-media-controls-enclosure', '-webkit-media-controls-fullscreen-button', '-webkit-media-controls-mute-button', '-webkit-media-controls-overlay-enclosure', '-webkit-media-controls-overlay-play-button', '-webkit-media-controls-panel', '-webkit-media-controls-play-button', '-webkit-media-controls-time-remaining-display', '-webkit-media-controls-timeline', '-webkit-media-controls-toggle-closed-captions-button', '-webkit-media-controls-volume-slider', '-webkit-media-slider-container', '-webkit-media-slider-thumb', '-webkit-media-text-track-container', '-webkit-media-text-track-display', '-webkit-media-text-track-region', '-webkit-media-text-track-region-container', '-webkit-meter-bar', '-webkit-meter-even-less-good-value', '-webkit-meter-inner-element', '-webkit-meter-optimum-value', '-webkit-meter-suboptimum-value', '-webkit-progress-bar', '-webkit-progress-inner-element', '-webkit-progress-value', '-webkit-resizer', '-webkit-scrollbar', '-webkit-scrollbar-button', '-webkit-scrollbar-corner', '-webkit-scrollbar-thumb', '-webkit-scrollbar-track', '-webkit-scrollbar-track-piece', '-webkit-search-cancel-button', '-webkit-search-decoration', '-webkit-slider-container', '-webkit-slider-runnable-track', '-webkit-slider-thumb', '-webkit-textfield-decoration-container']);
  const __SEL_PE_FUNC = new Set(['cue', 'highlight', 'part', 'picker', 'scroll-button', 'slotted', 'view-transition-group', 'view-transition-image-pair', 'view-transition-new', 'view-transition-old']);
  const __SEL_LEGACY_PE = new Set(['before', 'after', 'first-line', 'first-letter']);
  // Arguments in parentheses up to the matching close (strings and nesting
  // respected); null if unclosed.
  const __selArg = (t, i) => {
    let depth = 0, q = null;
    for (let k = i; k < t.length; k++) {
      const ch = t[k];
      if (q) { if (ch === '\\') k++; else if (ch === q) q = null; continue; }
      if (ch === '"' || ch === "'") { q = ch; continue; }
      if (ch === '(') depth++;
      else if (ch === ')') { if (--depth === 0) return { arg: __s_slice(t, i + 1, k), end: k + 1 }; }
    }
    // An unclosed paren at the end of the string is closed implicitly.
    return { arg: __s_slice(t, i + 1), end: t.length };
  };
  const __selAnb = (a, allowOf) => {
    const m = /^\s*(even|odd|[+-]?\d*n(?:\s*[+-]\s*\d+)?|[+-]?\d+)(?:\s+(of)\s+([\s\S]+))?\s*$/i.exec(a);
    if (!m) return false;
    if (m[2]) return allowOf && __selValid(m[3], false);
    return true;
  };
  const __selStringOrIdent = (x) => /^\s*(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|(?:-?(?:[_a-zA-Z\u00A0-\uFFFF]|\\.)(?:[-_a-zA-Z0-9\u00A0-\uFFFF]|\\.)*|--[-_a-zA-Z0-9\u00A0-\uFFFF\\]*))\s*$/.test(x);
  // One complex selector (no commas); `relative` allows a leading combinator.
  const __selValidOne = (t, relative, ctx) => {
    ctx = ctx || {};
    let i = 0; const n = t.length;
    const ws = () => { while (i < n && /\s/.test(t[i])) i++; };
    const ident = () => { const m = __SEL_IDENT.exec(__s_slice(t, i)); if (!m) return null; i += m[0].length; return m[0]; };
    ws();
    if (i >= n) return false;
    let expectCompound = true;
    if (/^[>+~]/.test(__s_slice(t, i))) { if (!relative) return false; i += 1; ws(); }
    while (i < n) {
      // Compound selector.
      let any = false;
      // Type with optional namespace: `*`, `ident`, `*|x`, `|x`; a foreign prefix fails.
      const save = i;
      let nsPrefix = null;
      if (t[i] === '&') { i++; any = true; }
      else if (t[i] === '*' || t[i] === '|' || __SEL_IDENT.test(__s_slice(t, i))) {
        let first = t[i] === '*' ? (i++, '*') : (t[i] === '|' ? '' : ident());
        if (first === null) return false;
        if (t[i] === '|' && t[i + 1] !== '=') { nsPrefix = first; i++; const el = t[i] === '*' ? (i++, '*') : ident(); if (el === null) return false; if (nsPrefix !== '*' && nsPrefix !== '') return false; }
        any = true;
      }
      void save;
      let afterPE = false;
      for (;;) {
        const ch = t[i];
        if (afterPE && (ch === '#' || ch === '.' || ch === '[' || ch === ':' || ch === '&')) return false;
        if (ch === '&') { i++; any = true; continue; }
        if (ch === '#') { i++; if (ident() === null) return false; any = true; continue; }
        if (ch === '.') { i++; if (ident() === null) return false; any = true; continue; }
        if (ch === '[') {
          i++; ws();
          if (t[i] === '*' && t[i + 1] === '|') i += 2; else if (t[i] === '|') i++;
          if (ident() === null) return false;
          if (t[i] === '|' && t[i + 1] !== '=') return false;   // foreign namespace prefix
          ws();
          if (i >= n) return true;            // `a[b` is closed implicitly
          if (t[i] !== ']') {
            if (!/^[~|^$*]?=/.test(__s_slice(t, i))) return false;
            i += t[i] === '=' ? 1 : 2; ws();
            if (i >= n) return false;
            const vm = /^(?:"(?:[^"\\\n]|\\[\s\S])*"|'(?:[^'\\\n]|\\[\s\S])*'|"(?:[^"\\\n]|\\[\s\S])*$|'(?:[^'\\\n]|\\[\s\S])*$)/.exec(__s_slice(t, i));
            if (vm) i += vm[0].length; else if (ident() === null) return false;
            ws();
            if (i >= n) return true;
            if (/^[iI](?=\s*(\]|$))/.test(__s_slice(t, i))) { i++; ws(); }
            if (i >= n) return true;
          }
          if (t[i] !== ']') return false;
          i++; any = true; continue;
        }
        if (ch === ':') {
          i++;
          const pe = t[i] === ':'; if (pe) i++;
          const name = ident(); if (name === null) return false;
          const low = __s_toLowerCase(name);
          if (t[i] === '(') {
            const a = __selArg(t, i); if (!a) return false;
            i = a.end;
            const arg = a.arg;
            const inner = { logical: true, noHas: ctx.noHas || low === 'has' };
            if (pe) {
              if (ctx.logical) return false;
              if (!__SEL_PE_FUNC.has(low) && !__s_startsWith(low, '-webkit-')) return false;
              if (low === 'part') { if (!__s_trim(arg) || !__s_split(__s_trim(arg), /\s+/).every((x) => __SEL_IDENT.test(x) && __SEL_IDENT.exec(x)[0] === x)) return false; }
              else if (low === 'slotted') { if (!__selCompoundOnly(arg)) return false; }
              else if (low === 'cue') { if (!__selValid(arg, false, inner)) return false; }
              else if (!__s_trim(arg)) return false;
              afterPE = true;
            } else {
              if (!__SEL_PC_FUNC.has(low)) return false;
              // :is/:where take a forgiving list: invalid parts dropped, empty allowed.
              if (low === 'is' || low === 'where') { for (const p of __selSplit(arg)) { if (!__s_trim(p)) continue; try { if (!__selValidOne(p, false, inner)) { if (/::|\bhas\(/.test(p)) {} } } catch (e) {} } }
              else if (low === 'not' || low === '-webkit-any') { if (!__selValid(arg, false, inner)) return false; }
              else if (low === 'has') { if (ctx.noHas || !__s_trim(arg) || !__selValid(arg, true, inner)) return false; }
              else if (low === 'nth-child' || low === 'nth-last-child') { if (!__selAnb(arg, true)) return false; }
              else if (low === 'nth-of-type' || low === 'nth-last-of-type') { if (!__selAnb(arg, false)) return false; }
              else if (low === 'host' || low === 'host-context') { if (!__selCompoundOnly(arg)) return false; }
              else if (low === 'lang') { if (!__selStringOrIdent(arg) || /["']/.test(arg)) return false; }
              else if (low === 'active-view-transition-type') { if (!__s_trim(arg) || !__s_split(arg, ',').every((x) => __selStringOrIdent(x) && !/["']/.test(x))) return false; }
              else if (low === 'dir' || low === 'state') { if (!__selStringOrIdent(arg) || /["']/.test(arg)) return false; }
              else if (!__s_trim(arg)) return false;
            }
          } else if (pe) {
            if (ctx.logical) return false;
            if (!__SEL_PE_PLAIN.has(low) && !__s_startsWith(low, '-webkit-')) return false;
            afterPE = true;
          } else if (__SEL_LEGACY_PE.has(low)) { if (ctx.logical) return false; afterPE = true; }
          else if (!__SEL_PC_PLAIN.has(low)) return false;
          any = true; continue;
        }
        break;
      }
      if (!any) return false;
      expectCompound = false;
      // Combinator.
      const before = i; ws();
      if (i >= n) return true;
      if (afterPE) return false;               // nothing may follow a pseudo-element
      if (t[i] === '>' || t[i] === '+' || t[i] === '~') { i++; ws(); expectCompound = true; }
      else if (i === before) return false;     // a character no selector allows
      else expectCompound = true;              // descendant (whitespace)
      if (i >= n) return false;                // trailing combinator
      if (/^[>+~]/.test(__s_slice(t, i))) return false; // two in a row
    }
    return !expectCompound;
  };
  const __selValid = (sel, relative, ctx) => {
    const s = String(sel);
    if (!__s_trim(s)) return false;
    for (const part of __selSplit(s)) { if (!__selValidOne(part, !!relative, ctx)) return false; }
    return true;
  };
  // Compound selector only (no combinators): :host(), ::slotted().
  const __selCompoundOnly = (sel) => {
    const t = __s_trim(String(sel));
    if (!t || /[>+~]|\s/.test(__s_replace(t, /\[[^\]]*\]|\([^)]*\)/g, ''))) return false;
    return __selValid(t, false, { logical: true });
  };
  const __selectorOk = (sel) => { try { return __selValid(sel, false); } catch (e) { return false; } };
  const __checkSelector = (sel, method, iface) => {
    if (__selectorOk(sel)) return String(sel);
    const msg = "Failed to execute '" + method + "' on '" + iface + "': '" +
      String(sel) + "' is not a valid selector.";
    throw __pt_mkErr(globalThis.DOMException || Error, msg, 'SyntaxError');
  };
  // Same argument count Chrome requires, and the same error text.
  const __needArgs = (got, want, method, iface) => {
    if (got >= want) return;
    throw __pt_mkErr(TypeError, "Failed to execute '" + method + "' on '" + iface + "': " +
      want + " argument" + (want === 1 ? '' : 's') + " required, but only " + got + " present.");
  };

  // Not a node where a node is required: Chrome throws its own `TypeError`
  // before doing anything, with this exact text. The Cloudflare challenge
  // calls `replaceChild` with bad arguments and checks the answer.
  const __needNode = (v, n, method, iface) => {
    if (v !== null && typeof v === 'object' && typeof v.__ptType === 'number') return;
    throw __pt_mkErr(TypeError, "Failed to execute '" + method + "' on '" + (iface || 'Node') + "': " +
      "parameter " + n + " is not of type 'Node'.");
  };

  // The reference node must be a child; otherwise Chrome throws `NotFoundError`
  // with its own words.
  const __needChild = (parent, ref, method, what) => {
    if (__s_indexOf(parent.__ptKids, ref) >= 0) return;
    throw __pt_mkErr(globalThis.DOMException || Error, 
      "Failed to execute '" + method + "' on 'Node': " + what, 'NotFoundError');
  };

  function matchesSelector(el, selector, scope) {
    if (!el || el.__ptType !== ELEMENT_NODE) return false;
    const list = __selCompiled(selector);
    return !!list && __selAny(list, el, { scope: scope || null });
  }
  // Results in document order: `querySelectorAll('input, button')` returns
  // elements in tree order (Turnstile's api.js describes the form this way).
  function query(root, selector) {
    const results = [];
    const list = __selCompiled(selector);
    if (list) {
      const ctx = { scope: root };
      walk(root, (e) => { if (__selAny(list, e, ctx)) results.push(e); });
    }
    results.item = (i) => results[i] || null;
    return results;
  }
  function queryFirst(root, selector) {
    const list = __selCompiled(selector);
    if (!list) return null;
    const ctx = { scope: root };
    return firstMatch(root, (e) => __selAny(list, e, ctx));
  }

  // ---- HTML serialization (innerHTML getter) --------------------------------
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
  const esc = (s, attr) => __s_replace(s, attr ? /[&<>"]/g : /[&<>]/g, c => ESC[c]);
  // HTML serialization also writes U+00A0 as `&nbsp;` (XML has no such
  // entity), and the text of raw text elements as it is.
  const __escHtml = (s, attr) => __s_replace(s, attr ? /[&<>"\u00A0]/g : /[&<>\u00A0]/g, (c) => (c === '\u00A0' ? '&nbsp;' : ESC[c]));
  const __RAW_TEXT_PARENT = new Set(['style', 'script', 'xmp', 'iframe', 'noembed', 'noframes', 'plaintext', 'noscript']);
  // Internal fields only: a page may shadow `attributes`, `data` or `tagName`
  // on an element (skyscanner does on an iframe); Chrome's serializer is native.
  // Depth first with a stack of nodes and closing strings: Chrome serializes
  // trees thousands deep.
  function serializeNode(root, withShadow) {
    const out = [];
    const st = [root];
    const pushKids = (kids) => { for (let i = kids.length - 1; i >= 0; i--) st.push(kids[i]); };
    while (st.length) {
      const n = st.pop();
      if (typeof n === 'string') { out.push(n); continue; }
      if (n.__ptType === TEXT_NODE) {
        const p = n.__ptParent;
        out.push(p && p.__ptType === ELEMENT_NODE && __RAW_TEXT_PARENT.has(p.__ptLocal) && __isHtmlEl(p) ? n.__ptData : __escHtml(n.__ptData, false));
        continue;
      }
      if (n.__ptType === COMMENT_NODE) { out.push(`<!--${n.__ptData}-->`); continue; }
      if (n.__ptType === 7) { out.push(`<?${n.__ptTarget} ${n.__ptData}?>`); continue; }
      if (n.__ptType !== ELEMENT_NODE) { pushKids(n.__ptKids); continue; }
      const tag = n.__ptLocal;
      let attrs = '';
      for (const [name, value] of n.__ptAttrs) attrs += ` ${name}="${__escHtml(value, true)}"`;
      if (VOID.has(tag)) { out.push(`<${tag}${attrs}>`); continue; }
      out.push(`<${tag}${attrs}>`);
      st.push(`</${tag}>`);
      // `<template>` serializes its content; a serializable shadow root
      // (getHTML with serializableShadowRoots) as <template shadowrootmode>,
      // before the children.
      pushKids(tag === 'template' ? __templateContent(n).__ptKids : n.__ptKids);
      if (withShadow && n.__ptShadow && n.__ptShadow.__ptSerializable) {
        const sr = n.__ptShadow;
        st.push('</template>');
        pushKids(sr.__ptKids);
        st.push(`<template shadowrootmode="${sr.mode}"${sr.__ptDelegatesFocus ? ' shadowrootdelegatesfocus=""' : ''}${sr.__ptSerializable ? ' shadowrootserializable=""' : ''}${sr.__ptClonable ? ' shadowrootclonable=""' : ''}>`);
      }
    }
    return out.join('');
  }

  // Emptying a node (`textContent = ''`, `innerHTML = …`, `replaceChildren()`)
  // removes its children the way `removeChild` does: they no longer have a
  // parent, observers see them go, and frames among them close. jQuery's
  // `buildFragment` empties its scratch <div> this way and then moves the
  // children into a fragment — with a stale parent that move threw.
  function __ptDropKids(node) {
    const old = node.__ptKids;
    if (!old || !old.length) return;
    node.__ptKids = [];
    __connRemovals++;
    for (const c of old) { __moNodeWillDetach(node, c); c.__ptParent = null; __hasNoteTree(c); }
    __markDirty(node);
    __styleTouchKids(node, null, -1);
    __mutation(__childListRecord(node, [], old, null, null));
    let frameLeft = false;
    for (const c of old) __walkTree(c, (f) => {
      if (__isFrameEl(f)) frameLeft = true;
      if (f.__ptFrameId) __ptDisconnectFrame(f);
      if (f.__ptRealm) { try { if (typeof f.__ptRealm.__pt_detach === 'function') f.__ptRealm.__pt_detach(); } catch (e) {} try { __realmFrames.delete(f); } catch (e) {} }
      if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
    });
    if (frameLeft) __framesChanged();
  }

  // Element classes as a set, parsed once per attribute value. The layout
  // cascade checks `.x` for every rule on every element; running the `class`
  // string through a regex each time was two thirds of CPU on a heavy page.
  const __ptClassCache = new WeakMap();
  function __ptClassSet(e) {
    const v = __ptGetA(e, 'class');
    if (v == null) return null;
    let c = __ptClassCache.get(e);
    if (c === undefined || c.raw !== v) {
      c = { raw: v, set: new Set(__s_split(v, /[\t\n\f\r ]+/)) };
      __ptClassCache.set(e, c);
    }
    return c.set;
  }

  // Default action of an uncancelled click (activation behavior), carried by
  // the nearest ancestor of the target that has one: submit button submits,
  // reset resets, link navigates. Applies to trusted mouse clicks too (the
  // solver and `--click`), not just `button.click()`.
  function __ptActivate(target) {
    for (let el = target; el && el.__ptType === 1; el = el.__ptParent) {
      const tag = el.__ptLocal;
      if ((tag === 'button' || tag === 'input') && __ptHasA(el, 'disabled')) return;
      const btype = tag === 'button' ? __s_toLowerCase(String(__ptGetA(el, 'type') || 'submit'))
        : tag === 'input' ? __inputType(el) : null;
      if (btype === 'submit' || btype === 'image' || btype === 'reset') {
        if (tag === 'button' && btype !== 'submit' && btype !== 'reset') return;
        let f = el.__ptParent; while (f && f.__ptLocal !== 'form') f = f.__ptParent;
        const formId = __ptGetA(el, 'form');
        if (formId && globalThis.document) f = document.getElementById(formId) || f;
        if (!f) return;
        const reset = __formGet(f, 'reset'), request = __formGet(f, 'requestSubmit');
        if (btype === 'reset') { if (typeof reset === 'function') reset.call(f); }
        else if (typeof request === 'function') request.call(f, el);
        return;
      }
      if (tag === 'button') return;
      if ((tag === 'a' || tag === 'area') && __ptHasA(el, 'href')) {
        const t = __s_toLowerCase(String(__ptGetA(el, 'target') || ''));
        if (t && t !== '_self' && t !== '_top' && t !== '_parent') return;
        if (__ptHasA(el, 'download')) return;
        const raw = String(__ptGetA(el, 'href'));
        if (/^\s*javascript:/i.test(raw)) return;
        let url;
        try { url = new URL(raw, document.baseURI || location.href); } catch (e) { return; }
        const here = String(location.href);
        // Fragment only: scroll and hashchange, no navigation.
        if (__s_split(url.href, '#')[0] === __s_split(here, '#')[0] && url.hash) { location.hash = url.hash; return; }
        location.assign(url.href);
        return;
      }
    }
  }

  // ---- HTML parsing for markup set by scripts --------------------------------
  const __SVG_NS = 'http://www.w3.org/2000/svg', __MATH_NS = 'http://www.w3.org/1998/Math/MathML';
  const __foreignElem = (doc, ns, name) => {
    const O = globalThis.__pt_orig || {};
    const f = O.createElementNS || Document.prototype.createElementNS;
    return f.call(doc, ns, name);
  };
  // The HTML parser (html5ever, as Chrome parses) on markup for an element:
  // `context` is the element whose children the markup becomes (`innerHTML`
  // on it, `insertAdjacentHTML` around it); none means `<body>`. The nodes
  // come back unattached, in order.
  function parseFragment(html, context) {
    const doc = (context && (context.__ptType === DOCUMENT_NODE ? context : context.__ptDoc)) || globalThis.document;
    let local = 'body', ns = 'http://www.w3.org/1999/xhtml';
    if (context && context.__ptType === ELEMENT_NODE) {
      local = context.__ptLocal;
      ns = context.__ptNS || 'http://www.w3.org/1999/xhtml';
    }
    const mode = doc && doc.compatMode === 'BackCompat' ? 'quirks' : 'no';
    const specs = __ptJSON.parse(__pt_parseHtmlFragment(String(html), local, ns, mode));
    return __buildSpecs(doc, specs, null, false);
  }
  // A name `createElement` refuses (`<div<div>` makes `div<div`) the parser
  // still creates, as an unknown element.
  const __CREATE_ELEMENT_NAME = /^[A-Za-z_:À-\u{10FFFF}][A-Za-z0-9_:.\-·À-\u{10FFFF}]*$/u;
  function __parserElement(doc, spec) {
    if (spec.ns) return __foreignElem(doc, spec.ns, spec.tag);
    const O = globalThis.__pt_orig || {};
    if (__CREATE_ELEMENT_NAME.test(spec.tag)) return (O.createElement || Document.prototype.createElement).call(doc, spec.tag);
    const e = new Element(spec.tag);
    if (globalThis.__pt_elementProto) { try { Object.setPrototypeOf(e, __pt_elementProto(spec.tag)); } catch (x) {} }
    e.__ptDoc = doc;
    return e;
  }
  // Nodes from the parser's specs, built without the page's own methods
  // (Chrome's parser calls none) and without a stack frame per level. With
  // `into` the top-level nodes are appended there, else returned. Scripts the
  // parser builds are "already started" unless `live`: the engine runs a
  // document's own, and markup set later (`innerHTML`) never runs.
  // Elements a shadow root can be attached to (Chrome's list).
  const __SHADOW_HOSTS = new Set(['article', 'aside', 'blockquote', 'body', 'div', 'footer', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'main', 'nav', 'p', 'section', 'span']);
  // `<template shadowrootmode>` in a document the parser builds becomes its
  // parent's shadow root, as Chrome's parser makes it; null when it stays a
  // template (another mode, a host that cannot have one or already has one).
  function __declarativeShadow(parent, spec) {
    if (!parent || parent.__ptType !== ELEMENT_NODE || parent.__ptShadow) return null;
    let mode = null, delegates = false, clonable = false, serializable = false;
    for (const a of spec.attrs) {
      const k = __s_toLowerCase(a[0]);
      if (k === 'shadowrootmode') mode = __s_toLowerCase(a[1]);
      else if (k === 'shadowrootdelegatesfocus') delegates = true;
      else if (k === 'shadowrootclonable') clonable = true;
      else if (k === 'shadowrootserializable') serializable = true;
    }
    if (mode !== 'open' && mode !== 'closed') return null;
    const host = parent.__ptLocal;
    if (parent.__ptNS || !(__SHADOW_HOSTS.has(host) || __s_indexOf(host, '-') > 0)) return null;
    try { return __ptAttachShadow.call(parent, { mode, delegatesFocus: delegates, clonable, serializable }); } catch (e) { return null; }
  }
  function __buildSpecs(doc, specs, into, live, dsd) {
    const out = [];
    const st = [specs, 0, into];
    while (st.length) {
      const top = st.length - 3;
      const list = st[top], i = st[top + 1], parent = st[top + 2];
      if (i >= list.length) { st.length = top; continue; }
      st[top + 1] = i + 1;
      const spec = list[i];
      let n = null;
      if (spec.k === 't') { n = new Text(spec.v); n.__ptDoc = doc; }
      else if (spec.k === 'c') { n = new Comment(spec.v); n.__ptDoc = doc; }
      else if (spec.k === 'p') n = __makePI(doc, spec.t, spec.v);
      else if (spec.k === 'd') n = __makeDoctype(doc, spec.name, spec.publicId, spec.systemId);
      else if (spec.k === 'e') {
        if (dsd && spec.tag === 'template' && !spec.ns) {
          const sr = __declarativeShadow(parent, spec);
          if (sr) { if (spec.children.length) st.push(spec.children, 0, sr); continue; }
        }
        const el = __parserElement(doc, spec);
        if (spec.tag === 'script' && !spec.ns) {
          if (!live) {
            Object.defineProperty(el, '__ptRan', { value: true, configurable: true, enumerable: false });
            el.__ptNoForceAsync = true;
          } else Object.defineProperty(el, '__ptParserIns', { value: true, configurable: true, enumerable: false });
        }
        for (const a of spec.attrs) {
          __ptSetA(el, a[0], a[1]);
          // Foreign content: `xlink:href`, `xml:lang`, `xmlns` in their namespaces.
          if (a[2]) { const c = __s_indexOf(a[0], ':'); __attrNsMap(el).set(a[0], [a[2], c < 0 ? null : __s_slice(a[0], 0, c), c < 0 ? a[0] : __s_slice(a[0], c + 1)]); }
        }
        n = el;
        // The parser puts template children into its content and leaves the
        // element empty (`t.childNodes.length === 0` in Chrome too).
        if (spec.children.length) st.push(spec.children, 0, spec.tag === 'template' && !spec.ns ? __templateContent(el) : el);
      }
      if (!n) continue;
      if (parent) __ptAdd.call(parent, n); else out.push(n);
    }
    return out;
  }
  // A whole document parsed into `doc` as the HTML parser builds it: doctype,
  // comments and processing instructions around the root, the root, and the
  // mode (quirks or not) the doctype gave.
  function __parseDocumentInto(doc, markup, live) {
    const r = __ptJSON.parse(__pt_parseHtmlDocument(String(markup)));
    __formSeq++;
    doc.__ptKids = [];
    doc.__ptDocEl = null;
    doc.__ptDoctype = null;
    for (const n of __buildSpecs(doc, r.children, null, !!live, !!live)) {
      if (n.__ptType === 10) {
        n.__ptParent = doc;
        doc.__ptKids.push(n);
        doc.__ptDoctype = n;
        continue;
      }
      __ptAdd.call(doc, n);
      if (n.__ptType === ELEMENT_NODE) doc.__ptDocEl = n;
    }
    doc.__ptMode = r.mode;
    return doc.__ptDocEl;
  }
  // A DocumentType: Node fields like any node, the name and ids in the
  // interface's stored members; no own properties, as in Chrome.
  function __makeDoctype(doc, name, publicId, systemId) {
    const P = (globalThis.DocumentType && DocumentType.prototype) || Node.prototype;
    const n = Object.create(P);
    n.__ptType = 10;
    n.__ptKids = [];
    n.__ptParent = null;
    n.__ptDoc = doc;
    n.__ptLis = Object.create(null);
    if (typeof __pt_write === 'function') {
      __pt_write(n, 'name', String(name || ''));
      __pt_write(n, 'publicId', String(publicId || ''));
      __pt_write(n, 'systemId', String(systemId || ''));
    }
    return n;
  }
  // ---- build DOM from the Rust-parsed tree ----------------------------------
  // `<template>` keeps its parsed content in a separate DocumentFragment,
  // `t.content`. The Cloudflare challenge builds nodes through templates.
  function __templateContent(el) {
    let f = el.__ptContent;
    if (!f) {
      f = (el.ownerDocument || globalThis.document).createDocumentFragment();
      Object.defineProperty(el, '__ptContent', { value: f, writable: true, enumerable: false });
    }
    return f;
  }
  globalThis.__pt_templateContent = __templateContent;

  // The page's own document: declarative shadow roots attach.
  const buildNode = (doc, spec) => __buildSpecs(doc, [spec], null, false, true)[0];

  // ---- install globals ------------------------------------------------------
  const document = new Document();
  globalThis.document = document;
  // Standard Node type constants, on the constructor and the prototype — drivers
  // check `node.__ptType !== Node.ELEMENT_NODE` before acting on a node.
  const NODE_TYPES = {
    ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, CDATA_SECTION_NODE: 4,
    // Types 5 and 6 are no longer created, but Node keeps the constants and
    // they are counted: Chrome's `Node.prototype` has exactly 48 names.
    ENTITY_REFERENCE_NODE: 5, ENTITY_NODE: 6,
    PROCESSING_INSTRUCTION_NODE: 7, COMMENT_NODE: 8, DOCUMENT_NODE: 9,
    DOCUMENT_TYPE_NODE: 10, DOCUMENT_FRAGMENT_NODE: 11, NOTATION_NODE: 12,
    DOCUMENT_POSITION_DISCONNECTED: 1, DOCUMENT_POSITION_PRECEDING: 2,
    DOCUMENT_POSITION_FOLLOWING: 4, DOCUMENT_POSITION_CONTAINS: 8,
    DOCUMENT_POSITION_CONTAINED_BY: 16, DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC: 32,
  };
  Object.assign(Node, NODE_TYPES);
  Object.assign(Node.prototype, NODE_TYPES);

  // Node members that belong on Node, not Element; the fingerprinter counts
  // this level.
  const __nodeName = function () {
    switch (this.__ptType) {
      case 1: return this.tagName;
      case 3: return '#text';
      case 4: return '#cdata-section';
      case 7: return this.__ptTarget;
      case 8: return '#comment';
      case 9: return '#document';
      case 10: return this.name || 'html';
      case 11: return '#document-fragment';
      default: return '#unknown';
    }
  };
  const __nodeMembers = {
    baseURI: { get: function () {
      const d = this.__ptType === 9 ? this : this.ownerDocument;
      if (d && typeof d.__ptBaseURI === 'function') return d.__ptBaseURI();
      return (d && d.URL) || (globalThis.location && location.href) || 'about:blank';
    } },
    nodeName: { get: __nodeName },
    parentElement: { get: function () { const p = this.__ptParent; return p && p.__ptType === 1 ? p : null; } },
    nodeValue: {
      get: function () { const t = this.__ptType; return (t === 3 || t === 4 || t === 7 || t === 8) ? this.__ptData : null; },
      // [LegacyNullToEmptyString]
      set: function (v) { const t = this.__ptType; if (t === 3 || t === 4 || t === 7 || t === 8) __cdSetAll(this, v === null ? '' : String(v)); },
    },
    isSameNode: { value: function isSameNode(other) { return this === other; } },
    isEqualNode: {
      value: function isEqualNode(other) {
        if (!other || this.__ptType !== other.__ptType) return false;
        if (this.nodeName !== other.nodeName) return false;
        if (this.__ptType === 3 || this.__ptType === 8) return this.__ptData === other.__ptData;
        if (this.__ptType === 7) return this.__ptTarget === other.__ptTarget && this.__ptData === other.__ptData;
        if (this.__ptType === 1) {
          const a = this.attributes || [], b = other.attributes || [];
          if (a.length !== b.length) return false;
          for (let i = 0; i < a.length; i++) {
            if (__ptGetA(other, a[i].name) !== a[i].value) return false;
          }
        }
        const x = this.childNodes, y = other.childNodes;
        if (x.length !== y.length) return false;
        for (let i = 0; i < x.length; i++) if (!x[i].isEqualNode(y[i])) return false;
        return true;
      },
    },
    compareDocumentPosition: {
      value: function compareDocumentPosition(other) {
        if (this === other) return 0;
        if (!other) return 1;
        // Ancestor chains from the root down; below the last shared ancestor
        // the two branches are siblings, ordered by their parent's child list.
        // (Walking the whole tree per call made jQuery's sort quadratic.)
        const up = (n) => { const c = []; for (; n; n = n.__ptParent) c.push(n); return c; };
        const ca = up(this), cb = up(other);
        let i = ca.length - 1, j = cb.length - 1;
        if (ca[i] !== cb[j]) return 35;                          // DISCONNECTED | IMPLEMENTATION_SPECIFIC | PRECEDING
        while (i > 0 && j > 0 && ca[i - 1] === cb[j - 1]) { i--; j--; }
        if (i === 0) return 20;                                  // other inside this: CONTAINED_BY | FOLLOWING
        if (j === 0) return 10;                                  // this inside other: CONTAINS | PRECEDING
        const x = ca[i - 1], y = cb[j - 1], kids = ca[i].__ptKids || [];
        for (let k = 0; k < kids.length; k++) {
          if (kids[k] === x) return 4;                           // other follows
          if (kids[k] === y) return 2;
        }
        return 4;
      },
    },
    normalize: {
      value: function normalize() {
        const kids = this.childNodes;
        for (let i = kids.length - 1; i > 0; i--) {
          const cur = kids[i], prev = kids[i - 1];
          if (cur.__ptType === 3 && prev.__ptType === 3) { prev.data += cur.data; this.removeChild(cur); }
        }
        for (const c of this.childNodes) if (c.normalize) __s_normalize(c);
      },
    },
    isDefaultNamespace: { value: function isDefaultNamespace(ns) { return ns === 'http://www.w3.org/1999/xhtml'; } },
    lookupNamespaceURI: { value: function lookupNamespaceURI(prefix) { return prefix ? null : 'http://www.w3.org/1999/xhtml'; } },
    lookupPrefix: { value: function lookupPrefix() { return null; } },
  };
  for (const [name, spec] of Object.entries(__nodeMembers)) {
    if (Object.getOwnPropertyDescriptor(Node.prototype, name)) continue;
    try {
      Object.defineProperty(Node.prototype, name,
        Object.assign({ enumerable: true, configurable: true }, spec,
                      spec.value ? { writable: true } : {}));
    } catch (e) {}
  }
  // A WebIDL interface's members are *enumerable* on its prototype: in a browser
  // `Object.keys(Document.prototype)` lists `body`, `title`, `querySelector` and
  // the rest. Ours were declared with `class`, whose members are non-enumerable by
  // language rule, so the same call returned two names. That is not an internal
  // detail — the Turnstile VM fingerprints by walking `Object.keys` up the whole
  // prototype chain, and against a browser's 1600-odd properties our graph showed
  // 318. Mark them the way the platform does; `constructor` stays hidden, as it is
  // in a browser.
  const __webidl = (ctor) => {
    if (!ctor || !ctor.prototype) return;
    for (const k of Object.getOwnPropertyNames(ctor.prototype)) {
      if (k === 'constructor') continue;
      const d = Object.getOwnPropertyDescriptor(ctor.prototype, k);
      if (!d || d.enumerable || !d.configurable) continue;
      d.enumerable = true;
      try { Object.defineProperty(ctor.prototype, k, d); } catch (e) {}
    }
  };

  globalThis.Node = Node;
  globalThis.Element = Element;
  // Element interfaces form a ladder: Element -> HTMLElement ->
  // HTMLCanvasElement and so on, each step with its own members, so
  // `div instanceof HTMLCanvasElement` is false and `constructor.name` is
  // right. Members still live on Element; their distribution comes later.
  const __ifaceProto = new Map();
  let __pendingTag = 'div';
  // The element a custom element definition is upgrading, with its class:
  // `super()` from that class hands back the existing element, as Chrome's
  // HTMLElement constructor does, so the constructor body runs on it.
  let __upgrading = null;
  // Strict mode matters: a sloppy function has own `arguments` and `caller`,
  // a browser interface does not, and the graph walk would see two extra
  // properties on each of ~100 `HTML*Element` names.
  const __mkIface = (function () {
    'use strict';
    return (name, parentProto) => {
    // Named at birth: editing `name` turns a function into dictionary mode.
    const C = ({ [name]: function () {
      // `new HTMLElement()` throws in Chrome, but `super()` from a custom
      // element class must work.
      if (new.target && new.target !== C) {
        const up = __upgrading;
        if (up && up.ctor === new.target) { __upgrading = null; return up.el; }
        return Reflect.construct(Element, [__pendingTag], new.target);
      }
      throw __pt_mkErr(TypeError, "Illegal constructor");
    } })[name];
    C.prototype = Object.create(parentProto);
    Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true });
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
    globalThis[name] = globalThis.__pt_native ? __pt_native(C) : C;
    return C.prototype;
    };
  })();
  const __htmlProto = __mkIface('HTMLElement', Element.prototype);
  // Tag -> interface, from Chrome 148.
  const TAG_IFACE = {
    a: 'HTMLAnchorElement', area: 'HTMLAreaElement', audio: 'HTMLAudioElement',
    br: 'HTMLBRElement', base: 'HTMLBaseElement', body: 'HTMLBodyElement',
    button: 'HTMLButtonElement', canvas: 'HTMLCanvasElement', data: 'HTMLDataElement',
    datalist: 'HTMLDataListElement', del: 'HTMLModElement', details: 'HTMLDetailsElement',
    dialog: 'HTMLDialogElement', div: 'HTMLDivElement', dl: 'HTMLDListElement',
    embed: 'HTMLEmbedElement', fieldset: 'HTMLFieldSetElement', form: 'HTMLFormElement',
    h1: 'HTMLHeadingElement', h2: 'HTMLHeadingElement', h3: 'HTMLHeadingElement',
    h4: 'HTMLHeadingElement', h5: 'HTMLHeadingElement', h6: 'HTMLHeadingElement',
    head: 'HTMLHeadElement', hr: 'HTMLHRElement', html: 'HTMLHtmlElement',
    iframe: 'HTMLIFrameElement', img: 'HTMLImageElement', input: 'HTMLInputElement',
    ins: 'HTMLModElement', label: 'HTMLLabelElement', legend: 'HTMLLegendElement',
    li: 'HTMLLIElement', link: 'HTMLLinkElement', map: 'HTMLMapElement',
    menu: 'HTMLMenuElement', meta: 'HTMLMetaElement', meter: 'HTMLMeterElement',
    object: 'HTMLObjectElement', ol: 'HTMLOListElement', optgroup: 'HTMLOptGroupElement',
    option: 'HTMLOptionElement', output: 'HTMLOutputElement', p: 'HTMLParagraphElement',
    picture: 'HTMLPictureElement', pre: 'HTMLPreElement', progress: 'HTMLProgressElement',
    q: 'HTMLQuoteElement', blockquote: 'HTMLQuoteElement', script: 'HTMLScriptElement',
    select: 'HTMLSelectElement', slot: 'HTMLSlotElement', source: 'HTMLSourceElement',
    span: 'HTMLSpanElement', style: 'HTMLStyleElement', table: 'HTMLTableElement',
    caption: 'HTMLTableCaptionElement', td: 'HTMLTableCellElement', th: 'HTMLTableCellElement',
    col: 'HTMLTableColElement', colgroup: 'HTMLTableColElement', tr: 'HTMLTableRowElement',
    tbody: 'HTMLTableSectionElement', tfoot: 'HTMLTableSectionElement',
    thead: 'HTMLTableSectionElement', template: 'HTMLTemplateElement',
    textarea: 'HTMLTextAreaElement', time: 'HTMLTimeElement', title: 'HTMLTitleElement',
    track: 'HTMLTrackElement', ul: 'HTMLUListElement', video: 'HTMLVideoElement',
    dir: 'HTMLDirectoryElement', font: 'HTMLFontElement', frame: 'HTMLFrameElement',
    frameset: 'HTMLFrameSetElement', marquee: 'HTMLMarqueeElement', param: 'HTMLParamElement',
    listing: 'HTMLPreElement', xmp: 'HTMLPreElement', fencedframe: 'HTMLFencedFrameElement',
    selectedcontent: 'HTMLSelectedContentElement',
  };
  // Tags known to HTML without their own interface: HTMLElement.
  const PLAIN_TAGS = new Set(['abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo',
    'cite', 'code', 'dd', 'dfn', 'dt', 'em', 'figcaption', 'figure', 'footer', 'header',
    'hgroup', 'i', 'kbd', 'main', 'mark', 'nav', 'noscript', 'rp', 'rt', 'ruby', 's',
    'samp', 'search', 'section', 'small', 'strong', 'sub', 'summary', 'sup', 'u', 'var',
    'wbr', 'center', 'big', 'strike', 'tt', 'nobr', 'acronym', 'basefont', 'layer',
    'noembed', 'noframes', 'nolayer', 'plaintext', 'rb', 'rtc']);
  for (const name of new Set(Object.values(TAG_IFACE))) __ifaceProto.set(name, __mkIface(name, __htmlProto));
  // Media elements inherit HTMLMediaElement.
  const __mediaProto = __mkIface('HTMLMediaElement', __htmlProto);
  for (const n of ['HTMLVideoElement', 'HTMLAudioElement']) {
    try { Object.setPrototypeOf(globalThis[n].prototype, __mediaProto); } catch (e) {}
  }
  __ifaceProto.set('HTMLUnknownElement', __mkIface('HTMLUnknownElement', __htmlProto));
  // Form and table collections: `table.rows`, `tr.cells`, `select.options`,
  // `form.elements`… (the Cloudflare challenge parses its test markup this way).
  {
    const proto = (n) => __ifaceProto.get(n);
    const defGet = (P, k, get) => { if (!P) return; try { Object.defineProperty(P, k, { get, enumerable: true, configurable: true }); } catch (e) {} };
    const defFn = (P, k, fn) => { if (!P) return; try { Object.defineProperty(P, k, { value: fn, writable: true, enumerable: true, configurable: true }); } catch (e) {} };
    const kids = (el) => (el && el.__ptKids ? el.__ptKids : []).filter((k) => k.__ptType === ELEMENT_NODE);
    const local = (el) => __s_toLowerCase(String(el.__ptLocal || ''));
    const isTag = (el, ...names) => el && el.__ptType === ELEMENT_NODE && __s_includes(names, local(el));
    const branded = (arr, name, named) => {
      const c = __collection(arr, named);
      try { const I = globalThis[name]; if (I && I.prototype) Object.setPrototypeOf(c, I.prototype); } catch (e) {}
      return c;
    };
    // Table.
    const tableRows = (t) => {
      const out = [];
      const heads = kids(t).filter((k) => isTag(k, 'thead'));
      const feet = kids(t).filter((k) => isTag(k, 'tfoot'));
      for (const h of heads) for (const r of kids(h)) if (isTag(r, 'tr')) out.push(r);
      for (const k of kids(t)) {
        if (isTag(k, 'tr')) out.push(k);
        else if (isTag(k, 'tbody')) for (const r of kids(k)) if (isTag(r, 'tr')) out.push(r);
      }
      for (const f of feet) for (const r of kids(f)) if (isTag(r, 'tr')) out.push(r);
      return out;
    };
    const T = proto('HTMLTableElement');
    defGet(T, 'rows', function () { return __collection(tableRows(this)); });
    defGet(T, 'tBodies', function () { return __collection(kids(this).filter((k) => isTag(k, 'tbody'))); });
    const defPair = (P, k, get, set) => { if (!P) return; try { Object.defineProperty(P, k, { get, set, enumerable: true, configurable: true }); } catch (e) {} };
    const tableSet = (t, tag, v, where) => {
      if (v !== null && !(v && isTag(v, tag))) throw __pt_mkErr(TypeError, "Failed to set the '" + (tag === 'thead' ? 'tHead' : tag === 'tfoot' ? 'tFoot' : tag) + "' property on 'HTMLTableElement': The provided value is not of type '" + (tag === 'caption' ? 'HTMLTableCaptionElement' : 'HTMLTableSectionElement') + "'.");
      const old = kids(t).find((k) => isTag(k, tag)); if (old) t.removeChild(old);
      if (!v) return;
      const ref = where(t); ref ? t.insertBefore(v, ref) : t.appendChild(v);
    };
    defPair(T, 'tHead', function () { return kids(this).find((k) => isTag(k, 'thead')) || null; },
      function (v) { tableSet(this, 'thead', v, (t) => kids(t).find((k) => !isTag(k, 'caption') && !isTag(k, 'colgroup')) || null); });
    defPair(T, 'tFoot', function () { return kids(this).find((k) => isTag(k, 'tfoot')) || null; },
      function (v) { tableSet(this, 'tfoot', v, () => null); });
    defPair(T, 'caption', function () { return kids(this).find((k) => isTag(k, 'caption')) || null; },
      function (v) { tableSet(this, 'caption', v, (t) => kids(t)[0] || null); });
    const S = proto('HTMLTableSectionElement');
    defGet(S, 'rows', function () { return __collection(kids(this).filter((k) => isTag(k, 'tr'))); });
    const R = proto('HTMLTableRowElement');
    defGet(R, 'cells', function () { return __collection(kids(this).filter((k) => isTag(k, 'td', 'th'))); });
    defGet(R, 'rowIndex', function () {
      let t = this.__ptParent;
      if (t && isTag(t, 'thead', 'tbody', 'tfoot')) t = t.__ptParent;
      if (!t || !isTag(t, 'table')) return -1;
      return __s_indexOf(tableRows(t), this);
    });
    defGet(R, 'sectionRowIndex', function () {
      const p = this.__ptParent;
      if (!p || !isTag(p, 'table', 'thead', 'tbody', 'tfoot')) return -1;
      return __s_indexOf(kids(p).filter((k) => isTag(k, 'tr')), this);
    });
    const C = proto('HTMLTableCellElement');
    defGet(C, 'cellIndex', function () {
      const p = this.__ptParent;
      if (!p || !isTag(p, 'tr')) return -1;
      return __s_indexOf(kids(p).filter((k) => isTag(k, 'td', 'th')), this);
    });
    // Select.
    const selOptions = (sel) => {
      const out = [];
      for (const k of kids(sel)) {
        if (isTag(k, 'option')) out.push(k);
        else if (isTag(k, 'optgroup')) for (const o of kids(k)) if (isTag(o, 'option')) out.push(o);
      }
      return out;
    };
    const isSelected = (o) => !!(o.__ptSelected != null ? o.__ptSelected : __ptHasA(o, 'selected'));
    const SEL = proto('HTMLSelectElement');
    // The select an options collection is of, for its setters.
    const selOfOpts = new WeakMap();
    globalThis.__pt_optsSelect = (c) => selOfOpts.get(c) || null;
    defGet(SEL, 'options', function () { const c = branded(selOptions(this), 'HTMLOptionsCollection', true); selOfOpts.set(c, this); return c; });
    // add(option or optgroup, before: an element in it, an option index, or null).
    const selAdd = (sel, el, before, on) => {
      const fail = (what, name) => __pt_mkErr(name ? (globalThis.DOMException || Error) : TypeError, "Failed to execute 'add' on '" + on + "': " + what, name);
      if (!isTag(el, 'option', 'optgroup')) throw fail('The provided value is not of type \'(HTMLOptGroupElement or HTMLOptionElement)\'.');
      let ref = null;
      if (before != null) {
        if (typeof before === 'object') {
          let p = before.__ptParent;
          while (p && p !== sel) p = p.__ptParent;
          if (!p) throw fail('The node before which the new node is to be inserted is not a child of this node.', 'NotFoundError');
          ref = before;
        } else ref = selOptions(sel)[Number(before) | 0] || null;
      }
      if (ref === el) return;
      __ptInsert.call(ref ? ref.__ptParent : sel, el, ref);
    };
    const selRemove = (sel, i) => {
      const o = selOptions(sel)[Number(i) | 0];
      if (o && o.__ptParent) o.__ptParent.removeChild(o);
    };
    defFn(SEL, 'add', function add(element) { selAdd(this, element, arguments[1], 'HTMLSelectElement'); });
    defFn(SEL, 'remove', function remove() {
      if (!arguments.length) { const p = this.__ptParent; if (p) p.removeChild(this); return; }
      selRemove(this, arguments[0]);
    });
    globalThis.__pt_selAdd = selAdd;
    globalThis.__pt_selRemove = selRemove;
    // selectedIndex and length setters, as Chrome's HTMLSelectElement/HTMLOptionsCollection.
    const selSetIndex = (sel, i) => {
      const opts = selOptions(sel); i = i | 0;
      opts.forEach((o, j) => { o.__ptSelected = (j === i); });
    };
    const selSetLength = (sel, n) => {
      const opts = selOptions(sel); n = Math.max(0, n >>> 0);
      if (n < opts.length) { for (const o of __s_slice(opts, n)) o.__ptParent && o.__ptParent.removeChild(o); }
      else for (let i = opts.length; i < n; i++) sel.appendChild(sel.ownerDocument.createElement('option'));
    };
    globalThis.__pt_selSetLength = selSetLength;
    globalThis.__pt_selSetIndex = selSetIndex;
    // A select's `value` is the selected option's; option `selected`/`value`/`text`.
    const optValue = (o) => { const v = __ptGetA(o, 'value'); return v != null ? String(v) : __s_trim(__s_replace(String(o.textContent || ''), /\s+/g, ' ')); };
    defPair(SEL, 'value', function () {
      if (__ptDropDown(this)) { const o = __ptSelChosen(this); return o ? optValue(o) : ''; }
      const chosen = selOptions(this).filter(isSelected);
      return chosen.length ? optValue(chosen[0]) : '';
    }, function (v) {
      const opts = selOptions(this); v = String(v); let hit = false;
      for (const o of opts) { if (!hit && optValue(o) === v) { o.__ptSelected = true; hit = true; } else o.__ptSelected = false; }
    });
    const O_ = proto('HTMLOptionElement');
    defPair(O_, 'selected', function () {
      let p = this.__ptParent;
      if (p && p.__ptTag === 'OPTGROUP') p = p.__ptParent;
      if (p && p.__ptTag === 'SELECT' && __ptDropDown(p)) return __ptSelChosen(p) === this;
      return isSelected(this);
    }, function (v) {
      this.__ptSelected = !!v;
      __markDirty(this);
      if (v) { let p = this.__ptParent; if (p && isTag(p, 'optgroup')) p = p.__ptParent; if (p && isTag(p, 'select') && !__ptHasA(p, 'multiple')) for (const o of selOptions(p)) if (o !== this) o.__ptSelected = false; }
    });
    defPair(O_, 'value', function () { return optValue(this); }, function (v) { __ptSetA(this, 'value', String(v)); });
    defPair(O_, 'text', function () { return __s_trim(__s_replace(String(this.textContent || ''), /\s+/g, ' ')); }, function (v) { this.textContent = String(v); });
    defGet(SEL, 'selectedOptions', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      let chosen = opts.filter(isSelected);
      if (!multiple) { if (chosen.length > 1) chosen = [chosen[chosen.length - 1]]; if (!chosen.length && opts.length && __ptGetA(this, 'size') == null) chosen = [opts[0]]; }
      return __collection(chosen);
    });
    defPair(SEL, 'selectedIndex', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      const chosen = opts.filter(isSelected);
      if (chosen.length) return __s_indexOf(opts, multiple ? chosen[0] : chosen[chosen.length - 1]);
      return !multiple && opts.length && __ptGetA(this, 'size') == null ? 0 : -1;
    }, function (v) { selSetIndex(this, v); });
    defPair(SEL, 'length', function () { return selOptions(this).length; }, function (v) { selSetLength(this, v); });
    defGet(SEL, 'type', function () { return __ptHasA(this, 'multiple') ? 'select-multiple' : 'select-one'; });
    defFn(SEL, 'item', function item(i) { return selOptions(this)[i | 0] || null; });
    defFn(SEL, 'namedItem', function namedItem(n) { return selOptions(this).find((o) => o.id === n || __ptGetA(o, 'name') === n) || null; });
    const DL = proto('HTMLDataListElement');
    defGet(DL, 'options', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'option')) out.push(n); }); return __collection(out, true); });
    // Forms and their elements.
    const LISTED = new Set(['button', 'fieldset', 'input', 'object', 'output', 'select', 'textarea']);
    // The form owner: with a `form` attribute and in a document, the form of
    // that id in the element's tree (or none); else the nearest form around
    // it in the same tree, not across a shadow root.
    const formOf = (el) => {
      const id = __ptGetA(el, 'form');
      if (id != null) {
        let root = el;
        while (root.__ptParent) root = root.__ptParent;
        let top = root;
        while (top && top.__ptType === 11 && top.__ptHost) { top = top.__ptHost; while (top.__ptParent) top = top.__ptParent; }
        if (top && top.__ptType === 9) {
          let found = null;
          __walkTree(root, (n) => { if (!found && n !== root && n.__ptType === ELEMENT_NODE && __ptGetA(n, 'id') === id) found = n; });
          return found && isTag(found, 'form') ? found : null;
        }
      }
      for (let p = el.__ptParent; p; p = p.__ptParent) if (isTag(p, 'form')) return p;
      return null;
    };
    // The form's tree, not the document: a detached form has its own controls.
    const formControls = (form) => {
      const out = [];
      let root = form;
      while (root.__ptParent) root = root.__ptParent;
      __walkTree(root, (n) => {
        if (!n || n.__ptType !== ELEMENT_NODE || !LISTED.has(local(n))) return;
        if (local(n) === 'input' && __s_toLowerCase(String(__ptGetA(n, 'type') || '')) === 'image') return;
        if (formOf(n) === form) out.push(n);
      });
      return out;
    };
    // Named and indexed members, as Chrome's interceptors answer them. A form
    // answers `form.q` and `form[0]` before its own members (an input named
    // "action" hides form.action), a name two controls share is a live
    // RadioNodeList, and a control keeps answering to a name it had until it
    // leaves the form (the past names map). Each form's names are worked out
    // once per DOM change.
    const R_get = Reflect.get, R_set = Reflect.set, R_has = Reflect.has, R_keys = Reflect.ownKeys;
    const R_desc = Reflect.getOwnPropertyDescriptor, R_def = Reflect.defineProperty, R_del = Reflect.deleteProperty;
    const arrayIndex = __arrayIndex;
    const engineKey = (k) => __s_charCodeAt(k, 0) === 95 && __s_charCodeAt(k, 1) === 95;
    const isHtmlForm = (t) => t.__ptLocal === 'form' && (t.__ptNS === undefined || t.__ptNS === 'http://www.w3.org/1999/xhtml');
    const addName = (m, k, el) => {
      if (!k) return;
      const v = m.get(k);
      if (v === undefined) m.set(k, el);
      else if (Array.isArray(v)) { if (v[v.length - 1] !== el) v.push(el); }
      else if (v !== el) m.set(k, [v, el]);
    };
    const namesOf = (list) => {
      const m = new Map();
      for (const el of list) { addName(m, __ptGetA(el, 'id'), el); addName(m, __ptGetA(el, 'name'), el); }
      return m;
    };
    const formMemo = new WeakMap(), pastNames = new WeakMap(), radioLists = new WeakMap(), controlLists = new WeakMap();
    const formState = (form) => {
      let st = formMemo.get(form);
      if (st && st.seq === __formSeq) return st;
      const ctrls = formControls(form);
      st = { seq: __formSeq, ctrls, names: namesOf(ctrls), imgs: null };
      formMemo.set(form, st);
      return st;
    };
    // An image belongs to the form around it.
    const imgOwner = (el) => { for (let p = el.__ptParent; p; p = p.__ptParent) if (isTag(p, 'form')) return p; return null; };
    const namedList = (form, k) => {
      const v = formState(form).names.get(k);
      return v === undefined ? [] : Array.isArray(v) ? v : [v];
    };
    const radioList = (form, k) => {
      let m = radioLists.get(form);
      if (!m) radioLists.set(form, m = new Map());
      let l = m.get(k);
      if (!l) { l = liveList(globalThis.RadioNodeList.prototype, () => namedList(form, k), null, 'RadioNodeList'); m.set(k, l); }
      return l;
    };
    const formNamed = (form, k) => {
      const st = formState(form);
      let v = st.names.get(k);
      if (v === undefined) {
        if (!st.imgs) {
          const imgs = [];
          __walkTree(form, (n) => { if (isTag(n, 'img') && imgOwner(n) === form) imgs.push(n); });
          st.imgs = namesOf(imgs);
        }
        v = st.imgs.get(k);
      }
      let past = pastNames.get(form);
      if (v === undefined) {
        const el = past && past.get(k);
        if (el === undefined) return undefined;
        if ((isTag(el, 'img') ? imgOwner(el) : formOf(el)) === form) return el;
        past.delete(k);
        return undefined;
      }
      if (Array.isArray(v)) return radioList(form, k);
      if (!past) pastNames.set(form, past = new Map());
      past.set(k, v);
      return v;
    };
    const noSetter = (iface, k, i) => __pt_mkErr(TypeError, i >= 0
      ? "Failed to set an indexed property [" + i + "] on '" + iface + "': Indexed property setter is not supported."
      : "Failed to set a named property '" + k + "' on '" + iface + "': Named property setter is not supported.");
    // A live list: its indices (and `names`, when given) come from `items()`
    // at each read, so a list a page holds follows the document.
    function liveList(proto, items, names, iface) {
      // The base interfaces get their members on first use (`__link`).
      if (names) __link('HTMLCollection', __collectionProto); else __link('NodeList', __nodeListProto);
      formIfaces();
      const t = Object.create(proto);
      const named = (k) => (!names || engineKey(k) || !__namesSeen.has(k) ? undefined : names().get(k));
      const value = (o, k) => {
        if (typeof k !== 'string') return undefined;
        const i = arrayIndex(k);
        if (i >= 0) return items()[i];
        const v = named(k);
        return Array.isArray(v) ? t.__ptNamedList(k) : v;
      };
      return __ptProxy(t, {
        get(o, k, r) {
          if (k === '__ptLen') return items().length;
          if (typeof k === 'string' && !(k in o)) { const v = value(o, k); if (v !== undefined) return v; if (arrayIndex(k) >= 0) return undefined; }
          return R_get(o, k, r);
        },
        has(o, k) { return value(o, k) !== undefined || R_has(o, k); },
        getOwnPropertyDescriptor(o, k) {
          const v = R_desc(o, k) ? undefined : value(o, k);
          return v === undefined ? R_desc(o, k) : { value: v, writable: false, enumerable: true, configurable: true };
        },
        ownKeys(o) {
          const out = [], n = items().length;
          for (let i = 0; i < n; i++) out.push(String(i));
          if (names) for (const k of names().keys()) if (arrayIndex(k) < 0 && !R_desc(o, k)) out.push(k);
          for (const k of R_keys(o)) out.push(k);
          return out;
        },
        // No setters: an index or a name is not assigned (a strict-mode page
        // gets no error either, unlike Chrome).
        set(o, k, v, r) { return (typeof k === 'string' && arrayIndex(k) >= 0) || (value(o, k) !== undefined && !R_desc(o, k)) ? true : R_set(o, k, v, r); },
        defineProperty(o, k, d) {
          if (typeof k === 'string') {
            const i = arrayIndex(k);
            if (i >= 0 || (value(o, k) !== undefined && !R_desc(o, k))) throw noSetter(iface, k, i);
          }
          return R_def(o, k, d);
        },
        deleteProperty(o, k) {
          if (typeof k === 'string' && arrayIndex(k) >= 0) return value(o, k) === undefined;
          return R_del(o, k);
        },
      });
    }
    const controlsOf = (form) => {
      let l = controlLists.get(form);
      if (!l) {
        l = liveList(globalThis.HTMLFormControlsCollection.prototype, () => formState(form).ctrls, () => formState(form).names, 'HTMLFormControlsCollection');
        Object.defineProperty(l, '__ptNamedList', { value: (k) => radioList(form, k), configurable: true });
        Object.defineProperty(l, '__ptForm', { value: form, configurable: true });
        controlLists.set(form, l);
      }
      return l;
    };
    __formProxy = (el) => {
      const named = (t, k) => {
        if (typeof k !== 'string' || engineKey(k) || !isHtmlForm(t)) return undefined;
        const i = arrayIndex(k);
        return i >= 0 ? formState(px).ctrls[i] : __namesSeen.has(k) ? formNamed(px, k) : undefined;
      };
      const px = __ptProxy(el, {
        get(t, k, r) { const v = named(t, k); return v !== undefined || (typeof k === 'string' && !engineKey(k) && arrayIndex(k) >= 0 && isHtmlForm(t)) ? v : R_get(t, k, r); },
        has(t, k) { return named(t, k) !== undefined || R_has(t, k); },
        getOwnPropertyDescriptor(t, k) {
          const v = named(t, k);
          if (v === undefined) return R_desc(t, k);
          return { value: v, writable: false, enumerable: arrayIndex(k) >= 0, configurable: true };
        },
        ownKeys(t) {
          const out = [];
          if (isHtmlForm(t)) { const n = formState(px).ctrls.length; for (let i = 0; i < n; i++) out.push(String(i)); }
          for (const k of R_keys(t)) out.push(k);
          return out;
        },
        set(t, k, v, r) { return named(t, k) !== undefined || (typeof k === 'string' && !engineKey(k) && isHtmlForm(t) && arrayIndex(k) >= 0) ? true : R_set(t, k, v, r); },
        defineProperty(t, k, d) {
          if (typeof k === 'string' && !engineKey(k) && isHtmlForm(t)) {
            const i = arrayIndex(k);
            if (i >= 0 || named(t, k) !== undefined) throw noSetter('HTMLFormElement', k, i);
          }
          return R_def(t, k, d);
        },
        deleteProperty(t, k) {
          if (typeof k === 'string' && !engineKey(k) && isHtmlForm(t) && arrayIndex(k) >= 0) return named(t, k) === undefined;
          return named(t, k) !== undefined ? true : R_del(t, k);
        },
      });
      __formTargets.set(px, el);
      return px;
    };
    const F = proto('HTMLFormElement');
    // `reset` fires a cancelable event, then each control goes back to its
    // default: the value and checkedness its attributes give, a drop-down's
    // selected options.
    defFn(F, 'reset', function reset() {
      if (!__formGet(this, 'dispatchEvent').call(this, __ptTrust(new Event('reset', { bubbles: true, cancelable: true })))) return;
      for (const el of formState(this).ctrls) {
        const t = local(el);
        if (t === 'input' || t === 'textarea') { el.__ptValue = undefined; el.__ptChecked = undefined; }
        else if (t === 'select') {
          for (const o of selOptions(el)) o.__ptSelected = undefined;
          __ptSelReset(el);
        }
      }
      __markDirty(this);
    });
    defGet(F, 'elements', function () { return controlsOf(this); });
    defGet(F, 'length', function () { return formState(this).ctrls.length; });
    // HTMLFormControlsCollection.namedItem and RadioNodeList.value. Those
    // interfaces come later in the bootstrap, so the members are put on
    // them at the first list, as `__link` does.
    let ifacesDone = false;
    const radios = (l) => { const out = []; for (let i = 0, n = l.length; i < n; i++) { const el = l[i]; if (isTag(el, 'input') && __inputType(el) === 'radio') out.push(el); } return out; };
    const formIfaces = () => {
      if (ifacesDone) return;
      ifacesDone = true;
      const nat = globalThis.__pt_native || ((f) => f);
      const named = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return nat(f); };
      const FCC = globalThis.HTMLFormControlsCollection && HTMLFormControlsCollection.prototype;
      const RNL = globalThis.RadioNodeList && RadioNodeList.prototype;
      const brand = (P, t) => { if (t === null || typeof t !== 'object' || !P.isPrototypeOf(t)) throw __pt_mkErr(TypeError, 'Illegal invocation'); };
      if (FCC) {
        defFn(FCC, 'namedItem', named(function (name) {
          brand(FCC, this);
          __needArgs(arguments.length, 1, 'namedItem', 'HTMLFormControlsCollection');
          const form = this.__ptForm;
          if (!form) return null;
          const k = String(name), list = namedList(form, k);
          return list.length === 0 ? null : list.length === 1 ? list[0] : radioList(form, k);
        }, 'namedItem'));
      }
      // The checked radio button's value; setting it checks the first radio
      // button with that value.
      if (RNL) {
        try {
          Object.defineProperty(RNL, 'value', {
            get: named(function () { brand(RNL, this); for (const el of radios(this)) if (el.checked) return el.value; return ''; }, 'get value'),
            set: named(function (v) { brand(RNL, this); const s = String(v); for (const el of radios(this)) if (el.value === s) { el.checked = true; return; } }, 'set value'),
            enumerable: true, configurable: true,
          });
        } catch (e) {}
      }
    };
    const labelsOf = (el) => {
      const out = [];
      const doc = el.ownerDocument;
      const root = doc && doc.documentElement ? doc.documentElement : null;
      if (!root) return out;
      __walkTree(root, (n) => {
        if (!isTag(n, 'label')) return;
        const f = __ptGetA(n, 'for');
        if (f != null) { if (f === el.id) out.push(n); return; }
        let found = null;
        __walkTree(n, (m) => { if (!found && m !== n && m.__ptType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && __s_toLowerCase(String(__ptGetA(m, 'type') || '')) === 'hidden')) found = m; });
        if (found === el) out.push(n);
      });
      return out;
    };
    const LABELABLE = new Set(['button', 'input', 'meter', 'output', 'progress', 'select', 'textarea']);
    for (const n of ['HTMLButtonElement', 'HTMLInputElement', 'HTMLMeterElement', 'HTMLOutputElement', 'HTMLProgressElement', 'HTMLSelectElement', 'HTMLTextAreaElement']) {
      const P = proto(n);
      defGet(P, 'labels', function () {
        if (local(this) === 'input' && __s_toLowerCase(String(__ptGetA(this, 'type') || '')) === 'hidden') return null;
        return __staticNodeList(labelsOf(this));
      });
    }
    for (const n of ['HTMLButtonElement', 'HTMLInputElement', 'HTMLOutputElement', 'HTMLSelectElement', 'HTMLTextAreaElement', 'HTMLFieldSetElement', 'HTMLObjectElement', 'HTMLLabelElement', 'HTMLLegendElement']) {
      const P = proto(n);
      defGet(P, 'form', function () {
        if (local(this) === 'legend') { const p = this.__ptParent; return p && isTag(p, 'fieldset') ? formOf(p) : null; }
        if (local(this) === 'label') { const c = this.control; return c ? formOf(c) : null; }
        return formOf(this);
      });
    }
    const L = proto('HTMLLabelElement');
    defGet(L, 'control', function () {
      const f = __ptGetA(this, 'for');
      if (f != null) { const el = this.ownerDocument && this.ownerDocument.getElementById ? this.ownerDocument.getElementById(f) : null; return el && LABELABLE.has(local(el)) ? el : null; }
      let found = null;
      __walkTree(this, (m) => { if (!found && m !== this && m.__ptType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && __s_toLowerCase(String(__ptGetA(m, 'type') || '')) === 'hidden')) found = m; });
      return found;
    });
    // Members that look reflected but are not, as in Chrome.
    // A script made by a page is async until told otherwise ("force async");
    // one from the parser is not.
    defPair(proto('HTMLScriptElement'), 'async',
      function () { return !this.__ptNoForceAsync || __ptHasA(this, 'async'); },
      function (v) { this.__ptNoForceAsync = true; if (v) __ptSetA(this, 'async', ''); else __ptDelA(this, 'async'); });
    // `disabled` is the sheet's flag; without a sheet it reads false and a
    // write does nothing.
    defPair(proto('HTMLStyleElement'), 'disabled',
      function () { const sh = this.sheet; return sh ? !!sh.disabled : false; },
      function (v) { const sh = this.sheet; if (sh) sh.disabled = !!v; });
    // A textarea's value is its text until edited, with line breaks as \n.
    const lf = (v) => __s_replace(String(v), /\r\n?/g, '\n');
    defPair(proto('HTMLTextAreaElement'), 'value',
      function () { return this.__ptValue !== undefined ? this.__ptValue : lf(this.textContent); },
      function (v) { this.__ptValue = lf(v); __markDirty(this); });
    // The default value of a textarea is its text.
    defPair(proto('HTMLTextAreaElement'), 'defaultValue',
      function () { return this.textContent; },
      function (v) { this.textContent = String(v); });
    defPair(proto('HTMLOutputElement'), 'defaultValue',
      function () { return this.__ptDefault != null ? this.__ptDefault : this.textContent; },
      function (v) { if (this.__ptDefault != null) this.__ptDefault = String(v); else this.textContent = String(v); });
    // The rendered size: only an image button has one, and nothing renders.
    for (const k of ['width', 'height']) {
      defPair(proto('HTMLInputElement'), k,
        function () { return __s_toLowerCase(String(__ptGetA(this, 'type') || '')) === 'image' ? (parseInt(__ptGetA(this, k), 10) >>> 0) || 0 : 0; },
        function (v) { __ptSetA(this, k, String(Number(v) >>> 0)); });
    }
    defPair(__mediaProto, 'preservesPitch',
      function () { return this.__ptKeepPitch !== false; },
      function (v) { this.__ptKeepPitch = !!v; });
    const M = proto('HTMLMapElement');
    defGet(M, 'areas', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'area')) out.push(n); }); return __collection(out); });
    const O = proto('HTMLOptionElement');
    defGet(O, 'index', function () { let p = this.__ptParent; if (p && isTag(p, 'optgroup')) p = p.__ptParent; return p && isTag(p, 'select') ? __s_indexOf(selOptions(p), this) : 0; });
    // Slots: a host's child goes to the first slot of its shadow tree with
    // the same name (or the slot it was assigned to in manual mode); Lit and
    // other components read `assignedElements()` to find their content.
    const SL = proto('HTMLSlotElement');
    defFn(SL, 'assignedNodes', function assignedNodes(opts) { return opts && opts.flatten ? __slotFlat(this) : __slotAssigned(this); });
    defFn(SL, 'assignedElements', function assignedElements(opts) { return (opts && opts.flatten ? __slotFlat(this) : __slotAssigned(this)).filter((n) => n.__ptType === ELEMENT_NODE); });
    defFn(SL, 'assign', function assign(...nodes) {
      const root = __slotRoot(this);
      const list = [];
      for (const n of nodes) {
        if (!n || (n.__ptType !== ELEMENT_NODE && n.__ptType !== TEXT_NODE)) throw __pt_mkErr(TypeError, "Failed to execute 'assign' on 'HTMLSlotElement': Failed to convert value to 'Element or Text'.");
        if (!__s_includes(list, n)) list.push(n);
      }
      // A node is assigned to one slot at a time.
      if (root) for (const other of __slotsIn(root)) if (other !== this && other.__ptManual) other.__ptManual = other.__ptManual.filter((n) => !__s_includes(list, n));
      Object.defineProperty(this, '__ptManual', { value: list, writable: true, configurable: true, enumerable: false });
    });
    const slotGet = function () { return __slotFor(this, true); };
    defGet(globalThis.Element && Element.prototype, 'assignedSlot', slotGet);
  }
  globalThis.__pt_elementProto = (tag) => {
    tag = __s_toLowerCase(String(tag));
    const iface = TAG_IFACE[tag];
    if (iface) return __ifaceProto.get(iface) || __htmlProto;
    if (PLAIN_TAGS.has(tag)) return __htmlProto;
    // Anything not in HTML is HTMLUnknownElement, as in Chrome.
    return /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(tag) ? __htmlProto : __ifaceProto.get('HTMLUnknownElement');
  };
  globalThis.__pt_setPendingTag = (tag) => { __pendingTag = String(tag || 'div'); };
  // `sheet` is the element's own stylesheet, the same one in
  // `document.styleSheets` (`document.querySelector('style').sheet.cssRules`).
  for (const iface of ['HTMLStyleElement', 'HTMLLinkElement']) {
    const proto = globalThis[iface] && globalThis[iface].prototype;
    if (!proto) continue;
    Object.defineProperty(proto, 'sheet', {
      get() {
        if (this.__ptLocal === 'link' && !__ptHasSheet(this)) return null;
        if (!this.isConnected) return null;
        return globalThis.__pt_sheetFor ? __pt_sheetFor(this) : null;
      },
      enumerable: true, configurable: true,
    });
  }
  // `decode()` as Chrome answers it: resolved once the image has loaded,
  // `EncodingError` with no `src`, for something that is not an image, or when
  // `src` changes while it waits; an image not loading (a far lazy one,
  // images switched off) leaves it pending.
  function __imgDecodeSettle(el, ok) {
    const list = el.__ptDecodeWait;
    if (!list || !list.length) return;
    el.__ptDecodeWait = null;
    for (const w of list) {
      if (ok) w.resolve();
      else w.reject(__pt_mkErr(globalThis.DOMException || Error, 'The source image cannot be decoded.', 'EncodingError'));
    }
  }
  {
    const proto = globalThis.HTMLImageElement && HTMLImageElement.prototype;
    if (proto) {
      const decode = { decode() {
        if (!(this instanceof HTMLImageElement)) throw __pt_mkErr(TypeError, 'Illegal invocation');
        const el = this;
        return new Promise((resolve, reject) => {
          if (!__ptGetA(el, 'src')) {
            reject(__pt_mkErr(globalThis.DOMException || Error, 'The source image cannot be decoded.', 'EncodingError'));
            return;
          }
          if (el.__ptImgDone) {
            if (el.__ptImgOk) resolve();
            else reject(__pt_mkErr(globalThis.DOMException || Error, 'The source image cannot be decoded.', 'EncodingError'));
            return;
          }
          if (!el.__ptDecodeWait) Object.defineProperty(el, '__ptDecodeWait', { value: [], writable: true, configurable: true, enumerable: false });
          el.__ptDecodeWait.push({ resolve, reject });
        });
      } }.decode;
      Object.defineProperty(proto, 'decode', {
        value: globalThis.__pt_native ? __pt_native(decode) : decode,
        writable: true, enumerable: true, configurable: true,
      });
    }
  }
  // `complete` is true when there is nothing to load or loading finished, and
  // false while in flight: right after setting `src` it is `false`, and turns
  // `true` with the event.
  {
    const proto = globalThis.HTMLImageElement && HTMLImageElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'complete', {
        get() {
          const src = __ptGetA(this, 'src');
          if (!src) return true;
          return !!this.__ptImgDone;
        },
        enumerable: true, configurable: true,
      });
    }
  }
  // HTMLTemplateElement members from Chrome 148. `content` is the fragment;
  // the rest reflect the declarative shadow root attributes.
  {
    const proto = globalThis.HTMLTemplateElement && HTMLTemplateElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'content', {
        get() { return globalThis.__pt_templateContent ? __pt_templateContent(this) : null; },
        enumerable: true, configurable: true,
      });
      const attr = (name, want) => Object.defineProperty(proto, name, {
        get() { const v = __ptGetA(this, want); return v === null ? (want === 'shadowrootmode' ? '' : false) : (want === 'shadowrootmode' ? v : true); },
        set(v) { if (want === 'shadowrootmode') __ptSetA(this, want, String(v)); else if (v) __ptSetA(this, want, ''); else __ptDelA(this, want); },
        enumerable: true, configurable: true,
      });
      attr('shadowRootMode', 'shadowrootmode');
      attr('shadowRootDelegatesFocus', 'shadowrootdelegatesfocus');
      attr('shadowRootClonable', 'shadowrootclonable');
      attr('shadowRootSerializable', 'shadowrootserializable');
      Object.defineProperty(proto, 'shadowRootCustomElementRegistry', {
        get() { return ''; }, set() {}, enumerable: true, configurable: true,
      });
    }
  }
  // The canvas prototype reference survives the worker-scope global trim:
  // OffscreenCanvas takes its methods from here when there is no document.
  try {
    Object.defineProperty(globalThis, '__pt_canvasProto', {
      value: globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype,
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}
  // SVG has its own, deeper ladder: `<path>` is SVGPathElement ->
  // SVGGeometryElement -> SVGGraphicsElement -> SVGElement -> Element. A widget
  // drawing its checkmark from path/line/circle exposes these names to the
  // fingerprinter. Chains from Chrome 148.
  const SVG_CHAIN = {"svg":["SVGSVGElement","SVGGraphicsElement","SVGElement"],"path":["SVGPathElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"line":["SVGLineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"circle":["SVGCircleElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"g":["SVGGElement","SVGGraphicsElement","SVGElement"],"rect":["SVGRectElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"text":["SVGTextElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"tspan":["SVGTSpanElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"defs":["SVGDefsElement","SVGGraphicsElement","SVGElement"],"use":["SVGUseElement","SVGGraphicsElement","SVGElement"],"polygon":["SVGPolygonElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"polyline":["SVGPolylineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"ellipse":["SVGEllipseElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"image":["SVGImageElement","SVGGraphicsElement","SVGElement"],"clipPath":["SVGClipPathElement","SVGElement"],"mask":["SVGMaskElement","SVGElement"],"pattern":["SVGPatternElement","SVGElement"],"filter":["SVGFilterElement","SVGElement"],"marker":["SVGMarkerElement","SVGElement"],"symbol":["SVGSymbolElement","SVGGraphicsElement","SVGElement"],"title":["SVGTitleElement","SVGElement"],"desc":["SVGDescElement","SVGElement"],"style":["SVGStyleElement","SVGElement"],"a":["SVGAElement","SVGGraphicsElement","SVGElement"],"foreignObject":["SVGForeignObjectElement","SVGGraphicsElement","SVGElement"],"linearGradient":["SVGLinearGradientElement","SVGGradientElement","SVGElement"],"radialGradient":["SVGRadialGradientElement","SVGGradientElement","SVGElement"],"stop":["SVGStopElement","SVGElement"],"animate":["SVGAnimateElement","SVGAnimationElement","SVGElement"],"textPath":["SVGTextPathElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"switch":["SVGSwitchElement","SVGGraphicsElement","SVGElement"],"metadata":["SVGMetadataElement","SVGElement"],"view":["SVGViewElement","SVGElement"],"set":["SVGSetElement","SVGAnimationElement","SVGElement"],"script":["SVGScriptElement","SVGElement"]};
  {
    const svgProto = new Map();
    // Built bottom-up: each step inherits from the next one in the chain.
    const protoFor = (chain, i) => {
      const name = chain[i];
      if (svgProto.has(name)) return svgProto.get(name);
      const parent = i + 1 < chain.length ? protoFor(chain, i + 1) : Element.prototype;
      const proto = __mkIface(name, parent);
      svgProto.set(name, proto);
      return proto;
    };
    for (const chain of Object.values(SVG_CHAIN)) protoFor(chain, 0);
    // Intermediate interfaces that are no tag's first link.
    for (const n of ['SVGGeometryElement', 'SVGGraphicsElement', 'SVGElement',
                     'SVGTextPositioningElement', 'SVGTextContentElement',
                     'SVGGradientElement', 'SVGAnimationElement', 'SVGComponentTransferFunctionElement']) {
      if (!svgProto.has(n)) svgProto.set(n, __mkIface(n, svgProto.get('SVGElement') || Element.prototype));
    }
    globalThis.__pt_svgProto = (tag) => svgProto.get((SVG_CHAIN[tag] || [])[0]) ||
                                        svgProto.get('SVGElement') || null;
    // By interface name, not tag: measuring members must sit on
    // `SVGTextContentElement`, not on `SVGElement`; pages walk the prototype
    // chain and see where each member lives.
    globalThis.__pt_svgIface = (name) => svgProto.get(name) || null;
  }


  // SVG measuring members (`getBBox`, `getTotalLength`, `getPointAtLength`,
  // `getScreenCTM`, `circle.cx`). A separate measuring path that is also
  // fingerprinted: text is measured by canvas and by the `<text>` bbox.
  {
    const P = (n) => (globalThis.__pt_svgIface && __pt_svgIface(n))
      || (globalThis.__pt_svgProto ? __pt_svgProto(n) : null);
    const wrap = (name, val) => {
      const C = globalThis[name];
      const o = C && C.prototype ? Object.create(C.prototype) : {};
      try {
        if (C && C.prototype && !Object.getOwnPropertyDescriptor(C.prototype, Symbol.toStringTag)) {
          Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true });
        }
      } catch (e) {}
      for (const [k, v] of Object.entries(val)) {
        Object.defineProperty(o, k, { value: v, enumerable: true, configurable: true, writable: true });
      }
      return o;
    };
    const svgLength = (v) => wrap('SVGLength', {
      unitType: 1, value: v, valueInSpecifiedUnits: v, valueAsString: String(v),
      newValueSpecifiedUnits() {}, convertToSpecifiedUnits() {},
    });
    const animLength = (get) => wrap('SVGAnimatedLength', {
      get baseVal() { return svgLength(get()); },
      get animVal() { return svgLength(get()); },
    });
    const svgRect = (x, y, w, h) => wrap('SVGRect', { x, y, width: w, height: h });
    const svgPoint = (x, y) => wrap('SVGPoint', { x, y, matrixTransform() { return svgPoint(x, y); } });
    const svgMatrix = () => wrap('SVGMatrix', {
      a: 1, b: 0, c: 0, d: 1, e: 0, f: 0,
      multiply() { return svgMatrix(); }, inverse() { return svgMatrix(); },
      translate() { return svgMatrix(); }, scale() { return svgMatrix(); },
      rotate() { return svgMatrix(); }, flipX() { return svgMatrix(); }, flipY() { return svgMatrix(); },
      skewX() { return svgMatrix(); }, skewY() { return svgMatrix(); },
      scaleNonUniform() { return svgMatrix(); }, rotateFromVector() { return svgMatrix(); },
    });
    const num = (el, name, dflt) => {
      const v = parseFloat(el.getAttribute && __ptGetA(el, name));
      return Number.isFinite(v) ? v : (dflt || 0);
    };

    // Parse the `d` attribute into contour points used for both bbox and
    // length. Curves are split into segments, as Chrome does (with a finer step).
    const pathPoints = (d) => {
      const out = [];
      const toks = __s_match(String(d || ''), /[MmLlHhVvCcSsQqTtAaZz]|-?[\d.]+(?:e-?\d+)?/g) || [];
      let i = 0, x = 0, y = 0, sx = 0, sy = 0, cmd = '';
      const n = () => parseFloat(toks[i++]) || 0;
      const push = (px, py) => out.push([px, py]);
      const bez = (x0, y0, x1, y1, x2, y2, x3, y3) => {
        for (let t = 1; t <= 16; t++) {
          const u = t / 16, m = 1 - u;
          push(m*m*m*x0 + 3*m*m*u*x1 + 3*m*u*u*x2 + u*u*u*x3,
               m*m*m*y0 + 3*m*m*u*y1 + 3*m*u*u*y2 + u*u*u*y3);
        }
      };
      while (i < toks.length) {
        if (/[A-Za-z]/.test(toks[i])) cmd = toks[i++];
        const rel = cmd === __s_toLowerCase(cmd);
        const C = __s_toUpperCase(cmd);
        if (C === 'M') { const a = n(), b = n(); x = rel ? x + a : a; y = rel ? y + b : b; sx = x; sy = y; push(x, y); cmd = rel ? 'l' : 'L'; }
        else if (C === 'L') { const a = n(), b = n(); x = rel ? x + a : a; y = rel ? y + b : b; push(x, y); }
        else if (C === 'H') { const a = n(); x = rel ? x + a : a; push(x, y); }
        else if (C === 'V') { const a = n(); y = rel ? y + a : a; push(x, y); }
        else if (C === 'C') {
          const x1 = n(), y1 = n(), x2 = n(), y2 = n(), x3 = n(), y3 = n();
          const ax1 = rel ? x + x1 : x1, ay1 = rel ? y + y1 : y1;
          const ax2 = rel ? x + x2 : x2, ay2 = rel ? y + y2 : y2;
          const ax3 = rel ? x + x3 : x3, ay3 = rel ? y + y3 : y3;
          bez(x, y, ax1, ay1, ax2, ay2, ax3, ay3); x = ax3; y = ay3;
        } else if (C === 'Q') {
          const x1 = n(), y1 = n(), x2 = n(), y2 = n();
          const ax1 = rel ? x + x1 : x1, ay1 = rel ? y + y1 : y1;
          const ax2 = rel ? x + x2 : x2, ay2 = rel ? y + y2 : y2;
          bez(x, y, x + 2/3*(ax1-x), y + 2/3*(ay1-y), ax2 + 2/3*(ax1-ax2), ay2 + 2/3*(ay1-ay2), ax2, ay2);
          x = ax2; y = ay2;
        } else if (C === 'Z') { push(sx, sy); x = sx; y = sy; }
        else { i++; }
      }
      return out;
    };

    const boxOfPoints = (pts) => {
      if (!pts.length) return [0, 0, 0, 0];
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const [px, py] of pts) { x0 = Math.min(x0, px); y0 = Math.min(y0, py); x1 = Math.max(x1, px); y1 = Math.max(y1, py); }
      return [x0, y0, x1 - x0, y1 - y0];
    };
    const lenOfPoints = (pts) => {
      let L = 0;
      for (let k = 1; k < pts.length; k++) L += Math.hypot(pts[k][0] - pts[k-1][0], pts[k][1] - pts[k-1][1]);
      return L;
    };
    const outline = (el) => {
      const t = __s_toLowerCase(el.__ptLocal || '');
      if (t === 'path') return pathPoints(__ptGetA(el, 'd'));
      if (t === 'line') return [[num(el, 'x1'), num(el, 'y1')], [num(el, 'x2'), num(el, 'y2')]];
      if (t === 'rect') { const x = num(el, 'x'), y = num(el, 'y'), w = num(el, 'width'), h = num(el, 'height');
        return [[x, y], [x + w, y], [x + w, y + h], [x, y + h], [x, y]]; }
      if (t === 'circle') { const cx = num(el, 'cx'), cy = num(el, 'cy'), r = num(el, 'r');
        return [[cx - r, cy - r], [cx + r, cy + r]]; }
      if (t === 'ellipse') { const cx = num(el, 'cx'), cy = num(el, 'cy'), rx = num(el, 'rx'), ry = num(el, 'ry');
        return [[cx - rx, cy - ry], [cx + rx, cy + ry]]; }
      if (t === 'polyline' || t === 'polygon') {
        const nums = __s_match(String(__ptGetA(el, 'points') || ''), /-?[\d.]+/g) || [];
        const pts = []; for (let k = 0; k + 1 < nums.length; k += 2) pts.push([+nums[k], +nums[k+1]]);
        return pts;
      }
      return [];
    };

    const graphics = P('SVGGraphicsElement');
    const geometry = P('SVGGeometryElement');
    const textContent = P('SVGTextContentElement');
    const def = (proto, name, value) => {
      if (!proto) return;
      try { Object.defineProperty(proto, name, { value, writable: true, enumerable: true, configurable: true }); } catch (e) {}
    };
    const acc = (proto, name, get) => {
      if (!proto) return;
      try { Object.defineProperty(proto, name, { get, enumerable: true, configurable: true }); } catch (e) {}
    };

    def(graphics, 'getBBox', function getBBox() {
      // The bbox needs a laid-out tree; otherwise stylesheet rules are not
      // collected yet and text is measured in the wrong face.
      __relayout();
      const t = __s_toLowerCase(this.__ptLocal || '');
      if (t === 'text' || t === 'tspan') {
        // Text bbox: width measured and rounded up to 1/64 px, ascent and
        // height from font metrics (verified at three sizes). Size and face come
        // from the cascade, not computed style, which builds 400+ properties
        // and cost ~1/8 s per `<text>` bbox.
        if (!__svgLaidOut(this)) return svgRect(0, 0, 0, 0);
        const s = __svgScale(this);
        const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
        const { fam, bold, italic } = __svgFont(this);
        // The bbox is the union of the ink box and the layout box: rightward
        // the farther one ("W" ink overflows its advance), leftward only if
        // ink starts before the origin (Arial "jjj" starts a pixel left).
        // Verified on five face/size combinations.
        const txt = __svgText(this);
        // No text, no box: Chrome returns zeros, not a line-high strip.
        if (!txt) return svgRect(0, 0, 0, 0);
        // Transformed text is laid out at size * scale (truncated to
        // hundredths), width rounded up to 1/64, then divided back in float32.
        const m = __textMetrics(txt, fs, fam, bold, italic);
        const adv = m[0] || 0;
        const over = Math.max(m[1] || 0, 0);
        const w = over + Math.ceil(Math.max(m[2] || 0, adv) * 64) / 64;
        const { asc, desc } = __svgAscDesc(txt, fs, fam);
        const x = num(this, 'x'), y = num(this, 'y');
        if (s === 1) return svgRect(x - over, y - asc, w, asc + desc);
        // Back from scaled space Chrome multiplies by the inverse scale in
        // float32 rather than dividing.
        const fr = Math.fround;
        const s32 = fr(s), inv = fr(1 / s32);
        return svgRect(fr(fr(fr(x * s32) - over) * inv), fr(fr(fr(y * s32) - asc) * inv), fr(w * inv), fr((asc + desc) * inv));
      }
      const kids = [...(this.__ptKids || [])].filter((k) => k.__ptType === ELEMENT_NODE);
      if (!outline(this).length && kids.length) {
        // A group's bbox is the union of its children's, each in its own
        // transform; float32 numbers, as in Chrome.
        const fr = Math.fround;
        let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        for (const k of kids) {
          if (!k.getBBox) continue;
          const b = k.getBBox();
          let bx = b.x, by = b.y, bw = b.width, bh = b.height;
          const M = __svgOwnMatrix(k);
          if (M) {
            const pts = [[bx, by], [bx + bw, by], [bx, by + bh], [bx + bw, by + bh]]
              .map(([px, py]) => [fr(M[0] * px + M[2] * py + M[4]), fr(M[1] * px + M[3] * py + M[5])]);
            const xs = pts.map((q) => q[0]), ys = pts.map((q) => q[1]);
            bx = Math.min(...xs); by = Math.min(...ys); bw = fr(Math.max(...xs) - bx); bh = fr(Math.max(...ys) - by);
          }
          x0 = Math.min(x0, bx); y0 = Math.min(y0, by);
          x1 = Math.max(x1, fr(bx + bw)); y1 = Math.max(y1, fr(by + bh));
        }
        if (x0 !== Infinity) return svgRect(x0, y0, fr(x1 - x0), fr(y1 - y0));
      }
      const [x, y, w, h] = boxOfPoints(outline(this));
      return svgRect(x, y, w, h);
    });
    def(graphics, 'getCTM', function getCTM() { return svgMatrix(); });
    def(graphics, 'getScreenCTM', function getScreenCTM() { return svgMatrix(); });
    def(geometry, 'getTotalLength', function getTotalLength() { return lenOfPoints(outline(this)); });
    def(geometry, 'getPointAtLength', function getPointAtLength(at) {
      const pts = outline(this);
      let left = Math.max(0, +at || 0);
      for (let k = 1; k < pts.length; k++) {
        const dx = pts[k][0] - pts[k-1][0], dy = pts[k][1] - pts[k-1][1];
        const seg = Math.hypot(dx, dy);
        if (left <= seg || k === pts.length - 1) {
          const u = seg ? left / seg : 0;
          return svgPoint(pts[k-1][0] + dx * u, pts[k-1][1] + dy * u);
        }
        left -= seg;
      }
      return svgPoint(pts.length ? pts[0][0] : 0, pts.length ? pts[0][1] : 0);
    });
    def(geometry, 'isPointInFill', function isPointInFill(pt) {
      const [x, y, w, h] = boxOfPoints(outline(this));
      const px = pt && pt.x || 0, py = pt && pt.y || 0;
      return px >= x && px <= x + w && py >= y && py <= y + h;
    });
    def(geometry, 'isPointInStroke', function isPointInStroke(pt) { return this.isPointInFill(pt); });
    acc(geometry, 'pathLength', function pathLength() { return animLength(() => num(this, 'pathLength')); });
    // Text length is the layout advance, not the bbox (ink can be wider than
    // the glyph). SVG text face and style come from the cascade, else the
    // document default (Times New Roman in Chrome), not sans-serif.
    const __svgFont = (el) => {
      const c = __cascadeFor(el);
      let famRaw = c.get('font-family');
      if (famRaw == null) famRaw = __inheritedValue(el, 'font-family');
      const fam = __s_trim(String(famRaw || '')) || String((typeof CS_BASE !== 'undefined' && CS_BASE['font-family']) || '"Times New Roman"');
      let st = c.get('font-style'); if (st == null) st = __inheritedValue(el, 'font-style');
      let wt = c.get('font-weight'); if (wt == null) wt = __inheritedValue(el, 'font-weight');
      const italic = /^(italic|oblique)/i.test(String(st || ''));
      const w = __s_toLowerCase(String(wt || ''));
      const bold = w === 'bold' || w === 'bolder' || (Number(w) >= 600);
      return { fam, bold, italic };
    };
    // Text scale: product of uniform scales of the element's and ancestors'
    // transforms up to the svg root; Chrome picks the layout font size this
    // way (`CalculateScreenFontSizeScalingFactor`).
    const __svgOwnMatrix = (n) => {
      let t = null;
      try { t = __cascadeFor(n).get('transform'); } catch (e) {}
      if (t == null) t = __ptGetA(n, 'transform');
      return __parseTransform(t);
    };
    const __svgOwnScale = (n) => {
      const M = __svgOwnMatrix(n);
      if (!M) return 1;
      const sc = Math.sqrt((M[0] * M[0] + M[1] * M[1] + M[2] * M[2] + M[3] * M[3]) / 2);
      return isFinite(sc) && sc > 0 ? sc : 1;
    };
    const __svgScale = (el) => {
      let s = 1;
      for (let n = el; n && n.__ptType === ELEMENT_NODE; n = n.__ptParent) {
        s *= __svgOwnScale(n);
        if (n.__ptLocal === 'svg') break;
      }
      return s;
    };
    const __svgSizeEff = (fs, s) => (s === 1 ? fs : Math.floor(fs * s * 100 + 1e-7) / 100);
    // Line ascent/descent come from the run's face: emoji use Noto Color
    // Emoji, with its metrics (1900/512 per 2048).
    const EMOJI_RE = /\p{Extended_Pictographic}/u;
    const __svgAscDesc = (txt, fs, fam) => {
      const fb = __fontBox(fs, fam);
      let asc = fb.asc, desc = fb.desc;
      if (EMOJI_RE.test(txt)) {
        const rest = __s_replace(txt, /\p{Extended_Pictographic}|\uFE0F|\u200D|[\u{1F3FB}-\u{1F3FF}]|\s/gu, '');
        // For the bitmap emoji face ascent and descent are the image bounds,
        // same as canvas actualBoundingBox (15/4 at 16px, 23/6 at 24px,
        // 139/38 at 150px).
        const m = __textMetrics(txt, fs, fam, false, false);
        const ea = Math.round(m[3] || fs * 1900 / 2048), ed = Math.round(m[4] || fs * 512 / 2048);
        if (!rest) { asc = ea; desc = ed; } else { asc = Math.max(asc, ea); desc = Math.max(desc, ed); }
      }
      return { asc, desc };
    };
    // Without layout (windowless document, detached node, unslotted host
    // child) Chrome returns zero lengths and boxes.
    const __svgLaidOut = (el) => {
      if (!el || !el.isConnected) return false;
      if (el.ownerDocument && el.ownerDocument !== document && !el.ownerDocument.defaultView) return false;
      if (typeof globalThis.__pt_inFlatTree === 'function' && !globalThis.__pt_inFlatTree(el)) return false;
      return true;
    };
    def(textContent, 'getComputedTextLength', function getComputedTextLength() {
      __relayout();
      if (!__svgLaidOut(this)) return 0;
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const txt = __svgText(this);
      if (!txt) return 0;
      const w = Math.ceil(__textWidth(txt, fs, fam, bold, italic) * 64) / 64;
      // Length divides by the scale in float32 (the bbox multiplies by the
      // inverse: two different paths in Chrome).
      return s === 1 ? w : Math.fround(w / Math.fround(s));
    });
    def(textContent, 'getSubStringLength', function getSubStringLength(start, n) {
      __relayout();
      if (!__svgLaidOut(this)) return 0;
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const full = __svgText(this);
      const from = Math.max(0, start | 0), len = Math.max(0, n | 0);
      const txt = __s_slice(full, from, from + len);
      if (!txt) return 0;
      const w = Math.ceil(__textWidth(txt, fs, fam, bold, italic) * 64) / 64;
      // Length divides by the scale in float32 (the bbox multiplies by the
      // inverse: two different paths in Chrome).
      return s === 1 ? w : Math.fround(w / Math.fround(s));
    });
    // Char extent: the line box of the element's face (primary font ascent and
    // descent), as wide as the glyph's advance.
    def(textContent, 'getExtentOfChar', function getExtentOfChar(i) {
      __relayout();
      if (!__svgLaidOut(this)) return svgRect(0, 0, 0, 0);
      const s = __svgScale(this);
      const fs = __svgSizeEff(__usedFontSize(this) || 16, s);
      const { fam, bold, italic } = __svgFont(this);
      const full = __svgText(this);
      let idx = Number(i); if (!isFinite(idx) || idx < 0) idx = 0; idx = Math.floor(idx);
      if (!full || idx >= full.length) {
        throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'getExtentOfChar' on 'SVGTextContentElement': The index provided (" + idx + ") is outside the range of characters.", 'IndexSizeError');
      }
      // A char includes its surrogate pair and modifiers: an emoji sequence has
      // one advance.
      const cps = Array.from(full);
      let at = 0, ci = 0;
      for (; ci < cps.length && at + cps[ci].length <= idx; ci++) at += cps[ci].length;
      const before = __s_slice(full, 0, at);
      const ch = __s_slice(full, at, at + (cps[ci] ? cps[ci].length : 1)) || __s_slice(full, at, at + 1);
      const wAll = __textWidth(before + ch, fs, fam, bold, italic), wBefore = before ? __textWidth(before, fs, fam, bold, italic) : 0;
      const adv = Math.ceil(Math.max(0, wAll - wBefore) * 64) / 64;
      const fb = __fontBox(fs, fam);
      const x = num(this, 'x') + wBefore, y = num(this, 'y');
      if (s === 1) return svgRect(x, y - fb.asc, adv, fb.asc + fb.desc);
      const fr = Math.fround; const s32 = fr(s), inv = fr(1 / s32);
      return svgRect(fr(fr(x * s32) * inv), fr(fr(fr(y * s32) - fb.asc) * inv), fr(adv / s32), fr((fb.asc + fb.desc) * inv));
    });
    def(textContent, 'getNumberOfChars', function getNumberOfChars() { return String(this.textContent || '').length; });

    // Geometry attributes are `SVGAnimatedLength`, not strings.
    const GEOM_ATTRS = {
      SVGCircleElement: ['cx', 'cy', 'r'],
      SVGEllipseElement: ['cx', 'cy', 'rx', 'ry'],
      SVGRectElement: ['x', 'y', 'width', 'height', 'rx', 'ry'],
      SVGLineElement: ['x1', 'y1', 'x2', 'y2'],
      SVGSVGElement: ['x', 'y', 'width', 'height'],
      SVGImageElement: ['x', 'y', 'width', 'height'],
      SVGTextPositioningElement: ['x', 'y', 'dx', 'dy'],
    };
    for (const [iface, attrs] of Object.entries(GEOM_ATTRS)) {
      const proto = P(iface) || (globalThis[iface] && globalThis[iface].prototype);
      for (const a of attrs) acc(proto, a, function () { return animLength(() => num(this, a)); });
    }
    const svgEl = P('SVGSVGElement');
    acc(svgEl, 'viewBox', function viewBox() {
      const n = __s_match(String(__ptGetA(this, 'viewBox') || ''), /-?[\d.]+/g) || [];
      const r = svgRect(+n[0] || 0, +n[1] || 0, +n[2] || 0, +n[3] || 0);
      return wrap('SVGAnimatedRect', { baseVal: r, animVal: r });
    });
    def(svgEl, 'createSVGPoint', function createSVGPoint() { return svgPoint(0, 0); });
    def(svgEl, 'createSVGRect', function createSVGRect() { return svgRect(0, 0, 0, 0); });
    def(svgEl, 'createSVGMatrix', function createSVGMatrix() { return svgMatrix(); });
    def(svgEl, 'createSVGLength', function createSVGLength() { return svgLength(0); });
  }

  // Codec probing is a standard fingerprint block sent whole in the
  // challenge's report. Chrome matches the codec against the container. Table
  // from Chrome 151 on this machine, 597 strings; `audio/mpeg`, `audio/aac`
  // and `audio/flac` are their own codec, so without a codec list they answer
  // `probably`; other known ones `maybe`.
  {
    const FAMILY = {
      'video/mp4': ['avc1.', 'avc3.', 'hev1.', 'hvc1.', 'av01.', 'vp09.', 'mp4a.40.',
                    'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'flac'],
      'video/webm': ['vp8', 'vp9', 'vp09.', 'av01.', 'opus', 'vorbis'],
      'video/ogg': ['vp8', 'opus', 'vorbis', 'flac'],
      'video/3gpp': ['avc1.', 'avc3.', 'mp4a.40.'],
      'video/x-matroska': ['avc1.', 'avc3.', 'hev1.', 'hvc1.', 'av01.', 'vp8', 'vp09.',
                           'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'vorbis', 'flac', '1'],
      'application/x-mpegurl': ['avc1.', 'avc3.', 'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3'],
      'application/vnd.apple.mpegurl': ['avc1.', 'avc3.', 'mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3'],
      'audio/mp4': ['mp4a.40.', 'mp4a.69', 'mp4a.6b', 'mp3', 'opus', 'flac'],
      'audio/ogg': ['opus', 'vorbis', 'flac'],
      'audio/webm': ['opus', 'vorbis'],
      'audio/wav': ['1'],
      'audio/x-wav': ['1'],
      'audio/x-m4a': ['mp4a.40.'],
      'audio/mpeg': ['mp3', 'mp4a.69', 'mp4a.6b'],
      'audio/aac': [],
      'audio/flac': [],
    };
    // These types are their own codec: container and content are the same.
    const SINGLE = new Set(['audio/mpeg', 'audio/aac', 'audio/flac']);
    const canPlay = function canPlayType(type) {
      const t = __s_trim(String(type == null ? '' : type));
      const semi = __s_indexOf(t, ';');
      const mime = __s_toLowerCase(__s_trim(semi < 0 ? t : __s_slice(t, 0, semi)));
      const rest = semi < 0 ? '' : __s_slice(t, semi + 1);
      const m = /codecs\s*=\s*"?([^"]*)"?/i.exec(rest);
      const codecs = m ? __s_split(m[1], ',').map((c) => __s_toLowerCase(__s_trim(c))).filter(Boolean) : [];
      const allowed = FAMILY[mime];
      if (!allowed) return '';
      if (!codecs.length) return SINGLE.has(mime) ? 'probably' : 'maybe';
      const fits = (c) => allowed.some((a) => (__s_charAt(a, a.length - 1) === '.' ? __s_indexOf(c, a) === 0 : c === a));
      return codecs.every(fits) ? 'probably' : '';
    };
    const M = globalThis.HTMLMediaElement && globalThis.HTMLMediaElement.prototype;
    if (M) {
      try { Object.defineProperty(M, 'canPlayType', { value: canPlay, writable: true, enumerable: true, configurable: true }); } catch (e) {}
      __mediaInstall(M, canPlay);
    }
    // Gamepads: Chrome returns four empty slots, not nothing; pages read `.length`.
    const N = globalThis.Navigator && globalThis.Navigator.prototype;
    if (N) {
      const fn = function getGamepads() { return [null, null, null, null]; };
      try {
        Object.defineProperty(N, 'getGamepads', {
          value: globalThis.__pt_native ? __pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
    // `MediaSource.isTypeSupported` answers from the same table, as a boolean.
    const MS = globalThis.MediaSource;
    if (MS) {
      try {
        Object.defineProperty(MS, 'isTypeSupported', {
          value: function isTypeSupported(type) { return canPlay(type) === 'probably'; },
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  // Media elements as Chrome 151 keeps them (values measured): a state per
  // element, the resource selection with `loadstart`, then a Range request
  // (`preload="none"` stops at `suspend`), `progress` and `suspend` when the
  // answer is in, then the metadata events for something that looks like
  // media, or `error` (MediaError 4) for anything else. The document's `load`
  // waits for it. Nothing is decoded or played: `play()` answers as Chrome
  // does with no playable source.
  function __mediaInstall(M, canPlay) {
    const V = globalThis.HTMLVideoElement && HTMLVideoElement.prototype;
    const state = new WeakMap();
    const st = (el) => {
      let s = state.get(el);
      if (!s) {
        s = { networkState: 0, readyState: 0, currentSrc: '', error: null, paused: true, ended: false, seeking: false,
          volume: 1, muted: null, playbackRate: 1, defaultPlaybackRate: 1, currentTime: 0, at: null, gen: 0,
          tracks: null, remote: null, ranges: null };
        state.set(el, s);
      }
      return s;
    };
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const acc = (P, name, get, set) => {
      if (!P) return;
      const d = Object.getOwnPropertyDescriptor(P, name);
      try {
        Object.defineProperty(P, name, {
          get: nat(get, 'get ' + name), set: set ? nat(set, 'set ' + name) : (d && d.set) || undefined,
          enumerable: d ? d.enumerable : true, configurable: true,
        });
      } catch (e) {}
    };
    const meth = (P, name, f, len) => {
      try { Object.defineProperty(f, 'length', { value: len | 0, configurable: true }); } catch (e) {}
      try { Object.defineProperty(P, name, { value: nat(f, name), writable: true, enumerable: true, configurable: true }); } catch (e) {}
    };
    // Instances of the interfaces as they stand when first made: the shape
    // pass replaces their prototypes after this runs, so their members are
    // set then.
    const shaped = new WeakSet();
    const mk = (iface, members) => {
      const C = globalThis[iface];
      const P = C && C.prototype;
      if (!P) return {};
      if (members && !shaped.has(P)) { shaped.add(P); members(P); }
      return Object.create(P);
    };
    // Empty time ranges; `start`/`end` on an empty one throw as in Chrome.
    const rangeState = new WeakMap();
    const rangeMembers = (TR) => {
      acc(TR, 'length', function () { const l = rangeState.get(this); return l ? l.length : 0; });
      for (const which of ['start', 'end']) {
        meth(TR, which, function (i) {
          const l = rangeState.get(this) || [];
          const k = Number(i);
          if (!(k >= 0 && k < l.length)) {
            throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute '" + which + "' on 'TimeRanges': The index provided (" + (k >>> 0) + ") is greater than or equal to the maximum bound (" + l.length + ').', 'IndexSizeError');
          }
          return l[k][which === 'start' ? 0 : 1];
        }, 1);
      }
    };
    const ranges = () => { const r = mk('TimeRanges', rangeMembers); rangeState.set(r, []); return r; };
    const errState = new WeakMap();
    const errMembers = (ME) => {
      acc(ME, 'code', function () { const e = errState.get(this); return e ? e[0] : 0; });
      acc(ME, 'message', function () { const e = errState.get(this); return e ? e[1] : ''; });
    };
    const mediaError = (code, message) => { const e = mk('MediaError', errMembers); errState.set(e, [code, message]); return e; };
    const trackMembers = (TTL) => acc(TTL, 'length', function () { return 0; });
    const fire = (el, type) => { try { el.dispatchEvent(__ptTrust(new Event(type))); } catch (e) {} };
    // The source the selection algorithm takes: `src`, else the first
    // `<source>` whose type can play.
    const pick = (el) => {
      const src = __ptGetA(el, 'src');
      if (src !== null) return src;
      for (const k of (el.__ptKids || [])) {
        if (k.__ptLocal !== 'source') continue;
        const s2 = __ptGetA(k, 'src');
        if (!s2) continue;
        const type = __ptGetA(k, 'type');
        if (type && canPlay(type) === '') continue;
        return s2;
      }
      return null;
    };
    const load = (el, connecting) => {
      const s = st(el);
      const raw = pick(el);
      if (raw === null) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (connecting && s.at === url) return;
      s.at = url;
      const gen = ++s.gen;
      s.error = null; s.readyState = 0; s.currentSrc = ''; s.networkState = 3;
      const tag = el.__ptLocal;
      const preload = __s_toLowerCase(String(__ptGetA(el, 'preload') || ''));
      const holdRel = preload === 'none' ? null : __holdLoad(tag + ' ' + url);
      __ptLater(() => {
        if (s.gen !== gen) { if (holdRel) holdRel(); return; }
        s.currentSrc = url; s.networkState = 2;
        fire(el, 'loadstart');
        if (preload === 'none') { s.networkState = 1; fire(el, 'suspend'); return; }
        const done = (ok, text) => {
          if (s.gen !== gen) { if (holdRel) holdRel(); return; }
          fire(el, 'progress');
          s.networkState = 1; fire(el, 'suspend');
          // The engine read the bytes' signature (the text here is lossy).
          if (ok && !(globalThis.__pt_mediaIsBad && __pt_mediaIsBad(url))) {
            s.readyState = 1; fire(el, 'durationchange'); fire(el, 'loadedmetadata');
            s.readyState = 4; fire(el, 'loadeddata'); fire(el, 'canplay'); fire(el, 'canplaythrough');
          } else {
            s.error = mediaError(4, 'PipelineStatus::DEMUXER_ERROR_COULD_NOT_OPEN: FFmpegDemuxer: open context failed');
            s.networkState = 3;
            fire(el, 'error');
          }
          if (holdRel) holdRel();
        };
        if (typeof globalThis.__pt_subresourceText !== 'function') { done(false, null); return; }
        globalThis.__pt_subresourceText(url, tag).then((t) => done(t != null, t), () => done(false, null));
      }, 0);
    };
    Object.defineProperty(globalThis, '__pt_mediaLoad', { value: load, configurable: true, enumerable: false });
    acc(M, 'networkState', function () { return st(this).networkState; });
    acc(M, 'readyState', function () { return st(this).readyState; });
    acc(M, 'currentSrc', function () { return st(this).currentSrc; });
    acc(M, 'error', function () { return st(this).error; });
    acc(M, 'paused', function () { return st(this).paused; });
    acc(M, 'ended', function () { return st(this).ended; });
    acc(M, 'seeking', function () { return st(this).seeking; });
    acc(M, 'duration', function () { return NaN; });
    acc(M, 'currentTime', function () { return st(this).currentTime; }, function (v) { st(this).currentTime = Number(v) || 0; });
    acc(M, 'volume', function () { return st(this).volume; }, function (v) {
      const x = Number(v);
      if (!(x >= 0 && x <= 1)) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to set the 'volume' property on 'HTMLMediaElement': The volume provided (" + v + ') is outside the range [0, 1].', 'IndexSizeError');
      st(this).volume = x;
    });
    acc(M, 'muted', function () { const s = st(this); return s.muted === null ? __ptHasA(this, 'muted') : s.muted; }, function (v) { st(this).muted = !!v; });
    acc(M, 'playbackRate', function () { return st(this).playbackRate; }, function (v) { st(this).playbackRate = Number(v); });
    acc(M, 'defaultPlaybackRate', function () { return st(this).defaultPlaybackRate; }, function (v) { st(this).defaultPlaybackRate = Number(v); });
    for (const n of ['buffered', 'played', 'seekable']) acc(M, n, function () { return ranges(); });
    acc(M, 'textTracks', function () { const s = st(this); return s.tracks || (s.tracks = mk('TextTrackList', trackMembers)); });
    acc(M, 'remote', function () { const s = st(this); return s.remote || (s.remote = mk('RemotePlayback')); });
    acc(M, 'controlsList', function () { return makeClassList(this, 'controlslist'); });
    acc(M, 'sinkId', function () { return ''; });
    acc(M, 'webkitAudioDecodedByteCount', function () { return 0; });
    acc(M, 'webkitVideoDecodedByteCount', function () { return 0; });
    for (const n of ['videoWidth', 'videoHeight', 'webkitDecodedFrameCount', 'webkitDroppedFrameCount']) acc(V, n, function () { return 0; });
    meth(M, 'load', function load_() { load(this, false); }, 0);
    meth(M, 'pause', function pause() {
      const s = st(this);
      if (!s.paused) { s.paused = true; __ptLater(() => { fire(this, 'timeupdate'); fire(this, 'pause'); }, 0); }
    }, 0);
    meth(M, 'play', function play() {
      const s = st(this);
      // Nothing here plays: with no source that opens, Chrome rejects this way.
      if (s.error || s.networkState === 3 || s.readyState < 1) {
        return Promise.reject(__pt_mkErr(globalThis.DOMException || Error, 'The element has no supported sources.', 'NotSupportedError'));
      }
      s.paused = false;
      __ptLater(() => { fire(this, 'play'); fire(this, 'playing'); }, 0);
      return Promise.resolve();
    }, 0);
  }

  // `hidden` is a reflected HTMLElement attribute present on every element.
  Object.defineProperty(__htmlProto, 'hidden', {
    get() { return __ptHasA(this, 'hidden'); },
    set(v) { if (v) __ptSetA(this, 'hidden', ''); else __ptDelA(this, 'hidden'); },
    enumerable: true, configurable: true,
  });

  // Member distribution per interface, lists from Chrome 148. Our
  // implementations are generic (they read attributes), so a member present on
  // several interfaces is installed on each with the same descriptor.
const CHROME_ELEMENT = ["activeViewTransition","after","animate","append","ariaActiveDescendantElement","ariaAtomic","ariaAutoComplete","ariaBrailleLabel","ariaBrailleRoleDescription","ariaBusy","ariaChecked","ariaColCount","ariaColIndex","ariaColIndexText","ariaColSpan","ariaControlsElements","ariaCurrent","ariaDescribedByElements","ariaDescription","ariaDetailsElements","ariaDisabled","ariaErrorMessageElements","ariaExpanded","ariaFlowToElements","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLabelledByElements","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaNotify","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowIndexText","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","assignedSlot","attachShadow","attributes","before","checkVisibility","childElementCount","children","classList","className","clientHeight","clientLeft","clientTop","clientWidth","closest","computedStyleMap","currentCSSZoom","customElementRegistry","elementTiming","firstElementChild","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","id","innerHTML","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","lastElementChild","localName","matches","moveBefore","namespaceURI","nextElementSibling","onbeforecopy","onbeforecut","onbeforepaste","onfullscreenchange","onfullscreenerror","onsearch","onwebkitfullscreenchange","onwebkitfullscreenerror","outerHTML","part","prefix","prepend","previousElementSibling","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","role","scroll","scrollBy","scrollHeight","scrollIntoView","scrollIntoViewIfNeeded","scrollLeft","scrollTo","scrollTop","scrollWidth","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTML","setHTMLUnsafe","setPointerCapture","shadowRoot","slot","startViewTransition","tagName","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen"];
const CHROME_HTMLELEMENT = ["accessKey","attachInternals","attributeStyleMap","autocapitalize","autofocus","blur","click","contentEditable","dataset","dir","draggable","editContext","enterKeyHint","focus","hidden","hidePopover","inert","innerText","inputMode","isContentEditable","lang","nonce","offsetHeight","offsetLeft","offsetParent","offsetTop","offsetWidth","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeinput","onbeforematch","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","outerText","popover","showPopover","spellcheck","style","tabIndex","title","togglePopover","translate","virtualKeyboardPolicy","writingSuggestions"];
const CHROME_IFACE_MEMBERS = {"HTMLAnchorElement":["attributionSrc","charset","coords","download","hash","host","hostname","href","hrefTranslate","hreflang","interestForElement","name","origin","password","pathname","ping","port","protocol","referrerPolicy","rel","relList","rev","search","shape","target","text","toString","type","username"],"HTMLBRElement":["clear"],"HTMLBodyElement":["aLink","background","bgColor","link","onafterprint","onbeforeprint","onbeforeunload","onblur","onerror","onfocus","ongamepadconnected","ongamepaddisconnected","onhashchange","onlanguagechange","onload","onmessage","onmessageerror","onoffline","ononline","onpagehide","onpageshow","onpopstate","onrejectionhandled","onresize","onscroll","onstorage","onunhandledrejection","onunload","text","vLink"],"HTMLButtonElement":["checkValidity","command","commandForElement","disabled","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","interestForElement","labels","name","popoverTargetAction","popoverTargetElement","reportValidity","setCustomValidity","type","validationMessage","validity","value","willValidate"],"HTMLCanvasElement":["captureStream","getContext","height","toBlob","toDataURL","transferControlToOffscreen","width"],"HTMLDivElement":["align"],"HTMLFormElement":["acceptCharset","action","autocomplete","checkValidity","elements","encoding","enctype","length","method","name","noValidate","rel","relList","reportValidity","requestSubmit","reset","submit","target"],"HTMLHeadingElement":["align"],"HTMLHtmlElement":["version"],"HTMLIFrameElement":["adAuctionHeaders","align","allow","allowFullscreen","allowPaymentRequest","browsingTopics","contentDocument","contentWindow","credentialless","csp","featurePolicy","frameBorder","getSVGDocument","height","loading","longDesc","marginHeight","marginWidth","name","privateToken","referrerPolicy","sandbox","scrolling","sharedStorageWritable","src","srcdoc","width"],"HTMLImageElement":["align","alt","attributionSrc","border","browsingTopics","complete","crossOrigin","currentSrc","decode","decoding","fetchPriority","height","hspace","isMap","loading","longDesc","lowsrc","name","naturalHeight","naturalWidth","referrerPolicy","sharedStorageWritable","sizes","src","srcset","useMap","vspace","width","x","y"],"HTMLInputElement":["accept","align","alt","autocomplete","checkValidity","checked","defaultChecked","defaultValue","dirName","disabled","files","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","height","incremental","indeterminate","labels","list","max","maxLength","min","minLength","multiple","name","pattern","placeholder","popoverTargetAction","popoverTargetElement","readOnly","reportValidity","required","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","showPicker","size","src","step","stepDown","stepUp","type","useMap","validationMessage","validity","value","valueAsDate","valueAsNumber","webkitEntries","webkitdirectory","width","willValidate"],"HTMLLIElement":["type","value"],"HTMLLabelElement":["control","form","htmlFor"],"HTMLLinkElement":["as","blocking","charset","crossOrigin","disabled","fetchPriority","href","hreflang","imageSizes","imageSrcset","integrity","media","referrerPolicy","rel","relList","rev","sheet","sizes","target","type"],"HTMLMetaElement":["content","httpEquiv","media","name","scheme"],"HTMLOptionElement":["defaultSelected","disabled","form","index","label","selected","text","value"],"HTMLParagraphElement":["align"],"HTMLScriptElement":["async","attributionSrc","blocking","charset","crossOrigin","defer","event","fetchPriority","htmlFor","innerText","integrity","noModule","referrerPolicy","src","text","textContent","type"],"HTMLSelectElement":["add","autocomplete","checkValidity","disabled","form","item","labels","length","multiple","name","namedItem","options","remove","reportValidity","required","selectedIndex","selectedOptions","setCustomValidity","showPicker","size","type","validationMessage","validity","value","willValidate"],"HTMLStyleElement":["blocking","disabled","media","sheet","type"],"HTMLTableElement":["align","bgColor","border","caption","cellPadding","cellSpacing","createCaption","createTBody","createTFoot","createTHead","deleteCaption","deleteRow","deleteTFoot","deleteTHead","frame","insertRow","rows","rules","summary","tBodies","tFoot","tHead","width"],"HTMLTextAreaElement":["autocomplete","checkValidity","cols","defaultValue","dirName","disabled","form","labels","maxLength","minLength","name","placeholder","readOnly","reportValidity","required","rows","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","textLength","type","validationMessage","validity","value","willValidate","wrap"],"HTMLTitleElement":["text"],"HTMLUListElement":["compact","type"],"HTMLVideoElement":["cancelVideoFrameCallback","disablePictureInPicture","getVideoPlaybackQuality","height","onenterpictureinpicture","onleavepictureinpicture","playsInline","poster","requestPictureInPicture","requestVideoFrameCallback","videoHeight","videoWidth","webkitDecodedFrameCount","webkitDroppedFrameCount","width"]};
  {
    const onElement = new Set(CHROME_ELEMENT);
    const onHtml = new Set(CHROME_HTMLELEMENT);
    const owners = new Map();   // name -> [interface prototypes]
    for (const [iface, members] of Object.entries(CHROME_IFACE_MEMBERS)) {
      const proto = __ifaceProto.get(iface);
      if (!proto) continue;
      for (const m of members) {
        if (!owners.has(m)) owners.set(m, []);
        owners.get(m).push(proto);
      }
    }
    for (const name of Object.getOwnPropertyNames(Element.prototype)) {
      if (name === 'constructor' || __s_lastIndexOf(name, '__pt', 0) === 0) continue;
      if (onElement.has(name)) continue;
      const d = Object.getOwnPropertyDescriptor(Element.prototype, name);
      if (!d || !d.configurable) continue;
      const targets = onHtml.has(name) ? [__htmlProto] : (owners.get(name) || []);
      if (!targets.length) continue;   // our own member: leave it as is
      for (const proto of targets) {
        if (Object.getOwnPropertyDescriptor(proto, name)) continue;
        try { Object.defineProperty(proto, name, d); } catch (e) {}
      }
      try { delete Element.prototype[name]; } catch (e) {}
    }
    // Some members also go on SVG through a shared mixin; without them an SVG
    // node had no style declaration or cascade (`<text font-size="150">`
    // measured at 16px).
    const svgRoot = globalThis.SVGElement && SVGElement.prototype;
    if (svgRoot) {
      for (const name of ['style', 'dataset', 'attributeStyleMap', 'nonce',
                          'tabIndex', 'autofocus', 'focus', 'blur']) {
        if (Object.getOwnPropertyDescriptor(svgRoot, name)) continue;
        const d = Object.getOwnPropertyDescriptor(__htmlProto, name);
        if (d) {
          try { Object.defineProperty(svgRoot, name, d); } catch (e) {}
        }
      }
    }
  }

  // Interface shape from Chrome 148: name -> category -> member names. The
  // fingerprinter walks the prototype chain by enumerable keys, so any missing
  // step is visible. Only missing members are filled; implemented ones are
  // left alone.
  const CHROME_IFACE_SHAPE = {"AudioContext":{"N":["close","createMediaElementSource","createMediaStreamDestination","createMediaStreamSource","getOutputTimestamp","resume","suspend","setSinkId"],"x":["baseLatency","outputLatency","onerror","playbackStats","sinkId","onsinkchange"]},"BaseAudioContext":{"N":["createAnalyser","createBiquadFilter","createBuffer","createBufferSource","createChannelMerger","createChannelSplitter","createConstantSource","createConvolver","createDelay","createDynamicsCompressor","createGain","createIIRFilter","createOscillator","createPanner","createPeriodicWave","createScriptProcessor","createStereoPanner","createWaveShaper","decodeAudioData"],"x":["destination","sampleRate","currentTime","listener","state","onstatechange","audioWorklet"]},"CSSStyleDeclaration":{"#0":["length"],"N":["getPropertyPriority","getPropertyValue","item","removeProperty","setProperty"],"e":["cssText","cssFloat"],"x":["parentRule"]},"DOMTokenList":{"#2":["length"],"N":["entries","keys","values","forEach","add","contains","item","remove","replace","supports","toggle","toString"],"s:a b":["value"]},"Element":{"#0":["scrollTop","scrollLeft","clientTop","clientLeft"],"#1":["childElementCount","currentCSSZoom"],"#18":["scrollHeight","clientHeight"],"#764":["scrollWidth","clientWidth"],"N":["after","animate","append","attachShadow","before","checkVisibility","closest","computedStyleMap","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","matches","moveBefore","prepend","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","scroll","scrollBy","scrollIntoView","scrollIntoViewIfNeeded","scrollTo","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTMLUnsafe","setPointerCapture","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen","ariaNotify","setHTML","startViewTransition"],"e":["slot","elementTiming"],"o":["classList","attributes","part","children","firstElementChild","lastElementChild","nextElementSibling","customElementRegistry"],"s:<div id=\"d\" class=\"a b\"><span>x</span></div>":["outerHTML"],"s:<span>x</span>":["innerHTML"],"s:DIV":["tagName"],"s:a b":["className"],"s:d":["id"],"s:div":["localName"],"s:http://www.w3.org/1999/xhtml":["namespaceURI"],"x":["prefix","shadowRoot","assignedSlot","onbeforecopy","onbeforecut","onbeforepaste","onsearch","onfullscreenchange","onfullscreenerror","onwebkitfullscreenchange","onwebkitfullscreenerror","role","ariaAtomic","ariaAutoComplete","ariaBusy","ariaBrailleLabel","ariaBrailleRoleDescription","ariaChecked","ariaColCount","ariaColIndex","ariaColSpan","ariaCurrent","ariaDescription","ariaDisabled","ariaExpanded","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","previousElementSibling","activeViewTransition","ariaColIndexText","ariaRowIndexText","ariaActiveDescendantElement","ariaControlsElements","ariaDescribedByElements","ariaDetailsElements","ariaErrorMessageElements","ariaFlowToElements","ariaLabelledByElements"]},"HTMLCanvasElement":{"#150":["height"],"#300":["width"],"N":["captureStream","getContext","toBlob","toDataURL","transferControlToOffscreen"]},"HTMLCollection":{"#1":["length"],"N":["item","namedItem"]},"HTMLElement":{"#-1":["tabIndex"],"#18":["offsetHeight"],"#764":["offsetWidth"],"#8":["offsetTop","offsetLeft"],"F":["hidden","inert","draggable","isContentEditable","autofocus"],"N":["attachInternals","blur","click","focus","hidePopover","showPopover","togglePopover"],"T":["translate","spellcheck"],"e":["title","lang","dir","accessKey","autocapitalize","enterKeyHint","inputMode","virtualKeyboardPolicy","nonce"],"o":["offsetParent","dataset","style","attributeStyleMap"],"s:inherit":["contentEditable"],"s:true":["writingSuggestions"],"s:x":["innerText","outerText"],"x":["editContext","popover","onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"NamedNodeMap":{"#2":["length"],"N":["getNamedItem","getNamedItemNS","item","removeNamedItem","removeNamedItemNS","setNamedItem","setNamedItemNS"]},"NodeList":{"#1":["length"],"N":["entries","keys","values","forEach","item"]},"OfflineAudioContext":{"N":["resume","startRendering","suspend"],"x":["oncomplete","length"]},"Performance":{"#0":["interactionCount"],"#1786865974979.1":["timeOrigin"],"N":["clearMarks","clearMeasures","clearResourceTimings","getEntries","getEntriesByName","getEntriesByType","mark","measure","setResourceTimingBufferSize","toJSON","now"],"o":["timing","navigation","memory","eventCounts"],"x":["onresourcetimingbufferfull"]},"SVGAnimatedLength":{"x":["baseVal","animVal"]},"SVGAnimatedRect":{"x":["baseVal","animVal"]},"SVGAnimatedString":{"x":["baseVal","animVal"]},"SVGAnimatedTransformList":{"x":["baseVal","animVal"]},"SVGCircleElement":{"o":["cx","cy","r"]},"SVGElement":{"#-1":["tabIndex"],"F":["autofocus"],"N":["blur","focus"],"e":["nonce"],"o":["className","ownerSVGElement","viewportElement","dataset","style","attributeStyleMap"],"x":["onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"SVGGeometryElement":{"N":["getPointAtLength","getTotalLength","isPointInFill","isPointInStroke"],"o":["pathLength"]},"SVGGraphicsElement":{"N":["getBBox","getCTM","getScreenCTM"],"o":["transform","nearestViewportElement","farthestViewportElement","requiredExtensions","systemLanguage"]},"SVGLength":{"N":["convertToSpecifiedUnits","newValueSpecifiedUnits"],"#0":["SVG_LENGTHTYPE_UNKNOWN"],"#1":["SVG_LENGTHTYPE_NUMBER"],"#2":["SVG_LENGTHTYPE_PERCENTAGE"],"#3":["SVG_LENGTHTYPE_EMS"],"#4":["SVG_LENGTHTYPE_EXS"],"#5":["SVG_LENGTHTYPE_PX"],"#6":["SVG_LENGTHTYPE_CM"],"#7":["SVG_LENGTHTYPE_MM"],"#8":["SVG_LENGTHTYPE_IN"],"#9":["SVG_LENGTHTYPE_PT"],"#10":["SVG_LENGTHTYPE_PC"],"x":["unitType","value","valueInSpecifiedUnits","valueAsString"]},"SVGLineElement":{"o":["x1","y1","x2","y2"]},"SVGMatrix":{"N":["flipX","flipY","inverse","multiply","rotate","rotateFromVector","scale","scaleNonUniform","skewX","skewY","translate"],"x":["a","b","c","d","e","f"]},"SVGPoint":{"N":["matrixTransform"],"x":["x","y"]},"SVGPointList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGRect":{"x":["x","y","width","height"]},"SVGRectElement":{"o":["x","y","width","height","rx","ry"]},"SVGSVGElement":{"#0":["SVG_ZOOMANDPAN_UNKNOWN"],"#1":["currentScale","SVG_ZOOMANDPAN_DISABLE"],"#2":["zoomAndPan","SVG_ZOOMANDPAN_MAGNIFY"],"N":["animationsPaused","checkEnclosure","checkIntersection","createSVGAngle","createSVGLength","createSVGMatrix","createSVGNumber","createSVGPoint","createSVGRect","createSVGTransform","createSVGTransformFromMatrix","deselectAll","forceRedraw","getCurrentTime","getElementById","getEnclosureList","getIntersectionList","pauseAnimations","setCurrentTime","suspendRedraw","unpauseAnimations","unsuspendRedraw","unsuspendRedrawAll"],"o":["x","y","width","height","currentTranslate","viewBox","preserveAspectRatio"]},"SVGStringList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGTransformList":{"N":["appendItem","clear","consolidate","createSVGTransformFromMatrix","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"ShadowRoot":{"F":["delegatesFocus","serializable","clonable"],"N":["elementFromPoint","elementsFromPoint","getAnimations","getHTML","getSelection","setHTMLUnsafe","setHTML"],"a":["adoptedStyleSheets"],"e":["innerHTML"],"o":["host","styleSheets","customElementRegistry"],"s:named":["slotAssignment"],"s:open":["mode"],"x":["onslotchange","activeElement","pointerLockElement","fullscreenElement","pictureInPictureElement"]},"SpeechSynthesis":{"F":["pending","speaking","paused"],"N":["cancel","getVoices","pause","resume","speak"],"x":["onvoiceschanged"]},"Storage":{"#0":["length"],"N":["clear","getItem","key","removeItem","setItem"]}};
  globalThis.__pt_fillShapes = () => {
    const native = globalThis.__pt_native || ((f) => f);
    const stub = (name, cat) => {
      if (cat === 'N') {
        return native(({ [name]: function () {} })[name]);
      }
      if (cat === 'x') return null;
      if (cat === 'u') return undefined;
      if (cat === 'T') return true;
      if (cat === 'F') return false;
      if (cat === 'e') return '';
      if (cat === 'o') return {};
      if (cat === 'a') return [];
      if (cat === 'p') { const q = Promise.resolve(); q.catch(() => {}); return q; }
      if (__s_charCodeAt(cat, 0) === 35) return Number(__s_slice(cat, 1));      // '#12' → 12
      if (__s_charCodeAt(cat, 0) === 115 && cat[1] === ':') return __s_slice(cat, 2);   // 's:auto'
      return undefined;
    };
    for (const iface of Object.keys(CHROME_IFACE_SHAPE)) {
      const C = globalThis[iface];
      const proto = C && C.prototype;
      if (!proto) continue;
      // "Already present" means on the interface or lower in the DOM chain,
      // not inherited from Object.prototype.
      const has = (name) => {
        for (let o = proto; o && o !== Object.prototype; o = Object.getPrototypeOf(o)) {
          if (Object.prototype.hasOwnProperty.call(o, name)) return true;
        }
        return false;
      };
      for (const cat of Object.keys(CHROME_IFACE_SHAPE[iface])) {
        for (const name of CHROME_IFACE_SHAPE[iface][cat]) {
          if (has(name)) continue;
          try {
            Object.defineProperty(proto, name, {
              value: stub(name, cat), writable: true, enumerable: true, configurable: true,
            });
          } catch (e) {}
        }
      }
    }
  };
  __pt_fillShapes();


  // Storage access in a third-party frame: the Turnstile widget requests it,
  // and Chrome then marks the frame's requests with a separate header. It must
  // return a promise.
  try {
    const D = Document.prototype;
    const def = (name, fn) => {
      try {
        Object.defineProperty(D, name, {
          value: globalThis.__pt_native ? __pt_native(fn) : fn,
          writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    };
    def('requestStorageAccess', function requestStorageAccess(types) {
      globalThis.__ptStorageAccess = true;
      if (types && typeof types === 'object') {
        const handle = {};
        for (const k of Object.keys(types)) if (types[k]) handle[k] = true;
        return Promise.resolve(handle);
      }
      return Promise.resolve(undefined);
    });
    def('hasStorageAccess', function hasStorageAccess() { return Promise.resolve(true); });
    def('hasUnpartitionedCookieAccess', function hasUnpartitionedCookieAccess() {
      return Promise.resolve(true);
    });
    def('requestStorageAccessFor', function requestStorageAccessFor() {
      globalThis.__ptStorageAccess = true;
      return Promise.resolve(undefined);
    });
  } catch (e) {}

  globalThis.ShadowRoot = ShadowRoot;
  globalThis.CharacterData = CharacterData;
  globalThis.Text = Text;
  globalThis.Comment = Comment;
  globalThis.ProcessingInstruction = ProcessingInstruction;
  globalThis.Document = Document;
  globalThis.Event = Event;
  globalThis.CustomEvent = CustomEvent;
  globalThis.WebGLContextEvent = WebGLContextEvent;
  globalThis.DocumentFragment = DocumentFragment;
  document.__ptView = globalThis;

  // <script> nodes in document order, so the loader can point `currentScript` at
  // the one it is about to run (for document.write positioning).
  let scriptNodes = [];

  // Called by the loader with the Rust-parsed <html> tree.
  // A child window's document built in place, no network, no engine: an empty
  // iframe gets `<html><head></head><body></body></html>`, `srcdoc` gets the
  // parsed markup, and scripts inside run in that window.
  // `DOMParser` and `XMLSerializer` are common fingerprint probes. Parsing uses
  // the `innerHTML` parser, serializing the `outerHTML` serializer plus a
  // namespace on the root, as Chrome does.
  const VOID_XML = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
    'link', 'meta', 'param', 'source', 'track', 'wbr']);
  globalThis.__pt_lateDom = {
    parseDocument(markup, type) {
      const kind = __s_toLowerCase(String(type || 'text/html'));
      const doc = new Document();
      Object.defineProperty(doc, '__ptContentType', { value: kind, writable: true, configurable: true });
      const isHtml = kind === 'text/html';
      if (!isHtml) Object.defineProperty(doc, '__ptXml', { value: true, writable: true, configurable: true });
      if (isHtml) {
        __parseDocumentInto(doc, markup == null ? '' : markup);
        return this.finishParsed(doc, true);
      }
      const nodes = (() => {
        const r = this.parseXml(doc, String(markup == null ? '' : markup));
        let root = r.nodes.find((n) => n.__ptType === ELEMENT_NODE);
        if (r.error) {
          // Chrome's parse error (libxml2): <parsererror> as the root's first
          // child, or html/body/parsererror without a root.
          const pe = this.parseErrorNode(doc, r.error);
          if (root) __ptInsert.call(root, pe, root.firstChild);
          else {
            root = doc.createElement('html'); __ptSetAttr.call(root, 'xmlns', 'http://www.w3.org/1999/xhtml');
            const body = doc.createElement('body'); __ptAdd.call(root, body); __ptAdd.call(body, pe);
            return [root];
          }
        }
        return r.nodes;
      })();
      let root = nodes.find((n) => n.__ptType === ELEMENT_NODE && n.__ptLocal === 'html');
      if (!root && isHtml) {
        root = doc.createElement('html');
        const head = doc.createElement('head');
        const body = doc.createElement('body');
        __ptAdd.call(root, head);
        __ptAdd.call(root, body);
        for (const n of nodes) __ptAdd.call(body, n);
      } else if (!root) {
        root = nodes.find((n) => n.__ptType === ELEMENT_NODE) || doc.createElement('html');
      } else if (isHtml) {
        if (!__tags(root, 'head')[0]) __ptInsert.call(root, doc.createElement('head'), root.firstChild);
        if (!__tags(root, 'body')[0]) __ptAdd.call(root, doc.createElement('body'));
      }
      __ptAdd.call(doc, root);
      doc.__ptDocEl = root;
      return this.finishParsed(doc, isHtml);
    },
    finishParsed(doc, isHtml) {
      __walkTree(doc, (n) => { n.__ptDoc = doc; });
      // A document from a string is complete immediately and has no window
      // (`location` own property, null); class HTMLDocument or XMLDocument.
      doc.__ptReady = 'complete';
      try {
        const g = function () { return null; };
        try { Object.defineProperty(g, 'name', { value: 'get location', configurable: true }); } catch (e) {}
        Object.defineProperty(doc, 'location', { get: globalThis.__pt_native ? __pt_native(g) : g, set: undefined, enumerable: true, configurable: false });
      } catch (e) {}
      try {
        if (isHtml) {
          const hp = globalThis.document && Object.getPrototypeOf(globalThis.document);
          if (hp && hp !== Document.prototype && hp.constructor && hp.constructor.name === 'HTMLDocument') Object.setPrototypeOf(doc, hp);
          else if (typeof globalThis.HTMLDocument === 'function' && globalThis.HTMLDocument.prototype && Object.getPrototypeOf(globalThis.HTMLDocument.prototype) === Document.prototype) Object.setPrototypeOf(doc, globalThis.HTMLDocument.prototype);
        } else if (typeof globalThis.XMLDocument === 'function' && globalThis.XMLDocument.prototype && Object.getPrototypeOf(globalThis.XMLDocument.prototype) === Document.prototype) {
          Object.setPrototypeOf(doc, globalThis.XMLDocument.prototype);
        }
      } catch (e) {}
      return doc;
    },
    // ---- XML: parsed by XML rules with libxml2-worded errors, as Chrome
    // shows them (`error on line L at column C: …`).
    parseXml(doc, src) {
      const out = { nodes: [], error: null };
      let i = 0; const n = src.length; let line = 1, ls = 0;
      const stack = [];
      const push = (node) => { const top = stack[stack.length - 1]; if (top) __ptAdd.call(top, node); else out.nodes.push(node); };
      const col = (at) => at - ls + 1;
      const fail = (msg, at) => { if (!out.error) out.error = { msg, line, col: col(at === undefined ? i : at) }; };
      const text = (t) => doc.createTextNode(t);
      const decode = (s) => __s_replace(s, /&(#[xX][0-9a-fA-F]+|#[0-9]+|[A-Za-z_][\w.\-]*);/g, (m, e) => {
        if (e[0] === '#') { const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(__s_slice(e, 2), 16) : parseInt(__s_slice(e, 1), 10); return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '\ufffd'; }
        const p = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e];
        if (p === undefined) { fail("Entity '" + e + "' not defined"); return ''; }
        return p;
      });
      let rootSeen = false;
      const advance = (from, to) => { for (let k = from; k < to; k++) if (__s_charCodeAt(src, k) === 10) { line++; ls = k + 1; } };
      while (i < n && !out.error) {
        if (src[i] === '<') {
          if (__s_startsWith(src, '<?', i)) { const e = __s_indexOf(src, '?>', i + 2); if (e < 0) { fail("Parsing XML declaration: '?>' expected"); break; } advance(i, e + 2); i = e + 2; continue; }
          if (__s_startsWith(src, '<!--', i)) { const e = __s_indexOf(src, '-->', i + 4); if (e < 0) { fail('Comment not terminated'); break; } push(doc.createComment(__s_slice(src, i + 4, e))); advance(i, e + 3); i = e + 3; continue; }
          if (__s_startsWith(src, '<![CDATA[', i)) { const e = __s_indexOf(src, ']]>', i + 9); if (e < 0) { fail('CData section not finished'); break; } if (!stack.length) { fail('Extra content at the end of the document'); break; } push(text(__s_slice(src, i + 9, e))); advance(i, e + 3); i = e + 3; continue; }
          if (__s_startsWith(src, '<!DOCTYPE', i)) { const e = __s_indexOf(src, '>', i); if (e < 0) { fail('DOCTYPE improperly terminated'); break; } advance(i, e + 1); i = e + 1; continue; }
          if (src[i + 1] === '/') {
            const m = /^<\/([^\s>]+)\s*>/.exec(__s_slice(src, i));
            if (!m) { fail("expected '>'"); break; }
            const top = stack[stack.length - 1];
            if (!top) { fail('Extra content at the end of the document'); break; }
            if (top.__ptLocal !== m[1]) { fail('Opening and ending tag mismatch: ' + top.__ptLocal + ' line ' + top.__ptLine + ' and ' + m[1], i + m[0].length + 1); break; }
            stack.pop(); i += m[0].length; continue;
          }
          const m = /^<([A-Za-z_:][\w:.\-]*)/.exec(__s_slice(src, i));
          if (!m) { fail('StartTag: invalid element name', i + 1); break; }
          if (!stack.length && rootSeen) { fail('Extra content at the end of the document'); break; }
          let el = doc.createElement(m[1]); el.__ptLine = line;
          let j = i + m[0].length;
          for (;;) {
            j += /^\s*/.exec(__s_slice(src, j))[0].length;
            if (src[j] === '>') { j++; break; }
            if (__s_startsWith(src, '/>', j)) { j += 2; push(el); if (!stack.length) rootSeen = true; el = null; break; }
            const am = /^([A-Za-z_:][\w:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/.exec(__s_slice(src, j));
            if (!am) {
              const nm = /^([A-Za-z_:][\w:.\-]*)/.exec(__s_slice(src, j));
              if (nm) fail('Specification mandates value for attribute ' + nm[1], j + nm[0].length); else fail('error parsing attribute name', j);
              break;
            }
            const val = am[2] !== undefined ? am[2] : am[3];
            if (__s_indexOf(val, '<') >= 0) { fail("Unescaped '<' not allowed in attributes values", j); break; }
            if (__ptHasA(el, am[1])) { fail('Attribute ' + am[1] + ' redefined', j); break; }
            __ptSetAttr.call(el, am[1], decode(val)); j += am[0].length;
          }
          if (out.error) break;
          if (el) { push(el); if (!stack.length) rootSeen = true; stack.push(el); }
          advance(i, j); i = j; continue;
        }
        const next = __s_indexOf(src, '<', i); const stop = next < 0 ? n : next;
        const chunk = __s_slice(src, i, stop);
        if (!stack.length) {
          if (__s_trim(chunk)) { fail(rootSeen ? 'Extra content at the end of the document' : "Start tag expected, '<' not found", i + (chunk.length - __s_replace(chunk, /^\s+/, '').length)); break; }
        } else push(text(decode(chunk)));
        advance(i, stop); i = stop;
      }
      if (!out.error && stack.length) { const top = stack[stack.length - 1]; fail('Premature end of data in tag ' + top.__ptLocal + ' line ' + top.__ptLine, n); }
      if (!out.error && !rootSeen) fail(__s_trim(src) ? "Start tag expected, '<' not found" : 'Document is empty', 0);
      return out;
    },
    parseErrorNode(doc, err) {
      const mk = (name, attrs, txt) => { const e = doc.createElement(name); for (const k of Object.keys(attrs)) __ptSetAttr.call(e, k, attrs[k]); if (txt != null) __ptAdd.call(e, doc.createTextNode(txt)); return e; };
      const pe = mk('parsererror', { xmlns: 'http://www.w3.org/1999/xhtml', style: 'display: block; white-space: pre; border: 2px solid #c77; padding: 0 1em 0 1em; margin: 1em; background-color: #fdd; color: black' }, null);
      __ptAdd.call(pe, mk('h3', {}, 'This page contains the following errors:'));
      __ptAdd.call(pe, mk('div', { style: 'font-family:monospace;font-size:12px' }, 'error on line ' + err.line + ' at column ' + err.col + ': ' + err.msg + '\n'));
      __ptAdd.call(pe, mk('h3', {}, 'Below is a rendering of the page up to the first error.'));
      return pe;
    },
    serializeXml(node) {
      // A whole document serializes as its root element with xmlns.
      if (node && node.__ptType === 9 && node.documentElement) node = node.documentElement;
      const one = (n, root) => {
        if (n.__ptType === TEXT_NODE) return esc(String(n.__ptData), false);
        if (n.__ptType === COMMENT_NODE) return '<!--' + n.__ptData + '-->';
        if (n.__ptType !== ELEMENT_NODE) {
          // Fragment children (shadow root included) are each a root: xmlns on
          // every top-level element, as in Chrome.
          return (n.__ptKids || []).map((c) => one(c, root)).join('');
        }
        const tag = n.__ptLocal;
        let attrs = '';
        if (root && !(n.ownerDocument && n.ownerDocument.__ptXml)) attrs += ' xmlns="http://www.w3.org/1999/xhtml"';
        for (const [name, value] of n.__ptAttrs) attrs += ' ' + name + '="' + esc(String(value), true) + '"';
        const kids = (n.__ptKids || []).map((c) => one(c, false)).join('');
        if (!kids && VOID_XML.has(tag)) return '<' + tag + attrs + ' />';
        return '<' + tag + attrs + '>' + kids + '</' + tag + '>';
      };
      // Fragment and shadow root: their top-level children are roots (xmlns).
      return one(node, node && (node.__ptType === ELEMENT_NODE || node.__ptType === DOCUMENT_FRAGMENT_NODE));
    },
  };

  // `window.length` and `window.frames[i]` count live frames, recomputed from
  // the tree so they stay in sync with insertions.
  {
    let cache = null, cacheSeq = -1, cacheDoc = null;
    const frameEls = () => {
      const doc = globalThis.document;
      if (cache && cacheSeq === __framesSeq && cacheDoc === doc) return cache;
      const out = [];
      cache = out; cacheSeq = __framesSeq; cacheDoc = doc;
      if (!doc || !doc.documentElement) return out;
      // Light tree only: Chrome does not count frames inside shadow roots.
      const de = doc.documentElement;
      if (de.__ptLocal === 'iframe' || de.__ptLocal === 'frame') out.push(de);
      walk(de, (n) => { if (n.__ptLocal === 'iframe' || n.__ptLocal === 'frame') out.push(n); });
      return out;
    };
    const windowOf = (el) => {
      try { return el.contentWindow || null; } catch (e) { return null; }
    };
    try {
      Object.defineProperty(globalThis, 'length', {
        get: () => frameEls().length,
        enumerable: true, configurable: true,
      });
    } catch (e) {}
    // Indexed window properties: exactly one per frame, as data properties
    // (non-writable, enumerable), not a fixed set of accessors.
    globalThis.__pt_frameAt = (i) => {
      const els = frameEls();
      return i >= 0 && i < els.length ? windowOf(els[i]) : undefined;
    };
    let __slots = 0;
    const __syncSlots = () => {
      const n = frameEls().length;
      for (let i = 0; i < n; i++) {
        try {
          Object.defineProperty(globalThis, String(i), {
            value: globalThis.__pt_frameAt(i),
            writable: false, enumerable: true, configurable: true,
          });
        } catch (e) {}
      }
      for (let i = n; i < __slots; i++) { try { delete globalThis[String(i)]; } catch (e) {} }
      __slots = n;
    };
    globalThis.__pt_syncFrameSlots = __syncSlots;
    __syncSlots();
  }


  // ---- Content Security Policy ---------------------------------------------
  // Document policy from the response header (the engine calls
  // `__pt_applyCsp`) and `<meta http-equiv="content-security-policy">`. Only
  // `script-src` (falling back to `default-src`) is enforced: without
  // 'unsafe-eval' a string in eval/Function/setTimeout throws EvalError with
  // Chrome's text, WebAssembly without 'wasm-unsafe-eval' a CompileError, a
  // blob:/data: worker a SecurityError; an inline script without nonce does
  // not run, and the document gets securitypolicyviolation.
  const __csp = { policies: [] };
  const __cspParse = (text) => {
    const out = {};
    for (const part of __s_split(String(text), ';')) {
      const toks = __s_split(__s_trim(part), /\s+/).filter(Boolean);
      if (!toks.length) continue;
      const name = __s_toLowerCase(toks[0]);
      if (!(name in out)) out[name] = __s_slice(toks, 1);
    }
    return out;
  };
  const __cspScriptDirective = (p) => (p.dirs['script-src'] ? ['script-src', p.dirs['script-src']] : (p.dirs['default-src'] ? ['default-src', p.dirs['default-src']] : null));
  const __cspHas = (list, kw) => list.some((t) => __s_toLowerCase(t) === kw);
  const __cspDirectiveText = (name, list) => name + (list.length ? ' ' + list.join(' ') : '');
  // Line and column of the call site, from the stack's first page frame.
  const __cspSite = () => {
    try {
      const st = __s_split(String(new Error().stack || ''), '\n');
      for (const line of __s_slice(st, 1)) {
        const m = /(https?:[^\s()]+|about:[^\s()]+):(\d+):(\d+)\)?\s*$/.exec(line);
        if (m && !/<anonymous>/.test(line)) return { file: m[1], line: +m[2], column: +m[3] };
      }
    } catch (e) {}
    return { file: '', line: 0, column: 0 };
  };
  // SecurityPolicyViolationEvent with fields from init (the interface stub
  // did not reflect them).
  const __spveState = new WeakMap();
  const __SPVE_FIELDS = [['documentURI', ''], ['referrer', ''], ['blockedURI', ''], ['effectiveDirective', ''], ['violatedDirective', ''], ['originalPolicy', ''], ['sourceFile', ''], ['sample', ''], ['disposition', 'enforce'], ['statusCode', 0], ['lineNumber', 0], ['columnNumber', 0]];
  const __spveEnsure = () => {
    const Ev = globalThis.Event;
    if (!Ev) return null;
    let E = globalThis.SecurityPolicyViolationEvent;
    let ok = false;
    try { const t = new E('x', { blockedURI: 'y' }); ok = t.blockedURI === 'y'; } catch (e) {}
    if (ok) return E;
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const oldProto = E && E.prototype && typeof E.prototype === 'object' ? E.prototype : null;
    const C = function SecurityPolicyViolationEvent(type, init) {
      if (!new.target) throw __pt_mkErr(TypeError, "Failed to construct 'SecurityPolicyViolationEvent': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to construct 'SecurityPolicyViolationEvent': 1 argument required, but only 0 present.");
      const ev = Reflect.construct(Ev, [type, init], new.target);
      const st = {};
      for (const [k, dflt] of __SPVE_FIELDS) { const v = init && init[k]; st[k] = v === undefined ? dflt : (typeof dflt === 'number' ? (Number(v) | 0) : String(v)); }
      __spveState.set(ev, st);
      return ev;
    };
    C.prototype = oldProto || Object.create(Ev.prototype);
    try { Object.setPrototypeOf(C.prototype, Ev.prototype); } catch (e) {}
    try { Object.setPrototypeOf(C, Ev); } catch (e) {}
    try { Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true }); } catch (e) {}
    for (const [k] of __SPVE_FIELDS) {
      try { Object.defineProperty(C.prototype, k, { get: nat(function () { const st = __spveState.get(this); if (!st) throw __pt_mkErr(TypeError, 'Illegal invocation'); return st[k]; }, 'get ' + k), enumerable: true, configurable: true }); } catch (e) {}
    }
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: 'SecurityPolicyViolationEvent', configurable: true }); } catch (e) {}
    try { Object.defineProperty(C, 'length', { value: 1, configurable: true }); } catch (e) {}
    try { Object.defineProperty(globalThis, 'SecurityPolicyViolationEvent', { value: nat(C, 'SecurityPolicyViolationEvent'), writable: true, enumerable: false, configurable: true }); } catch (e) {}
    return C;
  };
  // URL in a violation report: http(s) without credentials and fragment,
  // other schemes (about:srcdoc, blob:) just the scheme, as in Chrome.
  const __cspStripURL = (u) => {
    u = String(u || ''); if (!u) return '';
    if (/^https?:|^wss?:/.test(u)) { try { const x = new URL(u); x.username = ''; x.password = ''; x.hash = ''; return x.href; } catch (e) { return u; } }
    const m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(u); return m ? m[1] : u;
  };
  const __cspViolation = (name, list, blockedURI, sample, extra) => {
    try {
      const E = __spveEnsure();
      const site = extra && extra.noSite ? { file: '', line: 0, column: 0 } : __cspSite();
      const docURL = String((globalThis.location && location.href) || 'about:blank');
      const init = Object.assign({
        documentURI: __cspStripURL(docURL), referrer: String(document.referrer || ''), blockedURI, violatedDirective: name, effectiveDirective: name,
        originalPolicy: __csp.policies.map((p) => p.raw).join(', '), disposition: 'enforce', sourceFile: __cspStripURL(site.file), sample: __s_slice(String(sample || ''), 0, 40), statusCode: /^https?:/.test(docURL) ? 200 : 0, lineNumber: site.line, columnNumber: site.column,
      }, extra || {});
      delete init.noSite;
      const ev = typeof E === 'function' ? new E('securitypolicyviolation', Object.assign({ bubbles: true, composed: true }, init)) : new Event('securitypolicyviolation', { bubbles: true });
      __ptLater(() => { try { document.dispatchEvent(ev); } catch (e) {} }, 0);
    } catch (e) {}
  };
  const __cspEvalMessage = () => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d || __cspHas(d[1], "'unsafe-eval'")) continue;
      // Chrome 151's text, trailing quote included.
      return { name: d[0], list: d[1], msg: "Evaluating a string as JavaScript violates the following Content Security Policy directive because 'unsafe-eval' is not an allowed source of script: " + __cspDirectiveText(d[0], d[1]) + "\".\n" };
    }
    return null;
  };
  // ---- Trusted Types ---------------------------------------------------
  // `require-trusted-types-for 'script'`: a string reaching a code sink (eval,
  // Function, string timer, <script> text, innerHTML, srcdoc, document.write)
  // goes through the default policy; without one it is refused with Chrome's
  // words and a `trusted-types-sink` violation. TT is checked before CSP
  // 'unsafe-eval': with both, Chrome's eval throws the TT error.
  const __ttRequired = () => __csp.policies.some((p) => (p.dirs['require-trusted-types-for'] || []).some((t) => __s_toLowerCase(__s_replace(t, /'/g, '')) === 'script'));
  globalThis.__pt_ttRequired = __ttRequired;
  globalThis.__pt_ttNames = () => { for (const p of __csp.policies) { const l = p.dirs['trusted-types']; if (l) return __s_slice(l); } return null; };
  const __ttViolation = (sink, value) => __cspViolation('require-trusted-types-for', ["'script'"], 'trusted-types-sink', sink + '|' + String(value), {});
  const __TT_MEMBER = { TrustedHTML: 'createHTML', TrustedScript: 'createScript', TrustedScriptURL: 'createScriptURL' };
  // A trusted value is recognised across realms (Chrome checks the wrapper
  // type, not this window's prototype): by its toStringTag brand.
  const __ttIs = (kind, v) => { try { if (!v || typeof v !== 'object') return false; const tt = globalThis.trustedTypes; if (tt && (kind === 'TrustedHTML' ? tt.isHTML(v) : kind === 'TrustedScript' ? tt.isScript(v) : tt.isScriptURL(v))) return true; return Object.prototype.toString.call(v) === '[object ' + kind + ']'; } catch (e) { return false; } };
  // A string fit for a sink: a Trusted object gives its text; without TT the
  // value as is (the sink stringifies); otherwise via the default policy,
  // refused per Chrome's rules.
  globalThis.__pt_ttSink = (kind, sink, value, prefix, strict) => {
    if (__ttIs(kind, value)) return String(value);
    if (!__ttRequired() || __csp.ttSkip) return value;
    const def = typeof globalThis.__pt_ttDefault === 'function' ? __pt_ttDefault() : null;
    const fail = (why) => { __ttViolation(sink, value); return __pt_mkErr(TypeError, prefix + ": This document requires '" + kind + "' assignment" + why + '.'); };
    if (!def) throw fail('');
    const rule = def.rules && def.rules[__TT_MEMBER[kind]];
    if (typeof rule !== 'function') throw fail(" and no 'default' policy for '" + kind + "' has been defined");
    const r = rule.call(undefined, String(value), kind, sink);
    if (r === null || r === undefined) throw fail(" and the 'default' policy failed to execute");
    // The policy result is stringified (a Symbol fails the binding); for eval
    // it must equal the input: there the policy may only allow, not rewrite.
    if (typeof r === 'symbol') throw __pt_mkErr(TypeError, "Failed to execute 'invoke' on '" + __s_replace(__TT_MEMBER[kind], 'create', 'Create') + "Callback': Failed to convert value to 'String'.");
    const out = String(r);
    if (strict && out !== String(value)) throw fail(" and the 'default' policy failed to execute");
    return out;
  };
  // eval / new Function: called from the codegen hook (modify_codegen in
  // pool); returns the code after the default policy, or null (EvalError).
  globalThis.__pt_ttEval = (source) => {
    const src = String(source);
    if (!__ttRequired() || __csp.ttBypass) return src;
    const sink = /^\(function anonymous\(/.test(src) || /^\(async function anonymous\(/.test(src) || /^\(function\* anonymous\(/.test(src) || /^\(async function\* anonymous\(/.test(src) ? 'Function' : 'eval';
    try { return __pt_ttSink('TrustedScript', sink, src, '', true); } catch (e) { return null; }
  };
  const __cspWasmMessage = () => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d || __cspHas(d[1], "'unsafe-eval'") || __cspHas(d[1], "'wasm-unsafe-eval'")) continue;
      return { name: d[0], list: d[1], msg: "Compiling or instantiating WebAssembly module violates the following Content Security policy directive because 'unsafe-eval' is not an allowed source of script in the following Content Security Policy directive: \"" + __cspDirectiveText(d[0], d[1]) + "\"." };
    }
    return null;
  };
  // Whether a script URL is allowed by a source list (ignoring nonce/hash).
  const __cspAllowsUrl = (list, url, nonce, dyn) => {
    const u = String(url || '');
    if (nonce && list.some((t) => __s_toLowerCase(t) === "'nonce-" + __s_toLowerCase(nonce) + "'" || t === "'nonce-" + nonce + "'")) return true;
    if (__cspHas(list, "'strict-dynamic'")) return !!dyn;
    const scheme = (__s_match(u, /^([a-z][a-z0-9+.-]*):/i) || [])[1];
    const self_ = (globalThis.location && location.origin) || '';
    for (const t of list) {
      const low = __s_toLowerCase(t);
      if (low === '*') { if (scheme && !/^(blob|data|filesystem)$/i.test(scheme)) return true; continue; }
      if (low === "'self'") { if (self_ && __s_indexOf(u, self_ + '/') === 0) return true; continue; }
      if (/^[a-z][a-z0-9+.-]*:$/i.test(low)) { if (scheme && low === __s_toLowerCase(scheme) + ':') return true; continue; }
      if (__s_charAt(low, 0) === "'") continue;
      // host-source: compare scheme+host(+port), leading wildcard in host.
      try {
        const hs = __s_indexOf(low, '://') > 0 ? low : ((globalThis.location && location.protocol) || 'https:') + '//' + low;
        const want = new URL(__s_replace(hs, /\*\./g, 'wild.')), got = new URL(u, (globalThis.location && location.href) || undefined);
        if (want.protocol !== got.protocol) continue;
        const wh = want.hostname, gh = got.hostname;
        const okHost = /^\*\./.test(__s_replace(low, /^[a-z]+:\/\//, '')) ? (gh === __s_replace(wh, /^wild\./, '') || __s_endsWith(gh, '.' + __s_replace(wh, /^wild\./, ''))) : gh === wh;
        if (!okHost) continue;
        if (want.port && want.port !== got.port) continue;
        if (want.pathname && want.pathname !== '/' && __s_indexOf(got.pathname, want.pathname) !== 0) continue;
        return true;
      } catch (e) {}
    }
    return false;
  };
  // `'sha256-…'` and friends: the digest of the script's UTF-8 text, base64
  // (Chrome takes the URL-safe alphabet too).
  const __cspDigest = globalThis.__pt_digest;
  const __cspB64 = (u8) => {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    let out = '';
    for (let i = 0; i < u8.length; i += 3) {
      const n = (u8[i] << 16) | ((u8[i + 1] || 0) << 8) | (u8[i + 2] || 0);
      out += A[(n >> 18) & 63] + A[(n >> 12) & 63] + (i + 1 < u8.length ? A[(n >> 6) & 63] : '=') + (i + 2 < u8.length ? A[n & 63] : '=');
    }
    return out;
  };
  const __cspUtf8 = (str) => {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.charCodeAt(i);
      if (c >= 0xd800 && c < 0xdc00 && i + 1 < str.length) {
        const d = str.charCodeAt(i + 1);
        if (d >= 0xdc00 && d < 0xe000) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
        else c = 0xfffd;
      } else if (c >= 0xd800 && c < 0xe000) c = 0xfffd;
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return new Uint8Array(out);
  };
  const __cspHashMatches = (list, code) => {
    if (typeof __cspDigest !== 'function') return false;
    let bytes = null;
    const memo = {};
    for (const t of list) {
      const m = /^'(sha256|sha384|sha512)-([A-Za-z0-9+/_-]+={0,2})'$/i.exec(t);
      if (!m) continue;
      const alg = 'SHA-' + __s_slice(__s_toLowerCase(m[1]), 3);
      if (!(alg in memo)) {
        if (!bytes) bytes = __cspUtf8(String(code));
        const d = __cspDigest(alg, bytes);
        memo[alg] = d ? __s_replace(__cspB64(d), /=+$/, '') : null;
      }
      if (memo[alg] && memo[alg] === __s_replace(__s_replace(__s_replace(m[2], /-/g, '+'), /_/g, '/'), /=+$/, '')) return true;
    }
    return false;
  };
  // Inline script: nonce/hash/'unsafe-inline' (the last is voided by nonce/hash).
  const __cspAllowsInline = (el, dyn) => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const list = d[1];
      if (dyn && __cspHas(list, "'strict-dynamic'")) continue;
      const hasNonceOrHash = list.some((t) => /^'(nonce-|sha(256|384|512)-)/i.test(t));
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (nonce && list.some((t) => t === "'nonce-" + nonce + "'")) continue;
      if (el && hasNonceOrHash && __cspHashMatches(list, el.textContent || '')) continue;
      if (!hasNonceOrHash && __cspHas(list, "'unsafe-inline'")) continue;
      return { name: d[0], list };
    }
    return null;
  };
  const __cspReport = (what) => { try { (globalThis.__pt_parentConsole || console).error(what); } catch (e) {} };
  globalThis.__pt_cspBlocksInline = (el, dyn) => {
    const v = __cspAllowsInline(el, dyn);
    if (!v) return false;
    const text = __cspDirectiveText(v.name, v.list);
    __cspReport("Refused to execute inline script because it violates the following Content Security Policy directive: \"" + text + "\". Either the 'unsafe-inline' keyword, a hash ('sha256-…'), or a nonce ('nonce-...') is required to enable inline execution.\n");
    __cspViolation(v.name, v.list, 'inline', '', { violatedDirective: 'script-src-elem', effectiveDirective: 'script-src-elem', sourceFile: __cspStripURL(String((globalThis.location && location.href) || '')), lineNumber: (typeof __pt_markupLine === 'function' ? __pt_markupLine(String(el.textContent || '')) : 0) || 0, columnNumber: 0, noSite: true });
    return true;
  };
  // Attribute handler (`onclick="…"`): script-src-attr.
  globalThis.__pt_cspBlocksHandler = (el, name, code) => {
    const v = __cspAllowsInline(null);
    if (!v) return false;
    const text = __cspDirectiveText(v.name, v.list);
    __cspReport("Refused to execute inline event handler because it violates the following Content Security Policy directive: \"" + text + "\". Either the 'unsafe-inline' keyword, a hash ('sha256-…'), or a nonce ('nonce-...') is required to enable inline execution.\n");
    __cspViolation(v.name, v.list, 'inline', '', { violatedDirective: 'script-src-attr', effectiveDirective: 'script-src-attr', sourceFile: String((globalThis.location && location.href) || '') });
    return true;
  };
  globalThis.__pt_cspBlocksScriptUrl = (el, url, dyn) => {
    if (!__csp.policies.length) return false;
    // Matched, and reported, as the absolute URL.
    try { url = new URL(String(url), document.baseURI).href; } catch (e) {}
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (__cspAllowsUrl(d[1], url, nonce, dyn)) continue;
      const text = __cspDirectiveText(d[0], d[1]);
      __cspReport("Refused to load the script '" + url + "' because it violates the following Content Security Policy directive: \"" + text + "\". Note that 'script-src-elem' was not explicitly set, so 'script-src' is used as a fallback.\n");
      __cspViolation(d[0], d[1], String(url), '', { violatedDirective: 'script-src-elem', effectiveDirective: 'script-src-elem', sourceFile: '', lineNumber: 0, columnNumber: 0, noSite: true });
      return true;
    }
    return false;
  };
  // Violation from a direct eval/Function: called from the codegen hook
  // (modify_codegen in pool) before the EvalError is thrown.
  try { Object.defineProperty(globalThis, '__pt_cspEvalViolation', { value: () => { const e = __cspEvalMessage(); if (e) __cspViolation(e.name, e.list, 'eval'); }, writable: true, enumerable: false, configurable: true }); } catch (e) {}
  // DevTools evaluation (CDP Runtime.evaluate, callFunctionOn) is not the
  // page's code: Chrome runs it whatever the page's CSP or Trusted Types say.
  // Playwright's evaluate on GitHub got an EvalError instead.
  // The source is a script of its own named '' as Chrome compiles it: its
  // frames read `<anonymous>:1:7` and an eval inside it `eval at f (:1:7)`.
  // Under `eval` every frame named our function ("eval at
  // globalThis.__pt_devEval"). The stack formatter keeps ''-named frames.
  globalThis.__pt_devEval = (src) => {
    const allowed = !globalThis.__pt_cspEval && !globalThis.__pt_ttOn;
    const tt = __csp.ttBypass;
    try { if (typeof globalThis.__pt_setCodegen === 'function') __pt_setCodegen(true); } catch (e) {}
    __csp.ttBypass = true;
    try { return typeof __pt_evalScript === 'function' ? __pt_evalScript(src, '', 0) : (0, eval)(src); }
    finally {
      __csp.ttBypass = tt;
      try { if (typeof globalThis.__pt_setCodegen === 'function') __pt_setCodegen(allowed); } catch (e) {}
    }
  };
  // `Runtime.callFunctionOn`: Chrome compiles `(declaration)` and calls the
  // function itself, so the call leaves no frame of its own.
  const __devApply = Reflect.apply;
  globalThis.__pt_devCall = (decl, self, args) => __devApply(globalThis.__pt_devEval('(' + decl + '\n)'), self, args);
  const __cspWrapEval = () => {
    const ev = __cspEvalMessage();
    const tt = __ttRequired();
    try { Object.defineProperty(globalThis, '__pt_cspEval', { value: ev ? ev.msg : '', writable: true, enumerable: false, configurable: true }); } catch (e) {}
    try { Object.defineProperty(globalThis, '__pt_ttOn', { value: tt, writable: true, enumerable: false, configurable: true }); } catch (e) {}
    try { if (typeof globalThis.__pt_setCodegen === 'function') __pt_setCodegen(!ev && !tt); } catch (e) {}
    if ((!ev && !tt) || __csp.wrapped) return;
    __csp.wrapped = true;
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    // String function constructors: Function and its async/generator kin,
    // including via prototypes' `.constructor`.
    try {
      const evalErr = () => { const e = __cspEvalMessage(); __cspViolation(e.name, e.list, 'eval'); return new EvalError(e.msg); };
      // Under Trusted Types V8 builds the constructor source itself:
      // `(function anonymous(a\n) {\nbody\n})`, and the policy sees that.
      const ttFn = (real, a) => {
        const kind = real.name === 'AsyncGeneratorFunction' ? 'async function*' : real.name === 'GeneratorFunction' ? 'function*' : real.name === 'AsyncFunction' ? 'async function' : 'function';
        const params = a.length > 1 ? __s_slice(a, 0, -1).map(String).join(',') : '';
        const body = a.length ? String(a[a.length - 1]) : '';
        const src = '(' + kind + ' anonymous(' + params + '\n) {\n' + body + '\n})';
        const code = __pt_ttEval(src);
        if (code === null) throw new EvalError("Evaluating a string as JavaScript violates this document's Trusted Type assignment requirements.");
        __csp.ttBypass = true;
        try { return code === src ? real.apply(this, a) : (0, eval)(code); } finally { __csp.ttBypass = false; }
      };
      const seen = [];
      const ctors = [globalThis.Function];
      for (const mk of [() => Object.getPrototypeOf(async function () {}).constructor, () => Object.getPrototypeOf(function* () {}).constructor, () => Object.getPrototypeOf(async function* () {}).constructor]) { try { ctors.push(mk()); } catch (e) {} }
      for (const real of ctors) {
        if (typeof real !== 'function' || __s_includes(seen, real)) continue;
        seen.push(real);
        if (!ev) continue;
        const w = function (...a) { throw evalErr(); };
        w.prototype = real.prototype;
        try { Object.defineProperty(w, 'name', { value: real.name, configurable: true }); Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        const masked = nat(w, real.name);
        try { Object.defineProperty(real.prototype, 'constructor', { value: masked, writable: true, enumerable: false, configurable: true }); } catch (e) {}
        if (real === globalThis.Function) { try { Object.defineProperty(globalThis, 'Function', { value: masked, writable: true, enumerable: false, configurable: true }); } catch (e) {} }
      }
    } catch (e) {}
    // String timers: Chrome returns an id, does not run the string, and
    // reports a violation with blockedURI 'eval'.
    for (const name of ['setTimeout', 'setInterval']) {
      try {
        const real = globalThis[name]; if (typeof real !== 'function') continue;
        const w = ({ [name](handler, ...rest) { if (typeof handler !== 'function') { handler = __pt_ttSink('TrustedScript', 'Window ' + name, handler, "Failed to execute '" + name + "' on 'Window'"); const e = __cspEvalMessage(); if (e) { __cspViolation(e.name, e.list, 'eval'); return 0; } } return real.call(this, handler, ...rest); } })[name];
        try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, name, { value: nat(w, name), writable: true, enumerable: true, configurable: true });
      } catch (e) {}
    }
    // WebAssembly: compile and instantiate.
    if (ev) try {
      const W = globalThis.WebAssembly;
      if (W) {
        const CE = W.CompileError || Error;
        const wasmErr = (k) => { const m = __cspWasmMessage(); if (!m) return null; __cspViolation(m.name, m.list, 'wasm-eval'); return new CE('WebAssembly.' + k + '(): ' + m.msg); };
        for (const k of ['compile', 'instantiate', 'compileStreaming', 'instantiateStreaming']) {
          const real = W[k]; if (typeof real !== 'function') continue;
          const w = ({ [k](...a) { const e = wasmErr(k); if (e) return Promise.reject(e); return real.apply(this, a); } })[k];
          try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
          Object.defineProperty(W, k, { value: nat(w, k), writable: true, enumerable: false, configurable: true });
        }
        for (const k of ['Module', 'Instance']) {
          const real = W[k]; if (typeof real !== 'function') continue;
          const w = function (...a) { if (!new.target) throw __pt_mkErr(TypeError, "WebAssembly." + k + " must be invoked with 'new'"); const e = wasmErr(k); if (e) throw e; return Reflect.construct(real, a, new.target); };
          w.prototype = real.prototype;
          for (const sk of Object.getOwnPropertyNames(real)) { if (__s_includes(['length', 'name', 'prototype'], sk)) continue; try { Object.defineProperty(w, sk, Object.getOwnPropertyDescriptor(real, sk)); } catch (e) {} }
          try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
          Object.defineProperty(W, k, { value: nat(w, k), writable: true, enumerable: false, configurable: true });
        }
      }
    } catch (e) {}
    // Workers: script URL against script-src (blob:/data: only if listed).
    for (const name of ['Worker', 'SharedWorker']) {
      try {
        const real = globalThis[name]; if (typeof real !== 'function') continue;
        const w = function (url, opts) {
          if (!new.target) throw __pt_mkErr(TypeError, "Failed to construct '" + name + "': Please use the 'new' operator, this DOM object constructor cannot be called as a function.");
          const u = String(url);
          // Origin before policy: a foreign blob URL is a SecurityError.
          if (__s_slice(u, 0, 5) === 'blob:') {
            let o = 'null'; try { o = new URL(u).origin; } catch (e) {}
            const mine = (globalThis.location && location.origin) || 'null';
            if (o === 'null' || o !== mine) throw __pt_mkErr(globalThis.DOMException || Error, "Failed to construct '" + name + "': Script at '" + u + "' cannot be accessed from origin '" + mine + "'.", 'SecurityError');
          }
          for (const p of __csp.policies) {
            // For workers: worker-src, else child-src, else script-src/default-src.
            const d = p.dirs['worker-src'] ? ['worker-src', p.dirs['worker-src']] : (p.dirs['child-src'] ? ['child-src', p.dirs['child-src']] : __cspScriptDirective(p));
            if (!d) continue;
            if (__cspAllowsUrl(d[1], u, '')) continue;
            const text = __cspDirectiveText(d[0], d[1]);
            __cspReport("Refused to create a worker from '" + u + "' because it violates the following Content Security Policy directive: \"" + text + "\"." + (d[0] === 'worker-src' ? '\n' : " Note that 'worker-src' was not explicitly set, so '" + d[0] + "' is used as a fallback.\n"));
            const scheme = (__s_match(u, /^([a-z][a-z0-9+.-]*):/i) || [])[1];
            __cspViolation(d[0], d[1], /^(blob|data|filesystem)$/i.test(scheme || '') ? __s_toLowerCase(scheme) : u, '', { violatedDirective: 'worker-src', effectiveDirective: 'worker-src' });
            // Chrome returns an object but does not load the script; the
            // worker gets an error event.
            const dead = Reflect.construct(real, ['data:text/javascript,', opts], new.target);
            try { dead.terminate(); } catch (e) {}
            __ptLater(() => { try { dead.dispatchEvent(new ErrorEvent('error', { message: 'Failed to load worker script' })); } catch (e) {} }, 0);
            return dead;
          }
          return Reflect.construct(real, [url, opts], new.target);
        };
        w.prototype = real.prototype;
        try { Object.defineProperty(w, 'length', { value: real.length, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, name, { value: nat(w, name), writable: true, enumerable: false, configurable: true });
      } catch (e) {}
    }
  };
  globalThis.__pt_applyCsp = (text, source) => {
    const raw = __s_trim(String(text == null ? '' : text));
    if (!raw) return;
    for (const one of __s_split(raw, ',')) {
      const t = __s_trim(one);
      if (!t) continue;
      __csp.policies.push({ raw: t, dirs: __cspParse(t), source: source || 'meta' });
      if ((source || 'meta') === 'header') __csp.headerDelivered = true;
    }
    // The header arrives after the tree is installed: hide the nonces already
    // in it (Facebook's loader compares the attribute with the property).
    if (__csp.headerDelivered && globalThis.document && document.documentElement) {
      __walkTree(document.documentElement, (n) => { try { if (n && n.__ptType === ELEMENT_NODE && typeof n.__ptHideNonce === 'function') n.__ptHideNonce(); } catch (e) {} });
    }
    __cspWrapEval();
  };
  globalThis.__pt_cspActive = () => __csp.policies.length > 0;
  // Document meta policy: applied as soon as the markup is parsed.
  globalThis.__pt_cspFromMeta = (root) => {
    try {
      if (__csp.headerDelivered) __walkTree(root, (n) => { try { if (n && n.__ptType === ELEMENT_NODE && typeof n.__ptHideNonce === 'function') n.__ptHideNonce(); } catch (e) {} });
      const metas = [];
      __walkTree(root, (n) => { if (n && n.__ptType === ELEMENT_NODE && __s_toLowerCase(String(n.__ptLocal || '')) === 'meta' && __s_toLowerCase(String(__ptGetA(n, 'http-equiv') || '')) === 'content-security-policy') metas.push(n); });
      for (const m of metas) { const c = __ptGetA(m, 'content'); if (c) __pt_applyCsp(c, 'meta'); }
    } catch (e) {}
  };
  // The markup line a text starts at, for stack and CSP line numbers (Chrome
  // counts from the start of the document).
  globalThis.__pt_markupLine = (text) => {
    try {
      const m = document.__ptMarkup; if (typeof m !== 'string' || !text) return 0;
      const i = __s_indexOf(m, text); if (i < 0) return 0;
      let n = 1; for (let k = 0; k < i; k++) if (__s_charCodeAt(m, k) === 10) n++;
      return n;
    } catch (e) { return 0; }
  };
  globalThis.__pt_writeDocument = (html) => {
    try { Object.defineProperty(document, '__ptMarkup', { value: String(html == null ? '' : html), configurable: true, writable: true }); } catch (e) {}
    // Parsed whole, into a detached document first: the policy is read
    // before the tree is attached (scripts run on attach).
    const scratch = new Document();
    const root = __parseDocumentInto(scratch, html == null ? '' : html, true);
    if (root) __pt_cspFromMeta(root);
    __formSeq++;
    document.__ptKids = [];
    document.__ptDocEl = null;
    document.__ptDoctype = null;
    document.__ptMode = scratch.__ptMode;
    for (const n of __s_slice(scratch.__ptKids)) {
      if (n.__ptType === 10) { n.__ptParent = document; n.__ptDoc = document; document.__ptKids.push(n); document.__ptDoctype = n; continue; }
      __ptDrop.call(scratch, n);
      __ptAdd.call(document, n);
      if (n.__ptType === ELEMENT_NODE) document.__ptDocEl = n;
    }
    document.__ptReady = 'complete';
    // Markup scripts run here and now, in this window.
    if (root) for (const el of __tags(root, 'script')) {
      try { el.__ptRunScript(); } catch (e) {}
    }
    return document;
  };

  globalThis.__pt_installDocument = (tree, dt, markup, mode, before, after) => {
    if (typeof markup === 'string') { try { Object.defineProperty(document, '__ptMarkup', { value: markup, configurable: true, writable: true }); } catch (e) {} }
    __formSeq++;
    document.__ptKids = [];
    document.__ptDocEl = null;
    document.__ptCurScript = null;
    // `<!DOCTYPE html>` is a node, the document's first child, not a flag.
    document.__ptDoctype = null;
    // `Object.prototype.toString.call(doctype)` must be `[object DocumentType]`.
    try {
      if (globalThis.DocumentType && !Object.getOwnPropertyDescriptor(DocumentType.prototype, Symbol.toStringTag)) {
        Object.defineProperty(DocumentType.prototype, Symbol.toStringTag, { value: 'DocumentType', configurable: true });
      }
    } catch (e) {}
    // The document's children around the root: the doctype where it stood,
    // comments, processing instructions.
    const place = (n) => {
      if (n.__ptType === 10) {
        n.__ptParent = document;
        document.__ptKids.push(n);
        document.__ptDoctype = n;
      } else __ptAdd.call(document, n);
    };
    if (Array.isArray(before)) for (const n of __buildSpecs(document, before, null, false)) place(n);
    else if (dt) place(__makeDoctype(document, dt.name || 'html', dt.publicId, dt.systemId));
    document.__ptMode = typeof mode === 'string' ? mode : null;
    if (tree && tree.k === 'e') {
      const html = buildNode(document, tree);
      __pt_cspFromMeta(html);
      document.appendChild(html);
      document.__ptDocEl = html;
    }
    if (Array.isArray(after)) for (const n of __buildSpecs(document, after, null, false)) place(n);
    scriptNodes = __docTags(document, 'script');
    // While the document's own scripts run, readyState is 'loading'; code
    // branches on it ("not loading: start now, else wait for DOMContentLoaded").
    document.__ptReady = 'loading';
  };

  // The loader brackets each page script with these so `document.currentScript`
  // (and therefore document.write's insertion point) is correct while it runs.
  // The index matches the loader's document-order script list.
  // A document script is a task; over 50 ms it gets a long-animation-frame entry.
  let __ptScriptT0 = 0;
  globalThis.__pt_beginScript = (i) => { document.__ptCurScript = scriptNodes[i] || null; try { __ptScriptT0 = performance.now(); } catch (e) {} };
  // Whether a document script is blocked by CSP (inline without nonce, foreign URL).
  globalThis.__pt_cspScriptBlocked = (i) => {
    try {
      if (!__pt_cspActive()) return false;
      const el = scriptNodes[i]; if (!el) return false;
      const src = __ptGetA(el, 'src');
      if (src) { let abs = String(src); try { abs = new URL(src, document.baseURI || (globalThis.location && location.href) || undefined).href; } catch (e) {} return __pt_cspBlocksScriptUrl(el, abs); }
      return __pt_cspBlocksInline(el);
    } catch (e) { return false; }
  };
  globalThis.__pt_endScript = () => {
    const el = document.__ptCurScript;
    document.__ptCurScript = null;
    try {
      const dt = performance.now() - __ptScriptT0;
      if (dt > 50 && typeof globalThis.__pt_noteLoaf === 'function') {
        let src = el ? __ptGetA(el, 'src') : null;
        try { if (src) src = new URL(src, document.baseURI || location.href).href; } catch (e) {}
        const url = src || String(location.href || '');
        __pt_noteLoaf(__ptScriptT0, dt, url, 'classic-script', null, url);
      }
    } catch (e) {}
  };

  // Called after all page scripts have run: fire DOMContentLoaded then load.
  // Parsing is done: deferred scripts run next and see `interactive`.
  // Navigation marks (domInteractive, DOMContentLoaded, load) are taken when
  // each event really happens; Chrome's navigation timing includes document
  // parsing and its scripts.
  const __ptMark = (n) => { try { globalThis.__pt_markNav && __pt_markNav(n); } catch (e) {} };
  globalThis.__pt_parseDone = () => {
    if (document.__ptReady !== 'loading') return;
    __ptMark('interactive');
    document.__ptReady = 'interactive';
    try { document.dispatchEvent(__ptTrust(new Event('readystatechange'))); } catch (e) {}
  };
  // In steps, resumable: a listener the engine stops for running too long
  // ends only its own step, and the engine calls again for the rest (the
  // page still gets `load`, as in Chrome).
  // `upto` stops after that many steps: the engine holds `load` while the
  // loads it waits for are still coming.
  globalThis.__pt_finishLoad = (resume, upto) => {
    const steps = [__finishDcl, __finishLoadEvent, __finishPageshow];
    const end = upto === undefined ? steps.length : Math.min(upto, steps.length);
    for (let i = resume ? document.__ptFinishAt | 0 : 0; i < end; i++) {
      document.__ptFinishAt = i + 1;
      steps[i]();
    }
  };
  // readyState changes are visible: Chrome fires `readystatechange` at each
  // step.
  const __setReadyState = (v) => {
    document.__ptReady = v;
    try { document.dispatchEvent(__ptTrust(new Event('readystatechange'))); } catch (e) {}
  };
  const __finishDcl = () => {
    const setReadyState = __setReadyState;
    // Parsing may have finished earlier, before deferred scripts.
    if (document.__ptReady === 'loading') { __ptMark('interactive'); setReadyState('interactive'); }
    __ptMark('dclStart');
    // Lifecycle events come from the browser: `e.isTrusted` is true, and
    // pages check it first.
    const dcl = __ptTrust(new Event('DOMContentLoaded', { bubbles: true }));
    // It bubbles from the document to the window, where it is most often
    // listened for (Turnstile's api.js), once.
    document.dispatchEvent(dcl);
    __ptMark('dclEnd');
  };
  const __finishLoadEvent = () => {
    __ptMark('complete');
    __setReadyState('complete');
    __ptMark('loadStart');
    const load = __ptTrust(new Event('load'));
    globalThis.dispatchEvent && globalThis.dispatchEvent(load);
    // In Chrome `load` reaches the document and the body too.
    try { document.dispatchEvent(__ptTrust(new Event('load'))); } catch (e) {}
    __ptMark('loadEnd');
  };
  const __finishPageshow = () => {
    // `pageshow` follows `load`, with `persisted: false` on a normal load.
    try {
      const ps = __ptTrust(new Event('pageshow'));
      try { Object.defineProperty(ps, 'persisted', { value: false, enumerable: true, configurable: true }); }
      catch (e) {}
      globalThis.dispatchEvent && globalThis.dispatchEvent(ps);
    } catch (e) {}
  };

  // window is an EventTarget too. The window always needs its listener table:
  // with the V8 template chain it inherits from EventTarget.prototype at once,
  // and the branch below does not run.
  if (!Object.prototype.hasOwnProperty.call(globalThis, '__ptLis')) {
    try { Object.defineProperty(globalThis, '__ptLis', { value: Object.create(null), enumerable: false, writable: true, configurable: true }); } catch (e) {}
  }
  if (!globalThis.addEventListener) {
    globalThis.__ptLis = Object.create(null);
    globalThis.addEventListener = Node.prototype.addEventListener.bind(globalThis);
    globalThis.removeEventListener = Node.prototype.removeEventListener.bind(globalThis);
    globalThis.dispatchEvent = (ev) => {
      const l = globalThis.__ptLis[ev.type]; if (l) for (const { fn } of __s_slice(l)) { try { fn.call(globalThis, ev); } catch (_) {} }
      return true;
    };
  }

  // ---- Constraint validation ---------------------------------------------
  // `input.validity` was undefined, and form code that reads `.valid` threw
  // (fingerprint.com's signup form took the page down with it). One reckoning
  // of a control's state serves the API and the `:valid`/`:invalid` selectors.
  // Messages are Chrome's.
  const __customValidity = new WeakMap();
  const __validityObj = new WeakMap();
  const __candidate = (e) => {
    const t = e.__ptLocal;
    if (t === 'input') {
      const ty = __inputType(e);
      if (/^(hidden|reset|button)$/.test(ty)) return false;
      if (__ptHasA(e, 'readonly') && !/^(checkbox|radio|file|range|color|submit|image)$/.test(ty)) return false;
    } else if (t === 'textarea') {
      if (__ptHasA(e, 'readonly')) return false;
    } else if (t === 'button') {
      const ty = __s_toLowerCase(String(__ptGetA(e, 'type') || 'submit'));
      if (ty !== 'submit') return false;
    } else if (t !== 'select') return false;
    if (__isDisabled(e)) return false;
    for (let p = __parentEl(e); p; p = __parentEl(p)) if (p.__ptLocal === 'datalist') return false;
    return true;
  };
  const __EMAIL_LOCAL = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/;
  const __EMAIL_DOMAIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
  const __emailProblem = (v) => {
    const at = __s_indexOf(v, '@');
    if (at < 0) return "Please include an '@' in the email address. '" + v + "' is missing an '@'.";
    const local = __s_slice(v, 0, at), domain = __s_slice(v, at + 1);
    if (!local) return "Please enter a part followed by '@'. '" + v + "' is incomplete.";
    if (!domain) return "Please enter a part following '@'. '" + v + "' is incomplete.";
    if (!__EMAIL_LOCAL.test(local)) { const bad = local.match(/[^A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]/); return "A part followed by '@' should not contain the symbol '" + (bad ? bad[0] : '') + "'."; }
    if (__s_indexOf(domain, '@') >= 0) return "A part following '@' should not contain the symbol '@'.";
    if (!__EMAIL_DOMAIN.test(domain)) {
      const bad = domain.match(/[^A-Za-z0-9.-]/);
      if (bad) return "A part following '@' should not contain the symbol '" + bad[0] + "'.";
      return "'.' is used at a wrong position in '" + domain + "'.";
    }
    return '';
  };
  const __numberOf = (e, v) => { const n = Number(v); return v !== '' && Number.isFinite(n) ? n : null; };
  const __radioGroupChecked = (e) => {
    const name = __ptGetA(e, 'name');
    if (!name) return e.checked;
    const root = e.form || (e.getRootNode ? e.getRootNode() : document);
    let found = false;
    try { walk(root, (k) => { if (!found && k.__ptLocal === 'input' && __inputType(k) === 'radio' && __ptGetA(k, 'name') === name && k.checked) found = true; }); } catch (x) {}
    return found;
  };
  const __validity = (e) => {
    const out = { valueMissing: false, typeMismatch: false, patternMismatch: false, tooLong: false, tooShort: false,
      rangeUnderflow: false, rangeOverflow: false, stepMismatch: false, badInput: false, customError: false, valid: true, message: '' };
    const custom = __customValidity.get(e) || '';
    if (custom) { out.customError = true; }
    if (!__candidate(e)) { out.valid = !out.customError; out.message = ''; return out; }
    const t = e.__ptLocal;
    const ty = t === 'input' ? __inputType(e) : t;
    const v = t === 'button' ? '' : __valueOf(e);
    if (__ptHasA(e, 'required') && t !== 'button') {
      if (ty === 'checkbox') { if (!e.checked) { out.valueMissing = true; out.message = 'Please check this box if you want to proceed.'; } }
      else if (ty === 'radio') { if (!__radioGroupChecked(e)) { out.valueMissing = true; out.message = 'Please select one of these options.'; } }
      else if (ty === 'file') { if (!e.files || !e.files.length) { out.valueMissing = true; out.message = 'Please select a file.'; } }
      else if (t === 'select') { if (v === '') { out.valueMissing = true; out.message = 'Please select an item in the list.'; } }
      else if (v === '') { out.valueMissing = true; out.message = 'Please fill out this field.'; }
    }
    if (!out.valueMissing && v !== '' && t === 'input') {
      if (ty === 'email') {
        const parts = __ptHasA(e, 'multiple') ? __s_split(v, ',').map((x) => __s_trim(x)) : [v];
        for (const one of parts) { const m = __emailProblem(one); if (m) { out.typeMismatch = true; out.message = m; break; } }
      } else if (ty === 'url') {
        try { new URL(v); } catch (x) { out.typeMismatch = true; out.message = 'Please enter a URL.'; }
      }
      const pat = __ptGetA(e, 'pattern');
      if (!out.typeMismatch && pat !== null && /^(text|search|url|tel|email|password)$/.test(ty)) {
        let re = null;
        try { re = new RegExp('^(?:' + pat + ')$', 'v'); } catch (x) { try { re = new RegExp('^(?:' + pat + ')$', 'u'); } catch (y) { re = null; } }
        if (re && !re.test(v)) { out.patternMismatch = true; out.message = 'Please match the requested format.'; }
      }
      if (ty === 'number' || ty === 'range') {
        const n = __numberOf(e, v);
        const min = __numberOf(e, __ptGetA(e, 'min') || ''), max = __numberOf(e, __ptGetA(e, 'max') || '');
        if (n !== null) {
          if (min !== null && n < min) { out.rangeUnderflow = true; out.message = 'Value must be greater than or equal to ' + min + '.'; }
          else if (max !== null && n > max) { out.rangeOverflow = true; out.message = 'Value must be less than or equal to ' + max + '.'; }
          else {
            const stepA = __ptGetA(e, 'step');
            const step = stepA === null ? 1 : __s_toLowerCase(stepA) === 'any' ? 0 : Number(stepA) > 0 ? Number(stepA) : 1;
            const base = min !== null ? min : 0;
            if (step) {
              const k = (n - base) / step;
              if (Math.abs(k - Math.round(k)) > 1e-9) {
                out.stepMismatch = true;
                const lo = base + Math.floor(k) * step, hi = lo + step;
                const fmt = (x) => String(Math.round(x * 1e9) / 1e9);
                out.message = max !== null && hi > max ? 'Please enter a valid value. The nearest valid value is ' + fmt(lo) + '.'
                  : 'Please enter a valid value. The two nearest valid values are ' + fmt(lo) + ' and ' + fmt(hi) + '.';
              }
            }
          }
        }
      }
    }
    if (out.customError) out.message = custom;
    out.valid = !(out.valueMissing || out.typeMismatch || out.patternMismatch || out.tooLong || out.tooShort
      || out.rangeUnderflow || out.rangeOverflow || out.stepMismatch || out.badInput || out.customError);
    if (out.valid) out.message = '';
    return out;
  };
  globalThis.ValidityState = class ValidityState {
    constructor() { throw __pt_mkErr(TypeError, "Failed to construct 'ValidityState': Illegal constructor"); }
  };
  for (const k of ['valueMissing', 'typeMismatch', 'patternMismatch', 'tooLong', 'tooShort', 'rangeUnderflow', 'rangeOverflow', 'stepMismatch', 'badInput', 'customError', 'valid']) {
    Object.defineProperty(globalThis.ValidityState.prototype, k, { get: Object.getOwnPropertyDescriptor({ get [k]() {
      const el = __validityObj.get(this);
      if (!el) throw __pt_mkErr(TypeError, 'Illegal invocation');
      return __validity(el)[k];
    } }, k).get, enumerable: true, configurable: true });
  }
  const __fireInvalid = (e) => { const ev = new Event('invalid', { cancelable: true }); __ptTrust(ev); e.dispatchEvent(ev); };
  const __controlsOf = (form) => {
    const out = [];
    walk(form, (k) => { if (k !== form && /^(input|select|textarea|button|fieldset|output|object)$/.test(k.__ptLocal)) out.push(k); });
    return out;
  };
  const __vMethods = {
    get validity() {
      let v = null;
      v = this.__ptValidity;
      if (!v) { v = Object.create(globalThis.ValidityState.prototype); __validityObj.set(v, this); try { Object.defineProperty(this, '__ptValidity', { value: v, enumerable: false }); } catch (x) {} }
      return v;
    },
    get validationMessage() { return __validity(this).message; },
    get willValidate() { return __candidate(this); },
    checkValidity() { const r = __validity(this); if (__candidate(this) && !r.valid) { __fireInvalid(this); return false; } return true; },
    reportValidity() { const r = __validity(this); if (__candidate(this) && !r.valid) { __fireInvalid(this); return false; } return true; },
    setCustomValidity(m) { if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'setCustomValidity' on '" + (this.constructor && this.constructor.name) + "': 1 argument required, but only 0 present."); __customValidity.set(this, String(m)); __markDirty(this); },
  };
  for (const name of ['HTMLInputElement', 'HTMLTextAreaElement', 'HTMLSelectElement', 'HTMLButtonElement', 'HTMLFieldSetElement', 'HTMLOutputElement', 'HTMLObjectElement']) {
    const C = globalThis[name];
    if (typeof C !== 'function' || !C.prototype) continue;
    for (const k of Object.getOwnPropertyNames(__vMethods)) {
      const d = Object.getOwnPropertyDescriptor(__vMethods, k);
      const nd = d.get ? { get: d.get, enumerable: true, configurable: true } : { value: d.value, writable: true, enumerable: true, configurable: true };
      try { Object.defineProperty(C.prototype, k, nd); } catch (x) {}
    }
  }
  if (typeof globalThis.HTMLFormElement === 'function') {
    const F = globalThis.HTMLFormElement.prototype;
    const all = (form, report) => { let ok = true; for (const c of __controlsOf(form)) { if (__candidate(c) && !__validity(c).valid) { ok = false; __fireInvalid(c); } } return ok; };
    Object.defineProperty(F, 'checkValidity', { value: { checkValidity() { return all(this, false); } }.checkValidity, writable: true, enumerable: true, configurable: true });
    Object.defineProperty(F, 'reportValidity', { value: { reportValidity() { return all(this, true); } }.reportValidity, writable: true, enumerable: true, configurable: true });
  }

  // ---- Web Animations ------------------------------------------------------
  // `element.animate()` returned undefined, and animation code that sets
  // `animation.startTime` threw inside requestAnimationFrame (fingerprint.com
  // lost its page to it). Nothing is painted here: an animation keeps its time
  // against `document.timeline` and finishes on a timer, as in a browser.
  const __ANIM = new WeakMap();
  const __animLive = new Set();
  const __animNow = () => { try { return document.timeline.currentTime; } catch (e) { return performance.now(); } };
  const __timingOf = (o) => {
    const t = { delay: 0, direction: 'normal', duration: 'auto', easing: 'linear', endDelay: 0, fill: 'auto', iterationStart: 0, iterations: 1 };
    if (typeof o === 'number') { t.duration = o; return t; }
    if (o && typeof o === 'object') {
      for (const k of ['delay', 'endDelay', 'iterationStart', 'iterations']) if (o[k] !== undefined) t[k] = Number(o[k]);
      for (const k of ['direction', 'easing', 'fill']) if (o[k] !== undefined) t[k] = String(o[k]);
      if (o.duration !== undefined) t.duration = typeof o.duration === 'number' ? o.duration : String(o.duration) === 'auto' ? 'auto' : Number(o.duration);
    }
    if (t.duration !== 'auto' && (Number.isNaN(t.duration) || t.duration < 0)) throw __pt_mkErr(TypeError, "Failed to execute 'animate' on 'Element': duration must be non-negative or auto.");
    return t;
  };
  const __animFrames = (kf) => {
    if (kf === null || kf === undefined) return [];
    let list = kf;
    if (!Array.isArray(kf)) {
      // Property-indexed form: { opacity: [0, 1] }.
      const keys = Object.keys(kf).filter((k) => k !== 'offset' && k !== 'easing' && k !== 'composite');
      const n = Math.max(1, ...keys.map((k) => (Array.isArray(kf[k]) ? kf[k].length : 1)));
      list = [];
      for (let i = 0; i < n; i++) {
        const f = {};
        for (const k of keys) { const v = kf[k]; f[k] = Array.isArray(v) ? v[i] : v; }
        list.push(f);
      }
    }
    const n = list.length;
    return list.map((f, i) => {
      const o = { offset: f.offset === undefined ? null : Number(f.offset), easing: f.easing === undefined ? 'linear' : String(f.easing), composite: f.composite === undefined ? 'auto' : String(f.composite) };
      for (const k of Object.keys(f)) if (k !== 'offset' && k !== 'easing' && k !== 'composite') o[k] = String(f[k]);
      o.computedOffset = o.offset !== null ? o.offset : n === 1 ? 1 : i / (n - 1);
      return o;
    });
  };
  const __animFx = (o) => { const st = o !== null && typeof o === 'object' ? __ANIM.get(o) : undefined; if (!st || st.kind !== 'effect') throw __pt_mkErr(TypeError, 'Illegal invocation'); return st; };
  const __animOf = (o) => { const st = o !== null && typeof o === 'object' ? __ANIM.get(o) : undefined; if (!st || st.kind !== 'anim') throw __pt_mkErr(TypeError, 'Illegal invocation'); return st; };
  const __endTime = (eff) => {
    if (!eff) return 0;
    const t = __ANIM.get(eff).timing;
    const d = t.duration === 'auto' ? 0 : t.duration;
    return Math.max(0, t.delay + d * t.iterations + t.endDelay);
  };
  if (typeof globalThis.AnimationEffect !== 'function' || !globalThis.AnimationEffect.prototype.getTiming) {
    globalThis.AnimationEffect = class AnimationEffect {
      constructor() { throw __pt_mkErr(TypeError, "Failed to construct 'AnimationEffect': Illegal constructor"); }
      getTiming() { return Object.assign({}, __animFx(this).timing); }
      getComputedTiming() {
        const st = __animFx(this), t = st.timing;
        const d = t.duration === 'auto' ? 0 : t.duration;
        const active = d * t.iterations;
        const anim = st.animation ? __ANIM.get(st.animation) : null;
        const local = anim ? __animCurrent(anim) : null;
        let progress = null, iter = null;
        if (local !== null && local >= t.delay && local < t.delay + active) { const x = d ? (local - t.delay) / d : 0; iter = Math.floor(x); progress = x - iter; }
        return Object.assign({}, t, { duration: d, activeDuration: active, endTime: __endTime(this), localTime: local, progress, currentIteration: iter });
      }
      updateTiming() { const st = __animFx(this); const next = Object.assign({}, st.timing, arguments[0] || {}); st.timing = __timingOf(next); }
    };
  }
  globalThis.KeyframeEffect = class KeyframeEffect extends globalThis.AnimationEffect {
    constructor(target, keyframes, options) {
      if (arguments.length < 2) throw __pt_mkErr(TypeError, "Failed to construct 'KeyframeEffect': 2 arguments required, but only " + arguments.length + ' present.');
      const self = Object.create(new.target.prototype);
      if (target instanceof globalThis.KeyframeEffect) {
        const src = __ANIM.get(target);
        __ANIM.set(self, { kind: 'effect', target: src.target, frames: src.frames.slice(), timing: Object.assign({}, src.timing), composite: src.composite, pseudo: src.pseudo, animation: null });
        return self;
      }
      __ANIM.set(self, { kind: 'effect', target: target || null, frames: __animFrames(keyframes), timing: __timingOf(options), composite: (options && options.composite) || 'replace', pseudo: (options && options.pseudoElement) || null, animation: null });
      return self;
    }
    get target() { return __animFx(this).target; }
    set target(v) { __animFx(this).target = v || null; }
    get pseudoElement() { return __animFx(this).pseudo; }
    set pseudoElement(v) { __animFx(this).pseudo = v == null ? null : String(v); }
    get composite() { return __animFx(this).composite; }
    set composite(v) { __animFx(this).composite = String(v); }
    getKeyframes() { return __animFx(this).frames.map((f) => Object.assign({}, f)); }
    setKeyframes(kf) { __animFx(this).frames = __animFrames(kf); }
  };
  const __animCurrent = (st) => {
    if (st.hold !== null) return st.hold;
    if (st.start === null) return null;
    return (__animNow() - st.start) * st.rate;
  };
  const __animState = (st) => {
    const cur = __animCurrent(st);
    if (cur === null && !st.pendingPlay) return 'idle';
    if (st.paused) return 'paused';
    const end = __endTime(st.effect);
    if (cur !== null && ((st.rate > 0 && cur >= end) || (st.rate < 0 && cur <= 0))) return 'finished';
    return 'running';
  };
  const __animFire = (anim, type) => {
    const st = __ANIM.get(anim);
    let ev;
    try {
      ev = typeof globalThis.AnimationPlaybackEvent === 'function'
        ? new globalThis.AnimationPlaybackEvent(type, { currentTime: __animCurrent(st), timelineTime: __animNow() })
        : new Event(type);
    } catch (e) { ev = new Event(type); }
    __ptTrust(ev);
    try { globalThis.EventTarget.prototype.dispatchEvent.call(anim, ev); } catch (e) {}
  };
  const __newDeferred = (st, key) => {
    const d = {};
    d.promise = new Promise((res, rej) => { d.resolve = res; d.reject = rej; });
    d.promise.then(undefined, () => {});
    st[key] = d;
    return d;
  };
  const __scheduleFinish = (anim) => {
    const st = __ANIM.get(anim);
    if (st.timer) { clearTimeout(st.timer); st.timer = null; }
    if (st.paused || st.start === null || st.rate === 0) return;
    const cur = __animCurrent(st), end = __endTime(st.effect);
    const left = st.rate > 0 ? (end - cur) / st.rate : cur / -st.rate;
    const done = () => {
      st.timer = null;
      if (__animState(st) !== 'finished' || st.finishedFired) return;
      st.finishedFired = true;
      __animLive.delete(anim);
      st.finished.resolve(anim);
      __animFire(anim, 'finish');
    };
    if (left <= 0) Promise.resolve().then(done);
    else st.timer = setTimeout(done, left);
  };
  const __play = (anim) => {
    const st = __ANIM.get(anim);
    const end = __endTime(st.effect);
    const cur = __animCurrent(st);
    if (st.rate > 0 && (cur === null || cur < 0 || cur >= end)) st.hold = 0;
    else if (st.rate < 0 && (cur === null || cur <= 0 || cur > end)) st.hold = end;
    else if (st.hold === null) st.hold = cur;
    if (st.finishedFired) { st.finishedFired = false; __newDeferred(st, 'finished'); }
    st.paused = false;
    st.pendingPlay = true;
    st.start = null;
    __animLive.add(anim);
    if (st.ready.settled) __newDeferred(st, 'ready');
    // A pending play starts on the next frame, with the timeline's time.
    requestAnimationFrame(() => {
      if (!st.pendingPlay) return;
      st.pendingPlay = false;
      st.start = __animNow() - (st.hold || 0) / st.rate;
      st.hold = null;
      st.ready.settled = true;
      st.ready.resolve(anim);
      __scheduleFinish(anim);
    });
  };
  globalThis.Animation = class Animation {
    constructor(effect, timeline) {
      const self = Object.create(new.target.prototype);
      const st = { kind: 'anim', effect: effect || null, timeline: timeline === undefined ? document.timeline : timeline, start: null, hold: null, rate: 1,
        paused: false, pendingPlay: false, finishedFired: false, timer: null, id: '', onfinish: null, oncancel: null, onremove: null };
      __newDeferred(st, 'ready'); st.ready.settled = true; st.ready.resolve(self);
      __newDeferred(st, 'finished');
      __ANIM.set(self, st);
      if (effect && __ANIM.get(effect)) __ANIM.get(effect).animation = self;
      return self;
    }
    get id() { return __animOf(this).id; }
    set id(v) { __animOf(this).id = String(v); }
    get effect() { return __animOf(this).effect; }
    set effect(v) { const st = __animOf(this); st.effect = v || null; if (v && __ANIM.get(v)) __ANIM.get(v).animation = this; }
    get timeline() { return __animOf(this).timeline; }
    set timeline(v) { __animOf(this).timeline = v; }
    get startTime() { return __animOf(this).start; }
    set startTime(v) {
      const st = __animOf(this);
      if (v === null) { st.hold = __animCurrent(st); st.start = null; return; }
      st.start = Number(v); st.hold = null; st.pendingPlay = false; st.paused = false;
      if (!st.ready.settled) { st.ready.settled = true; st.ready.resolve(this); }
      __animLive.add(this);
      __scheduleFinish(this);
    }
    get currentTime() { return __animCurrent(__animOf(this)); }
    set currentTime(v) {
      const st = __animOf(this), t = Number(v);
      if (st.start !== null && !st.paused) st.start = __animNow() - t / st.rate; else st.hold = t;
      __scheduleFinish(this);
    }
    get playbackRate() { return __animOf(this).rate; }
    set playbackRate(v) { const st = __animOf(this); const cur = __animCurrent(st); st.rate = Number(v); if (st.start !== null && cur !== null) st.start = __animNow() - cur / st.rate; __scheduleFinish(this); }
    get playState() { return __animState(__animOf(this)); }
    get replaceState() { __animOf(this); return 'active'; }
    get pending() { const st = __animOf(this); return st.pendingPlay; }
    get ready() { return __animOf(this).ready.promise; }
    get finished() { return __animOf(this).finished.promise; }
    get onfinish() { return __animOf(this).onfinish; }
    set onfinish(v) { __animOf(this).onfinish = typeof v === 'function' ? v : null; }
    get oncancel() { return __animOf(this).oncancel; }
    set oncancel(v) { __animOf(this).oncancel = typeof v === 'function' ? v : null; }
    get onremove() { return __animOf(this).onremove; }
    set onremove(v) { __animOf(this).onremove = typeof v === 'function' ? v : null; }
    play() { __animOf(this); __play(this); }
    pause() {
      const st = __animOf(this);
      if (st.paused) return;
      const cur = __animCurrent(st);
      st.hold = cur === null ? 0 : cur; st.start = null; st.paused = true; st.pendingPlay = false;
      if (st.timer) { clearTimeout(st.timer); st.timer = null; }
      if (!st.ready.settled) { st.ready.settled = true; st.ready.resolve(this); }
    }
    finish() {
      const st = __animOf(this);
      const end = st.rate < 0 ? 0 : __endTime(st.effect);
      st.pendingPlay = false; st.paused = false;
      st.start = __animNow() - end / st.rate; st.hold = null;
      if (!st.ready.settled) { st.ready.settled = true; st.ready.resolve(this); }
      __scheduleFinish(this);
    }
    cancel() {
      const st = __animOf(this);
      if (__animState(st) === 'idle') return;
      if (st.timer) { clearTimeout(st.timer); st.timer = null; }
      st.start = null; st.hold = null; st.pendingPlay = false; st.paused = false;
      const err = __pt_mkErr(globalThis.DOMException || Error, 'The user aborted a request.', 'AbortError');
      if (!st.ready.settled) { st.ready.settled = true; st.ready.reject(err); __newDeferred(st, 'ready'); st.ready.settled = true; st.ready.resolve(this); }
      if (!st.finishedFired) { st.finished.reject(err); __newDeferred(st, 'finished'); }
      st.finishedFired = false;
      __animLive.delete(this);
      __animFire(this, 'cancel');
    }
    reverse() { const st = __animOf(this); st.rate = -st.rate; __play(this); }
    updatePlaybackRate(r) { this.playbackRate = r; }
    persist() { __animOf(this); }
    commitStyles() { __animOf(this); }
  };
  // `element.animate()` and the lists of running animations.
  const __animsOf = (root, sub) => {
    const out = [];
    for (const a of __animLive) {
      const st = __ANIM.get(a), eff = st.effect && __ANIM.get(st.effect);
      const t = eff && eff.target;
      if (!t) continue;
      if (t === root || (sub && root.contains && root.contains(t))) if (__animState(st) !== 'finished' || (eff.timing.fill === 'forwards' || eff.timing.fill === 'both')) out.push(a);
    }
    return out;
  };
  Object.defineProperty(Element.prototype, 'animate', { value: { animate(keyframes, options) {
    if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'animate' on 'Element': 1 argument required, but only 0 present.");
    const effect = new globalThis.KeyframeEffect(this, keyframes, options);
    const anim = new globalThis.Animation(effect, document.timeline);
    if (options && typeof options === 'object' && options.id !== undefined) __ANIM.get(anim).id = String(options.id);
    __play(anim);
    return anim;
  } }.animate, writable: true, enumerable: true, configurable: true });
  for (const C of [Element, Document, ShadowRoot]) {
    Object.defineProperty(C.prototype, 'getAnimations', { value: { getAnimations() {
      return C === Element ? __animsOf(this, !!(arguments[0] && arguments[0].subtree)) : __animsOf(this.documentElement || this, true);
    } }.getAnimations, writable: true, enumerable: true, configurable: true });
  }

  // ---- View Transitions ----------------------------------------------------
  // `document.startViewTransition()` returned undefined, and code that reads
  // `.ready` off the result broke the page (khanacademy.org rendered half).
  // Nothing is captured or painted: the update runs on the next frame, then
  // the promises settle in Chrome's order (updateCallbackDone, ready, finished).
  const __VT = new WeakMap();
  const __vtToken = Symbol();
  let __vtActive = null;
  const __vtOf = (o) => { const st = o !== null && typeof o === 'object' ? __VT.get(o) : undefined; if (!st) throw __pt_mkErr(TypeError, 'Illegal invocation'); return st; };
  const __vtAbort = (msg, name) => __pt_mkErr(globalThis.DOMException || Error, msg, name);
  const __VTTypes = globalThis.ViewTransitionTypeSet = class ViewTransitionTypeSet {
    constructor(token, list) {
      if (token !== __vtToken) throw __pt_mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      const set = new Set();
      for (const t of list || []) set.add(String(t));
      __VT.set(self, { set });
      return self;
    }
    get size() { return __vtOf(this).set.size; }
    add(v) { __vtOf(this).set.add(String(v)); return this; }
    clear() { __vtOf(this).set.clear(); }
    delete(v) { return __vtOf(this).set.delete(String(v)); }
    has(v) { return __vtOf(this).set.has(String(v)); }
    entries() { return __vtOf(this).set.entries(); }
    keys() { return __vtOf(this).set.values(); }
    values() { return __vtOf(this).set.values(); }
    forEach(cb) { const thisArg = arguments[1]; for (const v of __vtOf(this).set) cb.call(thisArg, v, v, this); }
  };
  Object.defineProperty(__VTTypes.prototype, Symbol.iterator, { value: __VTTypes.prototype.values, writable: true, configurable: true });
  Object.defineProperty(__VTTypes.prototype, Symbol.toStringTag, { value: 'ViewTransitionTypeSet', configurable: true });
  const __VTClass = globalThis.ViewTransition = class ViewTransition {
    constructor(token, update, types) {
      if (token !== __vtToken) throw __pt_mkErr(TypeError, 'Illegal constructor');
      const self = Object.create(new.target.prototype);
      const st = { update, types: new __VTTypes(__vtToken, types), skipped: false, readySettled: false, waits: [] };
      __newDeferred(st, 'ucd');
      __newDeferred(st, 'ready');
      __newDeferred(st, 'finished');
      __VT.set(self, st);
      return self;
    }
    get finished() { return __vtOf(this).finished.promise; }
    get ready() { return __vtOf(this).ready.promise; }
    get updateCallbackDone() { return __vtOf(this).ucd.promise; }
    get types() { return __vtOf(this).types; }
    get transitionRoot() { __vtOf(this); return document.documentElement; }
    skipTransition() { __vtSkip(__vtOf(this), __vtAbort('Transition was skipped', 'AbortError')); }
    waitUntil(p) {
      if (arguments.length < 1) throw __pt_mkErr(TypeError, "Failed to execute 'waitUntil' on 'ViewTransition': 1 argument required, but only 0 present.");
      __vtOf(this).waits.push(Promise.resolve(p));
    }
  };
  Object.defineProperty(__VTClass.prototype, Symbol.toStringTag, { value: 'ViewTransition', configurable: true });
  const __vtSkip = (st, err) => {
    if (st.readySettled) return;
    st.readySettled = true; st.skipped = true;
    st.ready.reject(err);
  };
  const __vtRun = (vt) => {
    const st = __VT.get(vt);
    let r;
    try { r = typeof st.update === 'function' ? st.update.call(undefined) : undefined; }
    catch (e) { r = Promise.reject(e); }
    Promise.resolve(r).then(() => {
      st.ucd.resolve(undefined);
      if (!st.readySettled) { st.readySettled = true; st.ready.resolve(undefined); }
      return Promise.all(st.waits);
    }, (e) => {
      st.ucd.reject(e);
      __vtSkip(st, e);
      throw e;
    }).then(() => st.finished.resolve(undefined), (e) => st.finished.reject(e))
      .then(() => { if (__vtActive === vt) __vtActive = null; });
  };
  Object.defineProperty(Document.prototype, 'startViewTransition', { value: { startViewTransition() {
    const arg = arguments[0];
    let update = null, types = [];
    if (typeof arg === 'function') update = arg;
    else if (arg !== undefined && arg !== null) {
      if (typeof arg !== 'object') throw __pt_mkErr(TypeError, "Failed to execute 'startViewTransition' on 'Document': The provided value is not of type '(StartViewTransitionOptions or ViewTransitionUpdateCallback)'.");
      if (arg.update !== undefined && arg.update !== null) update = arg.update;
      if (arg.types !== undefined && arg.types !== null) types = Array.from(arg.types, String);
    }
    const vt = new __VTClass(__vtToken, update, types);
    const st = __VT.get(vt);
    if (__vtActive) __vtSkip(__VT.get(__vtActive), __vtAbort('Transition was skipped', 'AbortError'));
    __vtActive = vt;
    if (this.visibilityState === 'hidden') __vtSkip(st, __vtAbort('View transition was skipped because document visibility state is hidden.', 'InvalidStateError'));
    // The update runs at the next rendering opportunity.
    setTimeout(() => __vtRun(vt), 16);
    return vt;
  } }.startViewTransition, writable: true, enumerable: true, configurable: true });
  Object.defineProperty(Document.prototype, 'activeViewTransition', { get: Object.getOwnPropertyDescriptor({ get activeViewTransition() { return __vtActive; } }, 'activeViewTransition').get, enumerable: true, configurable: true });

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
      try { return { type: t === 'function' ? 'object' : t, value: __ptJSON.parse(__ptJSON.stringify(v)) }; }
      catch (e) { return { type: 'object', value: null }; }
    }
    // The context's own index in the id: a handle outlives the document it
    // came from, and the next document's registry must not answer for it.
    const id = 'obj-' + (globalThis.__pt_ctxIndex | 0) + '.' + (__ptSeq++);
    __ptObjs.set(id, v);
    if (t === 'function') return { type: 'function', objectId: id, className: 'Function', description: (v.name ? 'function ' + v.name : 'function') + '() { [native code] }' };
    let subtype, className = (v.constructor && v.constructor.name) || 'Object', description = className;
    if (Array.isArray(v)) { subtype = 'array'; className = 'Array'; description = 'Array(' + v.length + ')'; }
    else if (v.__ptType === 1) { subtype = 'node'; description = v.__ptLocal || 'element'; }
    else if (v.__ptType) { subtype = 'node'; description = __s_toLowerCase(v.nodeName || 'node'); }
    return { type: 'object', subtype, objectId: id, className, description };
  };
  // A thrown or rejected value as Chrome reports it: `{__ptExc: {result,
  // exception, text}}`. An object comes back as a handle whatever `byValue`
  // says, an error described by its stack; a rejection's `result` follows
  // `byValue` like any value. Nothing here may run page code (`instanceof`
  // reads Symbol.hasInstance, `String(e)` calls the page's toString).
  const __excIsProto = Object.prototype.isPrototypeOf, __excErrProto = Error.prototype;
  const __excApply = Reflect.apply, __excOwn = Object.getOwnPropertyDescriptor;
  const __excStackGet = (() => { try { const d = __excOwn(new Error(), 'stack'); return d && d.get; } catch (x) { return undefined; } })();
  const __excIsError = (e) => { try { return __excApply(__excIsProto, __excErrProto, [e]); } catch (x) { return false; } };
  globalThis.__pt_exc = (e, rejected, byValue) => {
    let ro;
    const isErr = e !== null && typeof e === 'object' && __excIsError(e);
    if (e !== null && (typeof e === 'object' || typeof e === 'function')) {
      ro = __pt_wrap(e, false);
      if (isErr) {
        ro.subtype = 'error';
        // V8's own accessor or a plain value; a getter the page put there is not called.
        let stack;
        try {
          const d = __excOwn(e, 'stack');
          if (d && typeof d.value === 'string') stack = d.value;
          else if (d && d.get && d.get === __excStackGet) stack = __excApply(__excStackGet, e, []);
        } catch (x) {}
        if (typeof stack !== 'string' || !stack) {
          const m = __excOwn(e, 'message');
          const msg = m && typeof m.value === 'string' ? m.value : '';
          stack = msg ? ro.className + ': ' + msg : ro.className;
        }
        ro.description = stack;
      }
    } else {
      ro = __pt_wrap(e, true);
    }
    let text = rejected ? 'Uncaught (in promise)' : 'Uncaught';
    if (rejected && isErr && typeof ro.description === 'string') {
      const nl = __s_indexOf(ro.description, '\n');
      text += ' ' + (nl < 0 ? ro.description : __s_slice(ro.description, 0, nl));
    }
    return { __ptExc: { result: rejected ? __pt_wrap(e, byValue) : ro, exception: ro, text } };
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
    if (n == null || !n.__ptType) return null;
    const attrs = [];
    if (n.__ptType === ELEMENT_NODE && n.__ptAttrs) for (const [name, value] of n.__ptAttrs) { attrs.push(name); attrs.push(value); }
    return {
      backendNodeId: globalThis.__pt_nodeId(n), nodeId: 0, nodeType: n.__ptType,
      nodeName: n.nodeName || '', localName: n.localName || '', nodeValue: n.nodeValue || '',
      childNodeCount: (n.__ptKids || []).length, attributes: attrs,
      // The frame an <iframe> holds; the server names it as Chrome does.
      ptFrame: n.__ptLocal === 'iframe' && n.__ptFrameId ? n.__ptFrameId : undefined
    };
  };
  // ---- synthetic layout + interaction (no real rendering) ------------------
  // There is no layout engine, so every rendered element is assigned a unique,
  // deterministic one-row box in document order. That is enough for the two
  // things drivers need: (a) a non-empty box + coordinates for visibility and
  // click-point computation, and (b) a reversible point→element mapping so an
  // Input mouse event at a computed coordinate hits the intended element.
  // The document viewport is the same as `innerWidth`/`innerHeight`: in Chrome
  // `documentElement.clientWidth` and `innerWidth` describe one rectangle.
  const LAYOUT = {
    W: (globalThis.innerWidth | 0) || 1280,
    H: (globalThis.innerHeight | 0) || 720,
    ROW: 20,
  };
  // A frame's viewport is its own `<iframe>`, not the page (the Turnstile
  // widget is 300x65 and reads it). The engine reports it right after
  // creating the context.
  // Chrome does not lay out a `display: none` frame: the body width inside
  // stays `auto`. The host page sets the flag when its `<iframe>` has no box.
  let __rendered = true;
  globalThis.__pt_setRendered = (on) => {
    on = !!on;
    if (on === __rendered) return;
    __rendered = on;
    __layoutBuilt = -1;
    __layoutAllDirty = true;
  };

  // Relayout this document. Called from another realm: the page measures its
  // frame's nodes, and the frame lays them out itself.
  globalThis.__pt_relayout = () => { try { __relayout(); } catch (e) {} };

  // The window of a frame removed from the document: a closed context in
  // Chrome. A page holding the window reference reads zeros and `closed`.
  globalThis.__pt_detach = () => {
    try { Object.defineProperty(globalThis, '__ptDetached', { value: true, configurable: true }); } catch (e) {}
    try { globalThis.__pt_setViewport(0, 0); } catch (e) {}
    const nat = (f, n) => { try { Object.defineProperty(f, 'name', { value: n, configurable: true }); } catch (e) {} return globalThis.__pt_native ? __pt_native(f) : f; };
    const put = (k, v) => { try { const d = Object.getOwnPropertyDescriptor(globalThis, k); if (d && !d.configurable) return; Object.defineProperty(globalThis, k, { get: nat(function () { return v; }, 'get ' + k), set: undefined, enumerable: true, configurable: true }); } catch (e) {} };
    put('outerWidth', 0); put('outerHeight', 0); put('closed', true); put('frameElement', null);
    put('parent', globalThis); put('top', globalThis);
  };
  globalThis.__pt_setViewport = (w, h) => {
    w = Math.max(0, Math.round(Number(w) || 0));
    h = Math.max(0, Math.round(Number(h) || 0));
    if (w === LAYOUT.W && h === LAYOUT.H && __rendered) return;
    LAYOUT.W = w; LAYOUT.H = h;
    for (const [name, value] of [['innerWidth', w], ['innerHeight', h]]) {
      try {
        const d = Object.getOwnPropertyDescriptor(globalThis, name);
        Object.defineProperty(globalThis, name, {
          value, writable: d ? d.writable !== false : true,
          enumerable: d ? d.enumerable : true, configurable: true,
        });
      } catch (e) {}
    }
    __layoutBuilt = -1;   // recompute boxes for the new size
    __layoutAllDirty = true;
  };
  let __layoutSeq = 0;      // bumped on every DOM mutation
  let __layoutBuilt = -1;   // __layoutSeq the current boxes were built at
  let __rows = [];          // elements in paint order
  let __boxes = [];         // same, for hit testing
  let __mouseDownEl = null;
  let __hoverEl = null; // element the pointer is currently over

  // A change for layout: with the node it happened at, only that node's and
  // its ancestors' kept layouts are dropped (`__layoutOne`); without one,
  // all of them.
  function __markDirty(node) {
    __layoutSeq++;
    if (__layoutAllDirty) return;
    if (!node || __layoutDirty.length >= 4000) { __layoutAllDirty = true; __layoutDirty = []; return; }
    __layoutDirty.push(node);
  }
  // Drop the kept layouts a change reaches: the node and every box around it.
  function __layoutForget() {
    if (__layoutAllDirty) {
      __layoutMemo = new WeakMap();
      __layoutAllDirty = false;
      __layoutDirty = [];
      return;
    }
    for (const node of __layoutDirty) {
      for (let n = node; n; n = n.__ptParent || n.__ptHost || null) {
        if (!__layoutMemo.delete(n) && n.__ptType === ELEMENT_NODE && n.__ptLayoutUp === __layoutBuilt) break;
        if (n.__ptType === ELEMENT_NODE) n.__ptLayoutUp = __layoutBuilt;
      }
    }
    __layoutDirty = [];
  }

  // --- MutationObserver ---------------------------------------------------
  // As Blink does it (mutation_observer.cc): registrations live on the
  // observed nodes; a mutation walks the target's ancestors and each observer
  // interested gets one MutationRecord, with the old value only if one of its
  // registrations asked for it; observers are delivered in a microtask, in
  // the order they were created; a node removed from an observed subtree
  // keeps a transient registration until its observer is next delivered.
  // Observers without registrations or records are not held (all of them
  // were, for the life of the page).
  // Registration: { st, o: options, filter: Set|null, node, transients: Set }.
  const __moRegs = new WeakMap();
  const __moTransient = new WeakMap();
  let __moLive = 0;
  let __moPriority = 0;
  const __moActive = new Set();
  let __moScheduled = false;

  // Bookkeeping left behind, for tests: registrations (transient ones too)
  // and observers waiting for delivery.
  Object.defineProperty(globalThis, '__pt_moStats', { value: () => ({ regs: __moLive, active: __moActive.size }), configurable: true, enumerable: false });
  function __moActivate(st) {
    __moActive.add(st);
    if (!__moScheduled) { __moScheduled = true; queueMicrotask(__moDeliver); }
  }
  function __moClearTransients(reg) {
    for (const n of reg.transients) {
      const list = __moTransient.get(n);
      if (!list) continue;
      const i = __s_indexOf(list, reg);
      if (i >= 0) { list.splice(i, 1); __moLive--; }
      if (!list.length) __moTransient.delete(n);
    }
    reg.transients.clear();
  }
  function __moDeliver() {
    __moScheduled = false;
    const sts = [...__moActive].sort((a, b) => a.priority - b.priority);
    __moActive.clear();
    for (const st of sts) {
      for (const reg of st.regs) if (reg.transients.size) __moClearTransients(reg);
      if (!st.records.length) continue;
      const batch = st.records.splice(0);
      try { st.cb.call(st.api, batch, st.api); } catch (e) { __pt_reportError(e, 'MutationObserver'); }
    }
  }
  // A node leaving a parent: every subtree registration on the parent's
  // inclusive ancestors (transient ones too) follows it.
  function __moNodeWillDetach(parent, node) {
    if (!__moLive) return;
    for (let n = parent; n; n = n.__ptParent) {
      for (const map of [__moRegs, __moTransient]) {
        const regs = map.get(n);
        if (!regs) continue;
        for (const reg of regs) {
          if (!reg.o.subtree) continue;
          let list = __moTransient.get(node);
          if (!list) __moTransient.set(node, (list = []));
          list.push(reg);
          __moLive++;
          reg.transients.add(node);
          __moActivate(reg.st);
        }
      }
    }
  }
  function __moRecord(src, old) {
    const R = globalThis.MutationRecord;
    if (typeof R !== 'function' || typeof __pt_write !== 'function') return Object.assign({}, src, { oldValue: old });
    const m = Object.create(R.prototype);
    __pt_write(m, 'type', src.type);
    __pt_write(m, 'target', src.target);
    __pt_write(m, 'addedNodes', src.addedNodes);
    __pt_write(m, 'removedNodes', src.removedNodes);
    __pt_write(m, 'previousSibling', src.previousSibling || null);
    __pt_write(m, 'nextSibling', src.nextSibling || null);
    __pt_write(m, 'attributeName', src.attributeName == null ? null : src.attributeName);
    __pt_write(m, 'attributeNamespace', src.attributeNamespace == null ? null : src.attributeNamespace);
    __pt_write(m, 'oldValue', old);
    return m;
  }
  function __mutation(rec) {
    if (!__moLive) return;
    const type = rec.type;
    let wants = null;
    const consider = (reg, atTarget) => {
      const o = reg.o;
      if (!atTarget && !o.subtree) return;
      if (type === 'attributes') {
        if (!o.attributes) return;
        if (reg.filter && (rec.attributeNamespace != null || !reg.filter.has(rec.attributeName))) return;
      } else if (type === 'characterData') {
        if (!o.characterData) return;
      } else if (!o.childList) return;
      const old = (type === 'attributes' && o.attributeOldValue) || (type === 'characterData' && o.characterDataOldValue);
      if (!wants) wants = new Map();
      wants.set(reg.st, !!(wants.get(reg.st) || old));
    };
    for (let n = rec.target; n; n = n.__ptParent) {
      const regs = __moRegs.get(n);
      if (regs) for (const reg of regs) consider(reg, n === rec.target);
      const tr = __moTransient.get(n);
      if (tr) for (const reg of tr) consider(reg, n === rec.target);
    }
    if (!wants) return;
    const src = {
      type, target: rec.target,
      addedNodes: __staticNodeList(rec.addedNodes || __NO_NODES),
      removedNodes: __staticNodeList(rec.removedNodes || __NO_NODES),
      previousSibling: rec.previousSibling, nextSibling: rec.nextSibling,
      attributeName: rec.attributeName, attributeNamespace: rec.attributeNamespace,
    };
    let withOld = null, without = null;
    for (const [st, old] of wants) {
      const m = old
        ? (withOld || (withOld = __moRecord(src, rec.oldValue == null ? null : rec.oldValue)))
        : (without || (without = __moRecord(src, null)));
      st.records.push(m);
      __moActivate(st);
    }
  }

  function __childListRecord(target, added, removed, prev, next) {
    return {
      type: 'childList', target,
      addedNodes: added, removedNodes: removed,
      previousSibling: prev || null, nextSibling: next || null,
      attributeName: null, attributeNamespace: null, oldValue: null,
    };
  }

  class MutationObserver {
    constructor(cb) {
      if (typeof cb !== 'function') throw __pt_mkErr(TypeError, "Failed to construct 'MutationObserver': parameter 1 is not of type 'Function'.");
      const state = { cb, regs: [], records: [], api: this, priority: __moPriority++ };
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target, init) {
      __needArgs(arguments.length, 1, 'observe', 'MutationObserver');
      __needNode(target, 1, 'observe', 'MutationObserver');
      // The dictionary, read once per member in IDL order; the page's object
      // is not written to.
      const d = init == null ? {} : init;
      const has = (v) => v !== undefined;
      const filterIn = d.attributeFilter, aovIn = d.attributeOldValue, attrsIn = d.attributes;
      const cdIn = d.characterData, cdovIn = d.characterDataOldValue, childIn = d.childList, subIn = d.subtree;
      const filter = has(filterIn) ? new Set(Array.from(filterIn, (x) => String(x))) : null;
      const aov = has(aovIn) && !!aovIn;
      const attributes = (has(attrsIn) && !!attrsIn) || (!has(attrsIn) && (has(aovIn) || has(filterIn)));
      const cdov = has(cdovIn) && !!cdovIn;
      const characterData = (has(cdIn) && !!cdIn) || (!has(cdIn) && has(cdovIn));
      const childList = !!childIn, subtree = !!subIn;
      const err = (m) => __pt_mkErr(TypeError, "Failed to execute 'observe' on 'MutationObserver': " + m);
      if (!attributes) {
        if (aov) throw err("The options object may only set 'attributeOldValue' to true when 'attributes' is true or not present.");
        if (filter) throw err("The options object may only set 'attributeFilter' when 'attributes' is true or not present.");
      }
      if (cdov && !characterData) throw err("The options object may only set 'characterDataOldValue' to true when 'characterData' is true or not present.");
      if (!attributes && !characterData && !childList) throw err("The options object must set at least one of 'attributes', 'characterData', or 'childList' to true.");
      const o = { childList, attributes, characterData, subtree, attributeOldValue: aov, characterDataOldValue: cdov };
      const st = this.__ptState;
      let regs = __moRegs.get(target);
      const same = regs && regs.find((r) => r.st === st);
      if (same) {
        __moClearTransients(same);
        same.o = o;
        same.filter = filter;
        return;
      }
      if (!regs) __moRegs.set(target, (regs = []));
      const reg = { st, o, filter, node: target, transients: new Set() };
      regs.push(reg);
      st.regs.push(reg);
      __moLive++;
    }
    disconnect() {
      const st = this.__ptState;
      for (const reg of st.regs) {
        __moClearTransients(reg);
        const regs = __moRegs.get(reg.node);
        if (!regs) continue;
        const i = __s_indexOf(regs, reg);
        if (i >= 0) { regs.splice(i, 1); __moLive--; }
        if (!regs.length) __moRegs.delete(reg.node);
      }
      st.regs = [];
      st.records = [];
      __moActive.delete(st);
    }
    takeRecords() { return this.__ptState.records.splice(0); }
  }

  // --- ResizeObserver -----------------------------------------------------
  // No real layout here, so there is nothing to *re*-observe — but Chrome
  // delivers one observation as soon as you observe an element, and code that
  // waits for that first callback would otherwise hang forever.
  class ResizeObserver {
    constructor(cb) {
      const state = { cb, targets: [] };
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target) {
      const st = this.__ptState;
      st.targets.push(target);
      queueMicrotask(() => {
        const r = (target.getBoundingClientRect && target.getBoundingClientRect()) || { width: 0, height: 0, x: 0, y: 0, top: 0, left: 0 };
        const box = [{ inlineSize: r.width, blockSize: r.height }];
        try {
          st.cb([{ target, contentRect: r, borderBoxSize: box, contentBoxSize: box, devicePixelContentBoxSize: box }], this);
        } catch (e) {}
      });
    }
    unobserve(target) { const t = this.__ptState.targets; const i = __s_indexOf(t, target); if (i >= 0) t.splice(i, 1); }
    disconnect() { this.__ptState.targets = []; }
  }

  // --- frame plumbing -----------------------------------------------------
  // The engine drains `__pt_drainFrameQueue` each turn, builds the child context,
  // and calls back with `__pt_frameReady`. Messages travel the same road: a
  // `postMessage` in either direction becomes an op, and arrives as an event.
  const __frames = new Map();
  const __frameOps = [];
  let __nextFrameId = 1;

  // Every op costs an eval on the other side, so an unbounded queue is a way for
  // a page to spend the engine's memory: a widget that posts into its frame from
  // an interval, faster than the ops drain, once took RSS past five gigabytes.
  // Beyond the cap the newest op is dropped — a lost message degrades one widget,
  // where the alternative loses the process.
  const __MAX_FRAME_OPS = 4096;
  const __pushFrameOp = (op, into) => {
    const q = into || __frameOps;
    if (q.length < __MAX_FRAME_OPS) q.push(op);
  };

  globalThis.__pt_drainFrameQueue = () => __frameOps.splice(0);

  // MessagePorts sent across a frame boundary. The port that leaves goes dead here;
  // its partner stays and from now on talks to the other frame through the engine.
  // Each channel gets an id, its ends `<id>:a` (stayed) and `<id>:b` (went).
  const __portEnds = new Map();
  let __portSeq = 0;
  const __transferPorts = (transfer) => {
    const ids = [];
    if (!transfer || typeof transfer[Symbol.iterator] !== 'function') return ids;
    for (const p of transfer) {
      const st = p && p.__pt;
      if (!st || !('remote' in st)) continue;
      const id = (globalThis.__pt_frameId || 0) + '-' + (++__portSeq) + '-' + __s_slice(Math.random().toString(36), 2, 8);
      const peer = st.peer;
      st.peer = null;
      if (peer) {
        peer.__pt.peer = null;
        peer.__pt.remote = id + ':b';
        __portEnds.set(id + ':a', peer);
      } else if (st.remote) {
        // A port that already crossed once and moves on: hand its route over.
        ids.push(__s_replace(st.remote, /:[ab]$/, ''));
        continue;
      }
      ids.push(id);
    }
    return ids;
  };
  globalThis.__pt_portOut = (end, data) => {
    // A shared worker's port talks over the worker channel.
    if (__s_slice(end, 0, 3) === 'sw:') {
      __workerOps.push({ op: 'post', id: +__s_slice(end, 3), data: __pt_cloneEncode(data) });
      return;
    }
    __pushFrameOp({ op: 'portpost', end, data: __pt_cloneEncode(data) });
  };
  globalThis.__pt_portIn = (end, raw) => {
    const port = __portEnds.get(end);
    if (!port) return;
    let data = raw;
    try { data = globalThis.__pt_cloneRevive ? __pt_cloneRevive(raw) : raw; } catch (e) {}
    const ev = { type: 'message', data, origin: '', lastEventId: '', source: null, ports: [], isTrusted: true, target: port, currentTarget: port };
    setTimeout(() => {
      const st = port.__pt;
      if (!st.started) { st.queue.push(ev); return; }
      port.__ptDeliver(ev);
    }, 0);
  };
  const __receivePorts = (ids) => (ids || []).map((id) => {
    const port = new MessageChannel().port1;
    port.__pt.peer = null;
    port.__pt.remote = id + ':a';
    __portEnds.set(id + ':b', port);
    return port;
  });
  // `postMessage(data, targetOrigin, transfer)` or `postMessage(data, { targetOrigin, transfer })`.
  const __transferOf = (a, b) => (a && typeof a === 'object' && !Array.isArray(a)) ? a.transfer : b;
  // A frame element's box at request time: no layout exists at insertion, and
  // the engine asks after the document is parsed.
  globalThis.__pt_frameBoxOf = (el) => {
    // A set size beats a computed one: the widget sets it in style or
    // attributes, and layout may still be stale. A declared 0 is 0 (Chrome's
    // window for such a frame is 0x0); undeclared is -1.
    const px = (v) => { const n = parseFloat(v); return Number.isFinite(n) ? Math.max(0, Math.round(n)) : -1; };
    let w = -1, h = -1;
    try { w = px(el.style && el.style.width); if (w < 0) w = px(__ptGetA(el, 'width')); } catch (e) {}
    try { h = px(el.style && el.style.height); if (h < 0) h = px(__ptGetA(el, 'height')); } catch (e) {}
    if (w >= 0 || h >= 0) return __ptJSON.stringify([w < 0 ? 300 : w, h < 0 ? 150 : h]);
    w = 0; h = 0;
    // Declared size only: asking layout would build it mid-load and freeze it
    // half-built (pages then got zero boxes). Undeclared means the default
    // frame size.
    return __ptJSON.stringify([w || 300, h || 150]);
  };
  globalThis.__pt_frameBox = (id) => {
    const st = __frames.get(id);
    return st && st.el ? __pt_frameBoxOf(st.el) : '[300,150]';
  };

  // --- dynamically inserted <script src> -----------------------------------
  // The element cannot fetch; the engine can. Each insertion becomes an op the
  // driver picks up, fetches against the document's own base URL and cookies, and
  // evaluates in this context — then says how it went, so `onload`/`onerror` fire
  // where the page expects them.
  const __scriptEls = new Map();
  const __scriptOps = [];
  let __nextScriptId = 1;

  globalThis.__pt_drainScriptQueue = () => __scriptOps.splice(0);

  // While a page-inserted script runs, `document.currentScript` is that script,
  // as for markup scripts. Turnstile's api.js uses it to find its own URL and
  // its Resource Timing entry, which goes to the widget. For modules
  // `currentScript` is null in Chrome too; not set.
  globalThis.__pt_scriptStart = (id) => {
    const el = __scriptEls.get(id);
    if (el) document.__ptCurScript = el;
  };

  globalThis.__pt_scriptDone = (id, ok) => {
    const el = __scriptEls.get(id);
    // After the script runs `currentScript` is null again; `onload` does not
    // see it, as in Chrome.
    if (el && document.__ptCurScript === el) document.__ptCurScript = null;
    if (!el) return;
    __scriptEls.delete(id);
    // dispatchEvent calls `on…` itself; calling it separately fires twice.
    try { el.dispatchEvent && el.dispatchEvent(__ptTrust(new Event(ok ? 'load' : 'error'))); } catch (e) {}
    try { el.__ptReleaseLoad(); } catch (e) {}
  };

  // Tear down a frame whose element left the document, and let the element be
  // connected again later as a fresh one.
  const __ptDisconnectFrame = (el) => {
    const id = el.__ptFrameId;
    if (!id) return;
    try { el.__ptReleaseLoad(); } catch (e) {}
    __frames.delete(id);
    try { Object.defineProperty(el, '__ptFrameId', { value: 0, configurable: true, enumerable: false }); } catch (e) {}
    __frameOps.push({ op: 'close', id });
  };

  // The cross-origin window surface, and nothing more: `postMessage`, the frame
  // tree accessors, `closed`. Reading anything else from another origin throws in
  // a browser; answering `undefined` would give us away, so the object simply
  // carries what is allowed. Messages sent before the document exists are held
  // and flushed on ready, as a browser queues them against `about:blank`.
  const __frameWindow = (id, st) => ({
    postMessage: (data, targetOrigin, transfer) => {
      const origin = (targetOrigin && typeof targetOrigin === 'object') ? targetOrigin.targetOrigin : targetOrigin;
      const op = { op: 'post', id, data: __pt_cloneEncode(data), toParent: false, targetOrigin: String(origin || '*'),
        ports: __transferPorts(__transferOf(targetOrigin, transfer)) };
      __pushFrameOp(op, st.ready ? __frameOps : st.pending);
    },
    get closed() { return false; },
    get frames() { return st.win; },
    get length() { return 0; },
    get parent() { return globalThis; },
    get top() { return globalThis; },
    get opener() { return null; },
    get self() { return st.win; },
    get window() { return st.win; },
  });

  // The page's frames in document order, for the engine to tell each frame its siblings.
  globalThis.__pt_frameList = () => __ptJSON.stringify([...__frames.entries()]
    .map(([id, st]) => ({ id, name: (st.el && __ptGetA(st.el, 'name')) || '' })));

  globalThis.__pt_frameReady = (id, origin) => {
    const st = __frames.get(id);
    if (!st) return;
    st.ready = true;
    st.sameOrigin = !!(globalThis.location && origin === location.origin);
    for (const op of st.pending.splice(0)) __pushFrameOp(op);
    const ev = { type: 'load', target: st.el, currentTarget: st.el, isTrusted: true };
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
    try { st.el.__ptReleaseLoad(); } catch (e) {}
  };

  globalThis.__pt_frameFailed = (id) => {
    const st = __frames.get(id);
    if (!st) return;
    __frames.delete(id);
    const ev = { type: 'error', target: st.el, currentTarget: st.el, isTrusted: true };
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
    try { st.el.__ptReleaseLoad(); } catch (e) {}
  };

  // A `message` event arriving from the other side of a frame boundary.
  globalThis.__pt_deliverMessage = (raw, origin, fromFrameId, portIds) => {
    // The value arrives as a parsed literal; revive the same types from it.
    let data = raw;
    try { data = globalThis.__pt_cloneRevive ? __pt_cloneRevive(raw) : raw; } catch (e) {}
    const source = fromFrameId
      ? ((__frames.get(fromFrameId) || {}).win || (globalThis.__pt_siblingWindow ? __pt_siblingWindow(fromFrameId) : null) || null)
      : (globalThis.parent === globalThis ? null : globalThis.parent);
    const ev = {
      type: 'message', data, origin: String(origin || ''), lastEventId: '',
      source, ports: Object.freeze(__receivePorts(portIds)), isTrusted: true, target: globalThis, currentTarget: globalThis,
    };
    try { globalThis.dispatchEvent && globalThis.dispatchEvent(ev); } catch (e) {}
  };

  // Inside a frame, `parent`/`top` are the embedder, and `postMessage` on them
  // goes back up. The engine calls this right after creating the child context
  // and before its document exists — a context cannot know it is a frame while
  // its own bootstrap is still running.
  globalThis.__pt_markAsFrame = (id, name) => {
    globalThis.__pt_frameId = id;
    // `window.name` is the element's `name`: a frame can derive a sibling's name
    // from its own and look it up in `parent.frames`.
    if (name) { try { globalThis.name = String(name); } catch (e) {} }
    // The other frames of the same page: the engine keeps the list current.
    let siblings = [];
    const sibWins = new Map();
    const sibling = (sid) => {
      if (sid === id) return globalThis;
      if (!sibWins.has(sid)) {
        const w = {
          postMessage: (data, targetOrigin, transfer) => {
            __pushFrameOp({ op: 'post', toFrame: sid, data: __pt_cloneEncode(data),
              ports: __transferPorts(__transferOf(targetOrigin, transfer)) });
          },
          get closed() { return !siblings.some((f) => f.id === sid); },
          get frames() { return w; },
          get length() { return 0; },
          get parent() { return up; },
          get top() { return up; },
          get self() { return w; },
          get window() { return w; },
        };
        sibWins.set(sid, w);
      }
      return sibWins.get(sid);
    };
    globalThis.__pt_setSiblings = (list) => { siblings = Array.isArray(list) ? list : []; };
    globalThis.__pt_siblingWindow = (sid) => siblings.some((f) => f.id === sid) ? sibling(sid) : null;
    const frameAt = (k) => {
      if (typeof k !== 'string') return undefined;
      const f = /^\d+$/.test(k) ? siblings[Number(k)] : siblings.find((x) => x.name && x.name === k);
      return f ? sibling(f.id) : undefined;
    };
    const up = {
      postMessage: (data, targetOrigin, transfer) => {
        __pushFrameOp({ op: 'post', data: __pt_cloneEncode(data), toParent: true,
          ports: __transferPorts(__transferOf(targetOrigin, transfer)) });
      },
      get closed() { return false; },
      get length() { return siblings.length; },
      get self() { return up; },
      get window() { return up; },
    };
    const framesOf = new Proxy(up, {
      get(t, k) { if (k in t) return t[k]; return frameAt(k); },
      has(t, k) { return (k in t) || frameAt(k) !== undefined; },
    });
    Object.defineProperty(up, 'frames', { get: () => framesOf, configurable: true });
    try {
      Object.defineProperty(globalThis, 'parent', { value: up, configurable: true });
      Object.defineProperty(globalThis, 'top', { value: up, configurable: true });
    } catch (e) {}
    // A cross-origin frame cannot see its `<iframe>`: `frameElement` is null,
    // and so is `opener`.
    for (const k of ['frameElement', 'opener']) {
      try {
        const g = function () { return null; };
        try { Object.defineProperty(g, 'name', { value: 'get ' + k, configurable: true }); } catch (e) {}
        Object.defineProperty(globalThis, k, { get: globalThis.__pt_native ? __pt_native(g) : g, set: undefined, enumerable: true, configurable: true });
      } catch (e) {}
    }
  };

  // --- tree traversal ------------------------------------------------------
  // `NodeFilter` + `createTreeWalker`/`createNodeIterator`. Absent, this cost us
  // every Cloudflare challenge: the Turnstile loader answers its widget's
  // `requestExtraParams` with a page report that walks the document through a
  // TreeWalker, so `NodeFilter is not defined` threw inside a `message` listener
  // — where the exception is swallowed by design — and the reply the widget waits
  // for was never sent. It sat there answering heartbeats, forever, saying
  // nothing about why.
  const FILTER_ACCEPT = 1, FILTER_REJECT = 2, FILTER_SKIP = 3;
  const NodeFilter = {
    FILTER_ACCEPT, FILTER_REJECT, FILTER_SKIP,
    SHOW_ALL: 0xFFFFFFFF, SHOW_ELEMENT: 0x1, SHOW_ATTRIBUTE: 0x2, SHOW_TEXT: 0x4,
    SHOW_CDATA_SECTION: 0x8, SHOW_ENTITY_REFERENCE: 0x10, SHOW_ENTITY: 0x20,
    SHOW_PROCESSING_INSTRUCTION: 0x40, SHOW_COMMENT: 0x80, SHOW_DOCUMENT: 0x100,
    SHOW_DOCUMENT_TYPE: 0x200, SHOW_DOCUMENT_FRAGMENT: 0x400, SHOW_NOTATION: 0x800,
  };

  // The filter verdict for one node: the `whatToShow` bitmask first (a node it
  // hides is skipped without ever reaching the callback), then the caller's
  // filter, which may be a function or an object with `acceptNode`.
  const __ptVerdict = (walker, node) => {
    if (!((1 << (node.__ptType - 1)) & walker.__ptShow)) return FILTER_SKIP;
    const f = walker.__ptFilter;
    if (!f) return FILTER_ACCEPT;
    const v = typeof f === 'function' ? f(node) : (f.acceptNode ? f.acceptNode(node) : FILTER_ACCEPT);
    return v === undefined || v === null ? FILTER_ACCEPT : v;
  };

  // The node after `node` in document order, without leaving `root`.
  const __ptFollowing = (node, root, skipChildren) => {
    if (!skipChildren && node.__ptKids && node.__ptKids.length) return node.__ptKids[0];
    for (let n = node; n && n !== root; n = n.__ptParent) {
      if (n.nextSibling) return n.nextSibling;
    }
    return null;
  };

  class TreeWalker {
    constructor(root, whatToShow, filter) {
      this.__ptRoot = root;
      this.__ptShow = whatToShow === undefined ? 0xFFFFFFFF : whatToShow >>> 0;
      this.__ptFilter = filter || null;
      this.__ptCur = root;
    }
    get root() { return this.__ptRoot; }
    get whatToShow() { return this.__ptShow; }
    get filter() { return this.__ptFilter; }
    get currentNode() { return this.__ptCur; }
    set currentNode(n) { this.__ptCur = n; }

    nextNode() {
      let node = this.__ptCur, skipKids = false;
      for (;;) {
        node = __ptFollowing(node, this.__ptRoot, skipKids);
        if (!node) return null;
        const v = __ptVerdict(this, node);
        if (v === FILTER_ACCEPT) { this.__ptCur = node; return node; }
        skipKids = v === FILTER_REJECT;
      }
    }
    previousNode() {
      let node = this.__ptCur;
      while (node && node !== this.__ptRoot) {
        let prev = node.previousSibling;
        if (prev) {
          while (prev.__ptKids && prev.__ptKids.length) prev = prev.__ptKids[prev.__ptKids.length - 1];
          node = prev;
        } else {
          node = node.__ptParent;
          if (!node || node === this.__ptRoot) return null;
        }
        if (__ptVerdict(this, node) === FILTER_ACCEPT) { this.__ptCur = node; return node; }
      }
      return null;
    }
    parentNode() {
      for (let n = this.__ptCur; n && n !== this.__ptRoot; ) {
        n = n.__ptParent;
        if (!n) return null;
        if (__ptVerdict(this, n) === FILTER_ACCEPT) { this.__ptCur = n; return n; }
        if (n === this.__ptRoot) break;
      }
      return null;
    }
    firstChild() { return this.__ptChild(0); }
    lastChild() { return this.__ptChild(-1); }
    __ptChild(from) {
      const kids = this.__ptCur.__ptKids || [];
      const list = from === 0 ? kids : __s_slice(kids).reverse();
      for (const c of list) {
        if (__ptVerdict(this, c) === FILTER_ACCEPT) { this.__ptCur = c; return c; }
      }
      return null;
    }
    nextSibling() { return this.__ptSibling('nextSibling'); }
    previousSibling() { return this.__ptSibling('previousSibling'); }
    __ptSibling(dir) {
      for (let n = this.__ptCur[dir]; n; n = n[dir]) {
        if (__ptVerdict(this, n) === FILTER_ACCEPT) { this.__ptCur = n; return n; }
      }
      return null;
    }
  }

  class NodeIterator {
    constructor(root, whatToShow, filter) {
      this.__ptRoot = root;
      this.__ptShow = whatToShow === undefined ? 0xFFFFFFFF : whatToShow >>> 0;
      this.__ptFilter = filter || null;
      this.__ptRef = root;
      this.__ptBefore = true;
    }
    get root() { return this.__ptRoot; }
    get whatToShow() { return this.__ptShow; }
    get filter() { return this.__ptFilter; }
    get referenceNode() { return this.__ptRef; }
    get pointerBeforeReferenceNode() { return this.__ptBefore; }
    nextNode() {
      let node = this.__ptRef;
      if (this.__ptBefore) { this.__ptBefore = false; }
      else { node = __ptFollowing(node, this.__ptRoot, false); }
      while (node) {
        if (__ptVerdict(this, node) === FILTER_ACCEPT) { this.__ptRef = node; return node; }
        node = __ptFollowing(node, this.__ptRoot, false);
      }
      return null;
    }
    previousNode() { return null; }
    detach() {}
  }

  Document.prototype.createTreeWalker = function (root, whatToShow, filter) {
    return new TreeWalker(root || this, whatToShow, filter);
  };
  Document.prototype.createNodeIterator = function (root, whatToShow, filter) {
    return new NodeIterator(root || this, whatToShow, filter);
  };
  globalThis.NodeFilter = NodeFilter;
  globalThis.TreeWalker = TreeWalker;
  globalThis.NodeIterator = NodeIterator;

  // Assigned here, after the declarations (a class stays in its temporal dead
  // zone until then). These override the stealth layer's inert stubs: with a
  // document present there is a real tree to watch.
  globalThis.CustomElementRegistry = CustomElementRegistry;
  globalThis.customElements = new CustomElementRegistry();
  // `document.createRange()`: not a full Range, but an object of its interface;
  // pages measure text with `range.getBoundingClientRect()` and fingerprinters
  // read its name.
  const __range = () => {
    const R = globalThis.Range;
    const r = Object.create(R && R.prototype ? R.prototype : Object.prototype);
    let start = document, startOff = 0, end = document, endOff = 0;
    Object.defineProperties(r, {
      startContainer: { get: () => start, enumerable: true, configurable: true },
      endContainer: { get: () => end, enumerable: true, configurable: true },
      startOffset: { get: () => startOff, enumerable: true, configurable: true },
      endOffset: { get: () => endOff, enumerable: true, configurable: true },
      collapsed: { get: () => start === end && startOff === endOff, enumerable: true, configurable: true },
      commonAncestorContainer: { get: () => start, enumerable: true, configurable: true },
    });
    Object.assign(r, {
      setStart(n, o) { start = n; startOff = o | 0; },
      setEnd(n, o) { end = n; endOff = o | 0; },
      setStartBefore(n) { start = n.__ptParent || n; startOff = 0; },
      setStartAfter(n) { start = n.__ptParent || n; startOff = 0; },
      setEndBefore(n) { end = n.__ptParent || n; endOff = 0; },
      setEndAfter(n) { end = n.__ptParent || n; endOff = 0; },
      selectNode(n) { start = end = n.__ptParent || n; startOff = 0; endOff = 0; },
      selectNodeContents(n) { start = end = n; startOff = 0; endOff = (n.childNodes || []).length; },
      collapse(toStart) { if (toStart) { end = start; endOff = startOff; } else { start = end; startOff = endOff; } },
      cloneRange() { const c = __range(); c.setStart(start, startOff); c.setEnd(end, endOff); return c; },
      detach() {},
      toString() { return ''; },
      // Pages measure text through a range (second only to `measureText`).
      // Chrome returns one rect per line, which shows how the text wrapped.
      getClientRects() {
        const node = start;
        const el = node && node.__ptType === ELEMENT_NODE ? node
                 : (node && node.__ptParent) || null;
        const b = el && el.__ptType === ELEMENT_NODE ? __boxOf(el) : null;
        if (!b) return __ptRectList([]);
        const h = (b.asc || 0) + (b.desc || 0);
        const rows = (b.lines && b.lines.length ? b.lines : [{ width: b.cw }]);
        return __ptRectList(rows.map((ln, i) =>
          new DOMRect(b.cx, b.cy + i * (b.line || h), ln.width, h)));
      },
      getBoundingClientRect() {
        const list = this.getClientRects();
        if (!list.length) return { x: 0, y: 0, width: 0, height: 0, top: 0, right: 0, bottom: 0, left: 0 };
        let l = Infinity, t = Infinity, r2 = -Infinity, b2 = -Infinity;
        for (const q of list) { l = Math.min(l, q.left); t = Math.min(t, q.top); r2 = Math.max(r2, q.right); b2 = Math.max(b2, q.bottom); }
        return { x: l, y: t, left: l, top: t, right: r2, bottom: b2, width: r2 - l, height: b2 - t };
      },
      deleteContents() {}, extractContents() { return document.createDocumentFragment(); },
      cloneContents() { return document.createDocumentFragment(); },
      insertNode(n) { if (start && start.appendChild) start.appendChild(n); },
      surroundContents() {},
      isPointInRange() { return false; },
      comparePoint() { return 0; },
      intersectsNode() { return false; },
    });
    return r;
  };
  Document.prototype.createRange = function createRange() { return __range(); };

  // The interface shape table puts its own `src` reflector on
  // `HTMLImageElement.prototype`, overriding ours (which issues the request).
  // Put the real one back.
  try {
    const IP = globalThis.HTMLImageElement && globalThis.HTMLImageElement.prototype;
    if (IP) {
      Object.defineProperty(IP, 'src', {
        get() { return this.__ptUrlAttr ? this.__ptUrlAttr('src') : (__ptGetA(this, 'src') || ''); },
        set(v) {
          __ptSetA(this, 'src', v);
          if (this.__ptLoadImage) this.__ptLoadImage(true);
        },
        enumerable: true, configurable: true,
      });
      Object.defineProperty(IP, 'currentSrc', {
        get: (globalThis.__pt_native || ((f) => f))(Object.getOwnPropertyDescriptor({ get currentSrc() { return this.__ptCurSrc || ''; } }, 'currentSrc').get),
        set: undefined, enumerable: true, configurable: true,
      });
    }
  } catch (e) {}

  // `new Image()` is a factory, like `Audio`: Chrome returns a real `<img>`, so
  // `img.src = …` must go to the network.
  // Strict: the browser's factory has no own `arguments`/`caller`.
  const __ptImageCtor = (function () {
    'use strict';
    return function Image(w, h) {
      const O = globalThis.__pt_orig;
      const el = O && O.createElement
        ? O.createElement.call(document, 'img')
        : document.createElement('img');
      if (w !== undefined) __ptSetAttr.call(el, 'width', String(w | 0));
      if (h !== undefined) __ptSetAttr.call(el, 'height', String(h | 0));
      return el;
    };
  })();
  try {
    Object.defineProperty(globalThis, 'Image', { value: __ptImageCtor, writable: true, enumerable: false, configurable: true });
    Object.defineProperty(globalThis.Image, 'prototype', {
      value: globalThis.HTMLImageElement ? globalThis.HTMLImageElement.prototype : Object.prototype,
      writable: false, enumerable: false, configurable: false,
    });
  } catch (e) {}

  // `new Audio()` is a factory, not its own interface: Chrome returns an
  // HTMLAudioElement, and `Object.prototype.toString` says so.
  globalThis.Audio = (function () {
    'use strict';
    return function Audio(src) {
      const O = globalThis.__pt_orig;
      const el = O && O.createElement
        ? O.createElement.call(document, 'audio')
        : document.createElement('audio');
      if (src !== undefined) __ptSetAttr.call(el, 'src', String(src));
      return el;
    };
  })();
  try {
    Object.defineProperty(globalThis.Audio, 'prototype', {
      value: globalThis.HTMLAudioElement ? globalThis.HTMLAudioElement.prototype : Object.prototype,
      writable: false, enumerable: false, configurable: false,
    });
  } catch (e) {}

  globalThis.MutationObserver = MutationObserver;
  globalThis.ResizeObserver = ResizeObserver;

  // Each element names its interface (`[object HTMLCanvasElement]`). There are
  // no per-tag classes, so the name is derived from the tag.
  const __tagFor = (el) => {
    const local = el.__ptLocal || '';
    if (TAG_IFACE[local]) return TAG_IFACE[local];
    // A dashed name is a custom element (HTMLElement); an unknown single-word
    // tag is HTMLUnknownElement.
    return __s_indexOf(local, '-') > 0 || PLAIN_TAGS.has(local) ? 'HTMLElement' : 'HTMLUnknownElement';
  };
  for (const [C, name] of [[Node, 'Node'], [Element, 'Element'], [Text, 'Text'], [Comment, 'Comment'],
    [CharacterData, 'CharacterData'], [ProcessingInstruction, 'ProcessingInstruction'],
    [Document, 'Document'], [DocumentFragment, 'DocumentFragment'], [ShadowRoot, 'ShadowRoot']]) {
    if (!C) continue;
    try {
      // The prototype itself gets its own name (`[object Element]`), instances
      // the tag's interface name.
      Object.defineProperty(C.prototype, Symbol.toStringTag, name
        ? { value: name, configurable: true }
        : { get: function () { if (this === C.prototype) return C === Element ? 'Element' : 'Node'; return this.__ptType === ELEMENT_NODE ? __tagFor(this) : 'Node'; }, configurable: true });
    } catch (e) {}
  }

  // ChildNode: `after`, `before`, `replaceWith` — on elements they were
  // name-only stubs that did nothing, so a page that moved nodes with them
  // (jQuery's `replaceWith` falls through to them in places) kept its DOM as is.
  // Strings become text nodes; the anchor is the nearest sibling not among the
  // nodes being inserted, as the DOM standard's "viable sibling" rule says.
  const __asNodes = (ns) => ns.map((n) => (typeof n === 'string' ? new Text(n) : n));
  const __childIface = (n) => (n.__ptType === ELEMENT_NODE ? 'Element' : 'CharacterData');
  const __afterSelf = function after(...ns) {
    const p = this.__ptParent; if (!p) return;
    __needNoneAncestor(p, ns, 'after', __childIface(this));
    let ref = this.nextSibling; while (ref && __s_includes(ns, ref)) ref = ref.nextSibling;
    for (const n of __asNodes(ns)) p.insertBefore(n, ref);
  };
  const __beforeSelf = function before(...ns) {
    const p = this.__ptParent; if (!p) return;
    __needNoneAncestor(p, ns, 'before', __childIface(this));
    let prev = this.previousSibling; while (prev && __s_includes(ns, prev)) prev = prev.previousSibling;
    const ref = prev ? prev.nextSibling : p.firstChild;
    for (const n of __asNodes(ns)) p.insertBefore(n, ref);
  };
  const __replaceSelf = function replaceWith(...ns) {
    const p = this.__ptParent; if (!p) return;
    __needNoneAncestor(p, ns, 'replaceWith', __childIface(this));
    let ref = this.nextSibling; while (ref && __s_includes(ns, ref)) ref = ref.nextSibling;
    const nodes = __asNodes(ns);
    if (this.__ptParent === p && !__s_includes(nodes, this)) p.removeChild(this);
    for (const n of nodes) p.insertBefore(n, ref);
  };
  for (const C of [Element, CharacterData]) {
    Object.defineProperty(C.prototype, 'remove', { value: __removeSelf, writable: true, configurable: true });
    Object.defineProperty(C.prototype, 'after', { value: __afterSelf, writable: true, configurable: true });
    Object.defineProperty(C.prototype, 'before', { value: __beforeSelf, writable: true, configurable: true });
    Object.defineProperty(C.prototype, 'replaceWith', { value: __replaceSelf, writable: true, configurable: true });
  }

  // Now that every interface exists, publish their members the way the platform
  // does — enumerable on the prototype (see `__webidl` above).
  for (const name of ['Node', 'Element', 'HTMLElement', 'Document', 'Text', 'Comment',
    'DocumentFragment', 'ShadowRoot', 'Event', 'UIEvent', 'MouseEvent', 'PointerEvent',
    'KeyboardEvent', 'InputEvent', 'FocusEvent', 'MessageEvent', 'CustomEvent',
    'MutationObserver', 'ResizeObserver', 'IntersectionObserver', 'NodeFilter',
    'TreeWalker', 'NodeIterator', 'DOMTokenList', 'NamedNodeMap', 'Attr',
    'HTMLCollection', 'NodeList', 'CSSStyleDeclaration', 'DOMRect', 'Worker',
    'XMLHttpRequest', 'EventTarget', 'Blob', 'File', 'FileReader', 'FormData',
    'Headers', 'Request', 'Response', 'URL', 'URLSearchParams', 'ReadableStream',
    'WritableStream', 'TransformStream', 'BroadcastChannel', 'MessageChannel',
    'MessagePort', 'AbortController', 'AbortSignal', 'DOMException']) {
    __webidl(globalThis[name]);
  }

  // Tags that render nothing must take no space in layout, or frame content
  // shifts and hits land on <style> instead of a button.
  const __UNRENDERED = new Set(['HEAD', 'META', 'STYLE', 'SCRIPT', 'LINK', 'TITLE',
    'BASE', 'NOSCRIPT', 'TEMPLATE', 'PARAM', 'SOURCE', 'TRACK']);

  // No box at all: `display: none` and what is never laid out. Not the same
  // as invisible: `visibility: hidden` takes space and has a real rect.
  function __isUnboxed(el) {
    if (__UNRENDERED.has(el.__ptTag)) return true;
    if (__cascadeHides(el, false)) return true;
    if (el.hasAttribute && __ptHasA(el, 'hidden')) return true;
    // A hidden input takes no space, nor a line.
    if (el.__ptTag === 'INPUT' && /^hidden$/i.test(__ptGetA(el, 'type') || '')) return true;
    // The inline declarations straight from the engine's map: the page-facing
    // `style.display` goes through brand checks, and asking for `style`
    // built a declaration object for every element laid out.
    const m = __inlineDecls(el);
    if (m) { const d = m.get('display'); if (d != null && __s_toLowerCase(__s_trim(String(d))) === 'none') return true; }
    return false;
  }
  // An element's inline style as the engine's raw map, or null when it has
  // none (no `style` attribute and the page never touched `.style`).
  // Without `.style` touched it is the attribute parsed, not a declaration
  // object (700 own properties) built for the engine's eyes only.
  function __inlineDecls(el) {
    const s = el.__ptStyle;
    if (!s) {
      const t = el.__ptAttrs ? el.__ptAttrs.get('style') : undefined;
      return t === undefined ? null : __styleTextMap(t);
    }
    const raw = __declRaw.get(s);
    return raw ? raw() : null;
  }

  function __isHiddenEl(el) {
    if (__isUnboxed(el)) return true;
    if (__cascadeHides(el, true)) return true;
    const s = el.style;
    if (s) {
      const v = __s_toLowerCase(String(s.visibility || ''));
      if (v === 'hidden' || v === 'collapse') return true;
    }
    return false;
  }

  // Cascade: selectors are matched, specificity computed, and declarations
  // applied in increasing weight.
  const __SPEC_ATTR = /\[[^\]]*\]/g;
  function __specificity(sel) {
    const list = __selCompiled(sel);
    if (list && list.length === 1) {
      const [a, b, c] = list[0].spec;
      return a * 10000 + b * 100 + c;
    }
    const s = __s_replace(String(sel), __SPEC_ATTR, '[]');
    const ids = (__s_match(s, /#[\w-]+/g) || []).length;
    const cls = (__s_match(s, /\.[\w-]+|\[\]|:(?!:)[a-zA-Z-]+/g) || []).length;
    const tags = (__s_match(s, /(?:^|[\s>+~])([a-zA-Z][\w-]*)/g) || []).length
               + (__s_match(s, /::[\w-]+/g) || []).length;
    return ids * 10000 + cls * 100 + tags;
  }

  // @media: only viewport width and height are evaluated; anything else
  // answers "no" rather than guessing.
  function __mediaApplies(cond) {
    const c = __s_trim(__s_toLowerCase(String(cond || '')));
    if (!c || c === 'all' || c === 'screen') return true;
    if (/print|speech/.test(c)) return false;
    if (/prefers-color-scheme:\s*dark/.test(c)) return false;
    if (/prefers-reduced-motion:\s*reduce/.test(c)) return false;
    let ok = true;
    const px = (v) => parseFloat(v) || 0;
    for (const m of c.matchAll(/\((min|max)-(width|height):\s*([\d.]+)px\)/g)) {
      const have = m[2] === 'width' ? LAYOUT.W : LAYOUT.H;
      ok = ok && (m[1] === 'min' ? have >= px(m[3]) : have <= px(m[3]));
    }
    return ok;
  }

  let __rules = [];                       // {root, sel, spec, order, style}
  let __foreignRules = new WeakMap();     // document -> its rules
  let __styleCache = new WeakMap();
  // Cascades are kept from one layout pass to the next and dropped only where
  // a mutation can change them, as browsers invalidate style: recomputing all
  // of them after every class toggle made a page's layout passes allocate
  // ~25 MB each. A mutation at a node drops the subtree of its parent (the
  // node, its siblings for `+`/`~`, and everything below: inheritance and
  // custom properties flow down). Focus, the URL fragment and custom element
  // definitions are compared at each pass and drop everything when changed.
  // Cascades that a form control's state can change (`:checked`, `:invalid`...),
  // those below them, and another document's live for one pass only.
  let __stylePass = new WeakMap();
  let __styleVolatile = new WeakSet();
  let __styleTouched = [];
  let __styleAllStale = true;
  let __styleRulesSeen = null;
  // What the mutations since the last style pass touched, for `:has()`:
  // inserted and removed subtrees, attribute names with old and new values.
  // A `:has()` whose argument none of them could match keeps its anchors'
  // styles (Blink does the same with its invalidation sets).
  const __hasMut = { any: false, nodes: [], attrs: [] };
  function __hasNoteTree(n) {
    __formNoteTree(n);
    if (__hasMut.any || !n) return;
    if (__hasMut.nodes.length >= 256) { __hasMut.any = true; __hasMut.nodes = []; return; }
    __hasMut.nodes.push(n);
  }
  function __hasNoteAttr(name, oldV, newV) {
    __formNoteAttr(name);
    if (__hasMut.any) return;
    if (__hasMut.attrs.length >= 256) { __hasMut.any = true; __hasMut.attrs = []; return; }
    __hasMut.attrs.push([__s_toLowerCase(String(name)), oldV == null ? null : String(oldV), newV == null ? null : String(newV)]);
  }
  const __attrTest = (sel, v) => {
    if (v == null) return false;
    const want = sel.value;
    if (sel.op == null) return true;
    const a = sel.i ? __s_toLowerCase(v) : v, b = sel.i ? __s_toLowerCase(want) : want;
    switch (sel.op) {
      case '=': return a === b;
      case '~=': return __s_split(a, /\s+/).includes(b);
      case '|=': return a === b || __s_slice(a, 0, b.length + 1) === b + '-';
      case '^=': return !!b && __s_slice(a, 0, b.length) === b;
      case '$=': return !!b && __s_slice(a, a.length - b.length) === b;
      case '*=': return !!b && __s_indexOf(a, b) >= 0;
      default: return true;
    }
  };
  // Whether the recorded mutations can change any `:has()` result.
  function __hasMutRelevant(A) {
    const M = __hasMut;
    if (M.any || !A || A.any) return true;
    if (A.sibling && M.nodes.length) return true;
    const elemHits = (e) => {
      if (A.tags.size && A.tags.has(__s_toLowerCase(String(e.__ptLocal || '')))) return true;
      const id = __ptGetA(e, 'id');
      if (id && A.ids.has(id)) return true;
      if (A.classes.size) { const set = __ptClassSet(e); if (set) for (const c of set) if (A.classes.has(c)) return true; }
      if (A.attrs.length && e.__ptAttrs) {
        for (const sel of A.attrs) { const v = e.__ptAttrs.get(sel.name); if (v !== undefined && __attrTest(sel, v)) return true; }
      }
      return false;
    };
    let budget = 20000;
    for (const n of M.nodes) {
      const stack = [n];
      while (stack.length) {
        const e = stack.pop();
        if (--budget < 0) return true;
        if (e.__ptType === ELEMENT_NODE && elemHits(e)) return true;
        const kids = e.__ptKids;
        if (kids) for (const k of kids) if (k.__ptType === ELEMENT_NODE || k.__ptType === 11) stack.push(k);
      }
    }
    for (const [name, oldV, newV] of M.attrs) {
      if (name === 'class') {
        const a = new Set(__s_split(oldV || '', /\s+/)), b = new Set(__s_split(newV || '', /\s+/));
        for (const c of a) if (c && !b.has(c) && A.classes.has(c)) return true;
        for (const c of b) if (c && !a.has(c) && A.classes.has(c)) return true;
      }
      if (name === 'id' && ((oldV && A.ids.has(oldV)) || (newV && A.ids.has(newV)))) return true;
      for (const sel of A.attrs) if (sel.name === name && __attrTest(sel, oldV) !== __attrTest(sel, newV)) return true;
    }
    return false;
  }
  // A node's own change: its subtree, and the siblings after it when a rule
  // read across siblings (their subtrees too when the read was left of a
  // subject).
  function __styleTouch(node) {
    if (!node) return;
    __stylePush(node);
    __sibsAfter(node);
  }
  function __sibsAfter(node) {
    const up = node.__ptParent, f = up ? __kidDeps.get(up) | 0 : 0;
    if (!(f & 2)) return;
    const kids = up.__ptKids, i = __s_indexOf(kids, node);
    if (kids.length - i > 65) { __stylePush(up); return; }
    for (let k = i + 1; k < kids.length; k++) {
      if (kids[k].__ptType !== ELEMENT_NODE) continue;
      if (f & 16) __styleDeep(kids[k]); else __styleSelfPush(kids[k]);
    }
  }
  function __stylePush(root) {
    if (__styleAllStale) return;
    if (__styleTouched.length >= 2000) { __styleAllStale = true; __styleTouched = []; return; }
    __styleTouched.push(root);
  }
  // Nodes a change reached without restyling anything: `:has()` still looks
  // at their ancestors.
  let __styleSeeds = [], __styleSeedsLost = false;
  // Elements whose own matching changed but nothing below them through
  // selectors: cascaded again at the next pass, subtree kept unless the
  // result differs (Blink's local vs subtree style change).
  let __styleSelf = [];
  function __styleSelfPush(e) {
    if (__styleAllStale) return;
    if (__styleSelf.length >= 50000) { __styleAllStale = true; __styleSelf = []; return; }
    __styleSelf.push(e);
  }
  function __styleSeed(node) {
    if (__styleSeedsLost) return;
    if (__styleSeeds.length >= 2000) { __styleSeedsLost = true; __styleSeeds = []; return; }
    __styleSeeds.push(node);
  }
  // A child inserted or removed at `at` (-1: all of them went): the new
  // child's subtree; the siblings after it when a rule counted positions from
  // the start or read earlier siblings, those before it when one counted
  // from the end (appending to `<body>` restyles nothing else under
  // `:first-child` rules); the parent when a rule read whether it is empty.
  function __styleTouchKids(p, child, at) {
    if (__styleAllStale || !p) return;
    const f = __kidDeps.get(p) | 0;
    if (f & 64) { __stylePush(p); return; }
    // Its emptiness: the parent itself and the siblings reading it.
    if (f & 4) { __styleSelfPush(p); __sibsAfter(p); }
    const kids = p.__ptKids || [];
    if (at >= 0 && (f & 11)) {
      let lo = kids.length, hi = 0;
      if (f & 3) { lo = Math.min(lo, child ? at + 1 : at); hi = kids.length; }
      if (f & 8) { lo = 0; hi = Math.max(hi, at); }
      if (hi - lo > 64) { __stylePush(p); return; }
      for (let k = lo; k < hi; k++) {
        const e = kids[k];
        if (e.__ptType !== ELEMENT_NODE || e === child) continue;
        if (f & 16) __styleDeep(e); else __styleSelfPush(e);
      }
    }
    if (child && child.__ptType === ELEMENT_NODE && child.__ptParent === p) __stylePush(child);
    __styleSeed(p);
  }
  // An attribute change restyles nothing when no rule names it: a class, an
  // id or a data-* attribute (no rule reads those except by selector).
  function __styleTouchAttr(el, name, oldV, newV) {
    if (__styleAllStale) return;
    if ((oldV == null ? null : oldV) === (newV == null ? null : newV) || __attrInert(el, name, oldV, newV)) { __styleSeed(el); return; }
    if (name === 'class' && __classChange(el, oldV, newV)) return;
    __styleTouch(el);
  }
  // A class change: the element itself when a rule names the class in its
  // subject, and below it only the elements keyed like the rules that name
  // it further left (`.client-js .x` restyles the `.x`, not all of <html>;
  // Wikipedia flips classes on <html> while loading). False when that cannot
  // be told: a sibling rule, a rule with no key, another document.
  function __classChange(el, oldV, newV) {
    if (el.__ptDoc !== globalThis.document) return false;
    const X = __ruleClassIndex(__rules);
    if (!X) return false;
    const a = oldV ? __s_split(oldV, __CLASS_WS) : [], b = newV ? __s_split(newV, __CLASS_WS) : [];
    let self = false;
    const keys = new Set();
    const one = (c) => {
      if (!c) return true;
      const v = X.get(c);
      if (v === undefined) return true;
      if (v.sib || v.any) return false;
      if (v.self) self = true;
      for (const k of v.keys) keys.add(k);
      return true;
    };
    for (const c of a) if (__s_indexOf(b, c) < 0 && !one(c)) return false;
    for (const c of b) if (__s_indexOf(a, c) < 0 && !one(c)) return false;
    if (self) __styleSelfPush(el);
    else __styleSeed(el);
    __sibsAfter(el);
    if (keys.size) {
      const de = __docElement(globalThis.document);
      const under = __elementsWithKeys(el, keys, true, de);
      // Most of the subtree: dropping it is as cheap.
      if (under.length * 2 > under.seen) { __styleTouch(el); return true; }
      for (const e of under) if (e !== el) __styleSelfPush(e);
    }
    return true;
  }
  // A rule's selector without a trailing `::before`/`::after`, its compounds
  // at depth 0 and the combinator after each.
  function __ruleCompounds(r) {
    const pm = __PSEUDO_TAIL.exec(r.sel);
    const sel = pm ? (__s_trim(pm[1]) || '*') : String(r.sel);
    const parts = [], combs = [];
    let depth = 0, q = null, start = 0;
    for (let i = 0; i < sel.length; i++) {
      const c = sel[i];
      if (c === '\\') { i++; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (depth === 0 && (c === ' ' || c === '>' || c === '+' || c === '~')) {
        let j = i, comb = ' ';
        while (j < sel.length && (sel[j] === ' ' || sel[j] === '>' || sel[j] === '+' || sel[j] === '~')) { if (sel[j] !== ' ') comb = sel[j]; j++; }
        if (i > start) { parts.push(__s_slice(sel, start, i)); combs.push(comb); }
        start = j; i = j - 1;
      }
    }
    parts.push(__s_slice(sel, start));
    return { sel, parts, combs };
  }
  // Keys of the subjects of rules that read a position or a sibling left of
  // their subject (`li:first-child a`, `.a + div p`); `any` when one has no
  // key. An element whose position changed restyles itself and the elements
  // below it with these keys, not its whole subtree (jQuery's feature test
  // appends a <div> to <html>, and <body> stops being the last child).
  const __POS_PSEUDO = /:(?:first|last|only|nth)-|:empty\b/i;
  function __rulePosIndex(rules) {
    if (rules.__ptPosIx !== undefined) return rules.__ptPosIx;
    const X = { any: false, keys: new Set() };
    for (const r of rules) {
      const { sel, parts, combs } = __ruleCompounds(r);
      const last = parts.length - 1;
      let hit = false;
      for (let k = 0; k < last && !hit; k++) if (__POS_PSEUDO.test(parts[k]) || ((combs[k] === '+' || combs[k] === '~') && k + 1 < last)) hit = true;
      if (!hit && __s_indexOf(sel, ':has(') >= 0 && /[+~]|:(?:first|last|only|nth)-|:empty/i.test(sel)) hit = true;
      if (!hit) continue;
      const key = __ruleKey(sel);
      if (key == null) { X.any = true; break; }
      if (typeof key === 'string') X.keys.add(key); else for (const x of key) X.keys.add(x);
    }
    Object.defineProperty(rules, '__ptPosIx', { value: X, configurable: true, enumerable: false });
    return X;
  }
  // A sibling whose position or neighbours changed and below which a rule
  // read that.
  function __styleDeep(e) {
    const X = e.__ptDoc === globalThis.document ? __rulePosIndex(__rules) : null;
    if (!X || X.any) { __stylePush(e); return; }
    __styleSelfPush(e);
    if (!X.keys.size) return;
    const under = __elementsWithKeys(e, X.keys, true, __docElement(globalThis.document));
    if (under.length * 2 > under.seen) { __stylePush(e); return; }
    for (const u of under) if (u !== e) __styleSelfPush(u);
  }
  // Per class: whether a rule names it in its subject compound (`self`),
  // the keys of the subjects of rules naming it further left (`keys`), and
  // whether one names it before a sibling combinator (`sib`) or has a
  // subject with no key (`any`).
  function __ruleClassIndex(rules) {
    if (rules.__ptClassIx !== undefined) return rules.__ptClassIx;
    const X = new Map();
    const at = (c) => { let v = X.get(c); if (!v) X.set(c, (v = { self: false, sib: false, any: false, keys: new Set() })); return v; };
    for (const r of rules) {
      const { sel, parts, combs } = __ruleCompounds(r);
      const last = parts.length - 1;
      let key;
      for (let k = 0; k <= last; k++) {
        const found = new Set();
        __featScan(__FEAT_CLS, parts[k], found, false);
        if (!found.size) continue;
        let sib = false;
        for (let m = k; m < last; m++) if (combs[m] === '+' || combs[m] === '~') { sib = true; break; }
        for (const c of found) {
          const v = at(c);
          if (k === last) { v.self = true; continue; }
          if (sib) { v.sib = true; continue; }
          if (key === undefined) key = __ruleKey(sel);
          if (key == null) v.any = true;
          else if (typeof key === 'string') v.keys.add(key);
          else for (const x of key) v.keys.add(x);
        }
      }
    }
    Object.defineProperty(rules, '__ptClassIx', { value: X, configurable: true, enumerable: false });
    return X;
  }
  const __CLASS_WS = /[\t\n\f\r ]+/;
  function __attrInert(el, name, oldV, newV) {
    if (el.__ptDoc !== globalThis.document) return false;
    const isData = __s_slice(name, 0, 5) === 'data-';
    if (name !== 'class' && name !== 'id' && !isData) return false;
    const F = __ruleFeatures(__rules);
    if (F.any) return false;
    if (isData) return !F.attrs.has(name);
    if (name === 'id') return !(oldV && F.ids.has(oldV)) && !(newV && F.ids.has(newV));
    if (F.attrs.has('class')) return false;
    const a = oldV ? __s_split(oldV, __CLASS_WS) : [], b = newV ? __s_split(newV, __CLASS_WS) : [];
    for (const c of a) if (c && F.cls.has(c) && __s_indexOf(b, c) < 0) return false;
    for (const c of b) if (c && F.cls.has(c) && __s_indexOf(a, c) < 0) return false;
    return true;
  }
  // Every class, id and attribute name the rules mention anywhere in a
  // selector (`:not()`, `:has()` and `:is()` included), escapes decoded
  // (`.md\:flex`). A name may be collected that is none (inside an attribute
  // value), never missed.
  const __FEAT_NAME = '((?:[-_a-zA-Z0-9\\u0080-\\uffff]|\\\\[0-9a-fA-F]{1,6}[ \\t\\n\\f\\r]?|\\\\[^\\n\\r\\f0-9a-fA-F])+)';
  const __FEAT_CLS = new RegExp('\\.' + __FEAT_NAME, 'g');
  const __FEAT_ID = new RegExp('#' + __FEAT_NAME, 'g');
  const __FEAT_ATTR = new RegExp('\\[\\s*(?:[^\\]|=\\s]*\\|)?' + __FEAT_NAME, 'g');
  const __FEAT_ESC = /\\(?:([0-9a-fA-F]{1,6})[ \t\n\f\r]?|([^\n\r\f0-9a-fA-F]))/g;
  const __featUnescape = (t) => (__s_indexOf(t, '\\') < 0 ? t : __s_replace(t, __FEAT_ESC, (m, hex, ch) => {
    if (ch !== undefined) return ch;
    const c = parseInt(hex, 16);
    return c === 0 || c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff) ? '\ufffd' : String.fromCodePoint(c);
  }));
  const __featScan = (re, t, into, low) => {
    re.lastIndex = 0;
    for (let m = re.exec(t); m; m = re.exec(t)) {
      const v = __featUnescape(m[1]);
      into.add(low ? __s_toLowerCase(v) : v);
    }
  };
  function __ruleFeatures(rules) {
    if (rules.__ptFeat) return rules.__ptFeat;
    const F = { any: false, cls: new Set(), ids: new Set(), attrs: new Set() };
    for (const r of rules) {
      const t = String(r.sel);
      __featScan(__FEAT_CLS, t, F.cls, false);
      __featScan(__FEAT_ID, t, F.ids, false);
      __featScan(__FEAT_ATTR, t, F.attrs, true);
    }
    Object.defineProperty(rules, '__ptFeat', { value: F, configurable: true, enumerable: false });
    return F;
  }
  const __STATE_PSEUDO = /:(checked|indeterminate|valid|invalid|user-valid|user-invalid|in-range|out-of-range|placeholder-shown)\b/i;
  let __styleWorld = '';
  let __styleDefined = 0;
  let __styleActive = null;
  // At the start of a pass: drop what mutations since the last one reached.
  // What a new rule list changes, as Blink's rule-set invalidation: the keys
  // (see `__ruleKey`) of the rules added or dropped. Only elements carrying
  // one of them (and their subtrees) can cascade differently. Null when that
  // cannot be bounded: a rule with no key or with `:has()`, or rules that stay
  // but change their relative order (a sheet added before them declaring
  // layers). Entries that stay take over the parsed selector.
  function __rulesChanged(old, cur) {
    if (!old || !old.length) return null;
    const byRule = new Map();
    for (const r of old) {
      const l = byRule.get(r.rule);
      if (l) l.push(r); else byRule.set(r.rule, [r]);
    }
    const keys = new Set(), kept = [], probe = [];
    const docEl = __docElement(globalThis.document);
    const note = (r) => {
      // `::before`/`::after` restyle their element (their images load with
      // it); other rules that never match here change nothing.
      const pm = __PSEUDO_TAIL.exec(r.sel);
      if (!pm && !__ruleLive(r)) return true;
      const sel = pm ? (__s_trim(pm[1]) || '*') : r.sel;
      // The key is the subject's, `:has()` or not: the cascade looks the
      // rule up by it.
      const k = __ruleKey(sel);
      if (k != null) {
        if (typeof k === 'string') keys.add(k); else for (const x of k) keys.add(x);
        return true;
      }
      // No key (`.a > *`): the elements it matches now, in the document only;
      // an unkeyed `:has()` could search every subtree.
      if (r.root !== docEl || probe.length >= 32 || __s_indexOf(sel, ':has(') >= 0) return false;
      const list = __selCompiled(sel);
      if (!list) return false;
      probe.push(list);
      return true;
    };
    for (const r of cur) {
      const l = byRule.get(r.rule);
      let was = null;
      if (l) for (let i = 0; i < l.length; i++) if (l[i] && l[i].sel === r.sel) { was = l[i]; l[i] = null; break; }
      if (!was) { if (!note(r)) return null; continue; }
      if (was.__ptSel !== undefined) r.__ptSel = was.__ptSel;
      if (was.__ptVol !== undefined) r.__ptVol = was.__ptVol;
      if (was.__ptNever !== undefined) r.__ptNever = was.__ptNever;
      if (was.__ptSens !== undefined) r.__ptSens = was.__ptSens;
      kept.push(was, r);
    }
    for (const l of byRule.values()) for (const r of l) if (r && !note(r)) return null;
    // Kept rules in their old cascade order must still be in order.
    const idx = [];
    for (let i = 0; i < kept.length; i += 2) idx.push(i);
    idx.sort((a, b) => (kept[a].layer - kept[b].layer) || (kept[a].order - kept[b].order));
    for (let i = 1; i < idx.length; i++) {
      const p = kept[idx[i - 1] + 1], q = kept[idx[i] + 1];
      if ((p.layer - q.layer || p.order - q.order) >= 0) return null;
    }
    if (probe.length) keys.__ptProbe = probe;
    return keys;
  }
  // Elements carrying any of `keys` or matching a selector of `keys.__ptProbe`,
  // in the document and its shadow trees.
  // With `every`, each such element, nested ones too; else the topmost (a
  // dropped element takes its subtree along).
  function __elementsWithKeys(de, keys, every, docRoot) {
    const out = [];
    let attrs = false;
    for (const k of keys) if (k[0] === 'a') { attrs = true; break; }
    const probe = keys.__ptProbe;
    const has = (e) => {
      if (probe) for (let i = 0; i < probe.length; i++) { try { if (__selAny(probe[i], e, __CASCADE_CTX)) return true; } catch (x) { return true; } }
      if (keys.has('t' + __s_toLowerCase(String(e.__ptLocal || '')))) return true;
      if (e === (docRoot || de) && keys.has('r')) return true;
      const id = __ptGetA(e, 'id');
      if (id && keys.has('i' + id)) return true;
      const set = __ptClassSet(e);
      if (set) for (const c of set) if (keys.has('c' + c)) return true;
      if (attrs && e.__ptAttrs) for (const name of e.__ptAttrs.keys()) if (keys.has('a' + __s_toLowerCase(String(name)))) return true;
      return false;
    };
    let seen = 0;
    // A matched element's subtree only with `every`; a shadow tree before
    // the children. No stack frame per level.
    const walk = (n) => {
      const st = [n.__ptKids || __NO_NODES, 0];
      while (st.length) {
        const top = st.length - 2;
        const kids = st[top], i = st[top + 1];
        if (i >= kids.length) { st.length = top; continue; }
        st[top + 1] = i + 1;
        const k = kids[i];
        if (k.__ptType !== ELEMENT_NODE) continue;
        seen++;
        if (has(k)) { out.push(k); if (!every) continue; }
        st.push(k.__ptKids || __NO_NODES, 0);
        if (k.__ptShadow) st.push(k.__ptShadow.__ptKids || __NO_NODES, 0);
      }
    };
    const top = has(de);
    if (top) out.push(de);
    if (!top || every) { if (de.__ptShadow) walk(de.__ptShadow); walk(de); }
    out.seen = seen + 1;
    return out;
  }

  // 0 when no rule reads `:defined`, 2 when one also reads siblings or
  // `:has()`, else 1.
  function __readsDefined(rules) {
    if (!rules) return 2;
    if (rules.__ptDefined === undefined) {
      let v = 0;
      for (const r of rules) {
        const t = __s_toLowerCase(String(r.sel));
        if (__s_indexOf(t, ':defined') < 0) continue;
        v = 1;
        if (__s_indexOf(t, ':has(') >= 0 || /[+~]/.test(__s_replace(t, /\[[^\]]*\]/g, ''))) { v = 2; break; }
      }
      rules.__ptDefined = v;
    }
    return rules.__ptDefined;
  }
  // Whether a focus change can restyle more than the element and its subtree.
  function __focusReach(rules) {
    if (!rules) return true;
    if (rules.__ptFocusReach !== undefined) return rules.__ptFocusReach;
    let far = false;
    for (const r of rules) {
      const t = String(r.sel);
      if (__s_indexOf(t, ':focus') < 0) continue;
      if (/:focus-within|:has\(/i.test(t)) { far = true; break; }
      // Any sibling combinator, even one inside `:not()` or an An+B.
      if (/[+~]/.test(__s_replace(t, /\[[^\]]*\]/g, ''))) { far = true; break; }
    }
    rules.__ptFocusReach = far;
    return far;
  }
  function __styleRevalidate() {
    __stylePass = new WeakMap();
    __shareMap = new WeakMap();
    __styleVolatile = new WeakSet();
    const why = (k) => { __lstats['stale_' + k] = (__lstats['stale_' + k] | 0) + 1; };
    let ruleRoots = null;
    if (__styleRulesSeen !== __rules && !__styleAllStale) {
      const keys = __rulesChanged(__styleRulesSeen, __rules);
      const de = globalThis.document && globalThis.document.documentElement;
      if (!keys || !de) { __styleAllStale = true; why('rules'); }
      else { why('rulesKeyed'); if (keys.size || keys.__ptProbe) ruleRoots = __elementsWithKeys(de, keys, true); }
    } else if (__styleRulesSeen !== __rules) why('rules');
    const HA = __rules && __rules.__ptHas;
    const seeds = __styleSeeds, seedsLost = __styleSeedsLost;
    __styleSeeds = []; __styleSeedsLost = false;
    const selves = __styleSelf;
    __styleSelf = [];
    if (selves.length) ruleRoots = ruleRoots ? ruleRoots.concat(selves) : selves;
    let H = HA && (__styleTouched.length || seeds.length || seedsLost || selves.length) && !__styleAllStale ? __hasEffective(HA) : null;
    if (H && seedsLost) H = { any: true };
    __hasMut.any = false; __hasMut.nodes = []; __hasMut.attrs = [];
    if (H) {
      if (H.any) { __styleAllStale = true; why('hasAny'); }
      else {
        const anchors = new Set();
        // Previous element siblings: the nearest for `+`, all for `~`. A walk
        // stops at a sibling an earlier one saw (everything before it was
        // seen too), so each parent's children are read once per pass. By
        // the engine's child lists, not `previousElementSibling`.
        const sibSeen = new Set();
        const sibOf = (a) => {
          const up = a.__ptParent, kids = up && up.__ptKids;
          if (!kids) return;
          for (let i = kids.indexOf(a) - 1; i >= 0; i--) {
            const p = kids[i];
            if (p.__ptType !== ELEMENT_NODE) continue;
            if (H.tilde) { if (sibSeen.has(p)) return; sibSeen.add(p); }
            if (!anchors.has(p) && __hasAnchorMatch(p, H.sib)) anchors.add(p);
            if (!H.tilde) return;
          }
        };
        if (H.parentAny) {
          for (const r of __styleTouched.slice()) {
            const p = r && r.__ptParent;
            if (p && p.__ptType === ELEMENT_NODE) anchors.add(p);
          }
          for (const r of seeds.concat(selves)) {
            if (r.__ptType === ELEMENT_NODE) anchors.add(r);
            const p = r.__ptParent;
            if (p && p.__ptType === ELEMENT_NODE) anchors.add(p);
          }
        }
        for (const r of __styleTouched.concat(seeds, selves)) {
          for (let a = r; a && a.__ptType === ELEMENT_NODE; a = a.__ptParent) {
            if (!anchors.has(a) && __hasAnchorMatch(a, H)) anchors.add(a);
            if (H.hasSib) sibOf(a);
          }
        }
        // An anchor whose siblings were read restyles them too.
        for (const a of anchors) { __styleTouched.push(a); __sibsAfter(a); }
      }
    }
    if (__styleSelf.length) { ruleRoots = ruleRoots ? ruleRoots.concat(__styleSelf) : __styleSelf; __styleSelf = []; }
    const doc = globalThis.document;
    let hash = '';
    try { hash = String(globalThis.location && globalThis.location.hash || ''); } catch (e) {}
    const world = hash;
    if (world !== __styleWorld) { __styleAllStale = true; why('world'); }
    else if (doc && doc.__ptActive !== __styleActive) {
      // Only the elements losing and gaining focus restyle (with what they
      // hold), unless a rule reads focus from a sibling, a descendant or
      // `:has()`.
      if (__focusReach(__rules) || __styleAllStale) { __styleAllStale = true; why('focus'); }
      else {
        why('focusKeyed');
        for (const e of [__styleActive, doc.__ptActive]) if (e && e.__ptType === ELEMENT_NODE && e.__ptDoc === doc) __styleTouched.push(e);
      }
    }
    // A definition changes style only through `:defined`: the elements of
    // the new names restyle, or all when such a rule reads siblings or
    // `:has()`.
    const nDefined = __customs.size;
    if (nDefined !== __styleDefined && !__styleAllStale && __readsDefined(__rules)) {
      const de = doc && doc.documentElement;
      if (!de || nDefined < __styleDefined || __readsDefined(__rules) === 2) { __styleAllStale = true; why('defined'); }
      else {
        const keys = new Set();
        let i = 0;
        for (const n of __customs.keys()) if (i++ >= __styleDefined) keys.add('t' + n);
        for (const e of __elementsWithKeys(de, keys)) __styleTouched.push(e);
      }
    }
    __styleDefined = nDefined;
    __styleWorld = world;
    __styleActive = doc ? doc.__ptActive : null;
    __styleRulesSeen = __rules;
    if (__styleAllStale) {
      __lstats.allStale++;
      __styleCache = new WeakMap();
      __styleTouched = [];
      __styleAllStale = false;
      __layoutAllDirty = true;
      return null;
    }
    const drop = (root) => {
      const st = [root];
      while (st.length) {
        const n = st.pop();
        __lstats.dropped++;
        __styleCache.delete(n);
        __layoutMemo.delete(n);
        for (const k of (n.__ptKids || __NO_NODES)) if (k.__ptType === ELEMENT_NODE) st.push(k);
        if (n.__ptShadow) for (const k of (n.__ptShadow.__ptKids || __NO_NODES)) if (k.__ptType === ELEMENT_NODE) st.push(k);
      }
    };
    const roots = __styleTouched;
    for (const r of roots) { drop(r); if (!__layoutAllDirty) __layoutDirty.push(r); }
    __styleTouched = [];
    // A changed rule changes what its subject elements match, nothing below
    // them except through inheritance (`inherit`, `var()`, inherited
    // properties read off the ancestors). Each is cascaded again at once;
    // its subtree is dropped only when the result differs (Blink stops a
    // recalc the same way when the inherited values did not change).
    if (ruleRoots) {
      const gone = new Set(roots);
      const under = (e) => { for (let a = e; a; a = a.__ptParent || a.__ptHost || null) if (gone.has(a)) return true; return false; };
      const kidsOf = (x) => (x.__ptShadow ? __s_slice(x.__ptKids || []).concat(x.__ptShadow.__ptKids || []) : (x.__ptKids || []));
      // Below a changed cascade: kept layouts go, and so do the inherited
      // values each kept cascade remembered (`__ptInh`).
      const layoutDown = (x) => {
        for (const k of kidsOf(x)) {
          if (k.__ptType !== ELEMENT_NODE) continue;
          __layoutMemo.delete(k);
          const c = __styleCache.get(k);
          if (c !== undefined && c.__ptInh) c.__ptInh.clear();
          layoutDown(k);
        }
      };
      // A cascade came out different (`entries`) or with other variables
      // (`vars`, a `:root { --x }` rule): the cascades below are kept unless
      // they copy a parent value (`inherit`) or read variables; those are
      // recomputed, and so on down. Computed styles and kept layouts below
      // go, since inherited values may differ (Wikipedia flips classes on
      // <html> that restyle it; each dropped all 10,000 cascades).
      const changed = (x, old, now) => {
        const ent = !__cascadeEntriesSame(old, now), vars = !__varsSame(old, now);
        if (ent) {
          __styleGen++;
          __layoutMemo.delete(x);
          layoutDown(x);
          if (!__layoutAllDirty) __layoutDirty.push(x);
        }
        if (ent || vars) down(x, now.__ptVars, vars, ent);
      };
      const down = (x, vars, varsCh, entCh) => {
        for (const k of kidsOf(x)) {
          if (k.__ptType !== ELEMENT_NODE) continue;
          const c = __styleCache.get(k);
          if (c === undefined) continue;
          if (!((entCh && __inheritReaders.has(c)) || (varsCh && __varReaders.has(c)))) {
            if (varsCh) { c.__ptVars = vars; down(k, vars, true, false); }
            continue;
          }
          __styleCache.delete(k);
          const now = __cascadeFor(k);
          if (__styleCache.get(k) !== now) { drop(k); gone.add(k); if (!__layoutAllDirty) __layoutDirty.push(k); continue; }
          changed(k, c, now);
        }
      };
      for (const e of ruleRoots) {
        const old = __styleCache.get(e);
        if (old !== undefined) {
          __styleCache.delete(e);
          const now = __cascadeFor(e);
          // State-dependent now: its subtree follows it every pass.
          if (__styleCache.get(e) === now) { changed(e, old, now); continue; }
        } else if (under(e)) continue;
        drop(e);
        gone.add(e);
        if (!__layoutAllDirty) __layoutDirty.push(e);
      }
    }
    return roots;
  }
  // Bumped when a cascade changed and those below it were kept: computed
  // styles built from inherited values are rebuilt.
  let __styleGen = 0;
  // Cascades that copy a parent value with `inherit`.
  const __inheritReaders = new WeakSet();
  // Cascades that substitute `var()` or set their own variables: the ones a
  // change of inherited variables can change.
  const __varReaders = new WeakSet();
  function __cascadeEntriesSame(a, b) {
    if (a === b) return true;
    if (a.size !== b.size) return false;
    for (const [k, v] of a) if (b.get(k) !== v) return false;
    return true;
  }
  function __cascadeSame(a, b) {
    if (!__cascadeEntriesSame(a, b)) return false;
    return __varsSame(a, b);
  }
  function __varsSame(a, b) {
    // Variables chain to the parent's: the same parent object and the same
    // own values, or counted as changed (GitHub has thousands at the root;
    // walking the chain per element cost seconds).
    const x = a.__ptVars, y = b.__ptVars;
    if (x === y) return true;
    if (!x || !y || Object.getPrototypeOf(x) !== Object.getPrototypeOf(y)) return false;
    const kx = Object.keys(x), ky = Object.keys(y);
    if (kx.length !== ky.length) return false;
    for (const k of kx) if (x[k] !== y[k] || !Object.prototype.hasOwnProperty.call(y, k)) return false;
    return true;
  }
  // Font size and inherited values walk the ancestors and are asked many
  // times per pass; cache them for the cascade's lifetime.
  let __passFont = new WeakMap();
  let __passFold = new WeakMap();
  let __passCustom = new WeakMap();
  // Hidden by the cascade: `display: none`, or with `invisible` also
  // `visibility: hidden`/`collapse`. Read off the element's cascade, which is
  // kept until a mutation reaches it, so it costs nothing a style pass would
  // not pay anyway.
  function __cascadeHides(el, invisible) {
    const c = __cascadeFor(el);
    const d = c.get('display');
    if (d != null && __s_toLowerCase(__s_trim(String(d))) === 'none') return true;
    if (!invisible) return false;
    const v = c.get('visibility');
    if (v == null) return false;
    const t = __s_toLowerCase(__s_trim(String(v)));
    return t === 'hidden' || t === 'collapse';
  }

  // Rules of one tree: its stylesheets flattened into a list. Separate because
  // there can be more than one document (see `__rulesFor`).
  // Layer rank of rules outside any layer: above every layer.
  const __UNLAYERED = 1e9;
  // A style rule's selector list split, with specificities, as (sel, spec)
  // runs. Every added sheet regathers all rules; this keeps it to a lookup.
  const __selPartsOf = new WeakMap();
  function __selParts(r, selText) {
    const hit = __selPartsOf.get(r);
    if (hit !== undefined && hit.__ptText === selText) return hit;
    const out = [];
    for (const one of __selSplit(selText)) {
      const sel = __s_trim(one);
      if (!sel) continue;
      out.push(sel, __specificity(sel));
    }
    const parts = out.slice();
    parts.__ptText = selText;
    __selPartsOf.set(r, parts);
    return parts;
  }
  function __gatherRules(docEl, out) {
    const state = { order: out.length, anon: 0 };
    const faces = [];
    // Cascade layers in the order they are first named (a statement, a block
    // or an import); a nested one is `outer.inner`.
    const layers = new Map();
    const layerOf = (outer, name) => {
      const full = outer ? outer + '.' + name : name;
      if (!layers.has(full)) layers.set(full, layers.size);
      return full;
    };
    const take = (root, rules, layer) => {
      for (const r of rules || []) {
        const st = __cssom.get(r);
        if (!st) continue;
        const kind = st.kind;
        if (kind === 'font-face') { if (root === docEl) faces.push(r); continue; }
        if (kind === 'import') {
          const sub = __sheetRules(st.styleSheet);
          const into = st.layer == null ? layer : layerOf(layer, st.layer || ('\u0000' + (state.anon++)));
          const mt = st.media.mediaText;
          if (sub && (!mt || __mediaApplies(mt))) take(root, sub, into);
          continue;
        }
        if (kind === 'media' || kind === 'supports') {
          if (kind !== 'media' || __mediaApplies(st.cond)) take(root, st.kids, layer);
          continue;
        }
        if (kind === 'layer-statement') { for (const n of st.names) layerOf(layer, n); continue; }   // @layer a, b;
        if (kind === 'layer-block') {                 // @layer a { … }
          take(root, st.kids, layerOf(layer, st.name || ('\u0000' + (state.anon++))));
          continue;
        }
        if (kind !== 'style') continue;
        const selText = __ruleSel(st);
        if (!selText) continue;
        const rank = layer == null ? __UNLAYERED : layers.get(layer);
        const parts = __selParts(r, selText);
        for (let i = 0; i < parts.length; i += 2) {
          out.push({ root, sel: parts[i], spec: parts[i + 1], order: state.order++, rule: r, layer: rank });
        }
      }
    };
    const sheetsOf = (node, root) => {
      for (const n of (node.__ptKids || [])) {
        if (n.__ptType !== ELEMENT_NODE) continue;
        if ((n.tagName === 'STYLE' || (n.tagName === 'LINK' && n.__ptSheetText)) && n.sheet) {
          // `<link media="print">` is fetched but styles nothing on screen.
          const media = __ptGetA(n, 'media');
          if (!media || __mediaApplies(media)) take(root, __sheetRules(n.sheet), null);
        }
        if (n.__ptShadow) sheetsOf(n.__ptShadow, n.__ptShadow);
        sheetsOf(n, root);
      }
    };
    sheetsOf(docEl, docEl);
    out.faces = faces;
    return out;
  }

  // Whose rules apply to this element. A page may create another document
  // (`createHTMLDocument()`, DOMParser) and read computed style there; the
  // host page's styles do not reach it and Chrome answers with defaults. The
  // challenge captures the whole enumerated style.
  /// Rule key from the rightmost compound: id, class or tag. The cascade only
  /// checks rules with matching keys, as browsers do; matching all ~3000
  /// chess.com rules against every element cost ~100 ms per relayout.
  function __ruleKey(sel) {
    let depth = 0, q = null, start = 0;
    for (let i = 0; i < sel.length; i++) {
      const c = sel[i];
      if (c === '\\') { i++; continue; }
      if (q) { if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '(' || c === '[') depth++;
      else if (c === ')' || c === ']') depth--;
      else if (depth === 0 && (c === ' ' || c === '>' || c === '+' || c === '~' || c === '\t' || c === '\n')) start = i + 1;
    }
    const comp = __s_slice(sel, start);
    let flat = '';
    depth = 0;
    for (const c of comp) {
      if (c === '(' || c === '[') { depth++; continue; }
      if (c === ')' || c === ']') { depth--; continue; }
      if (depth === 0) flat += c;
    }
    if (__s_indexOf(flat, '\\') >= 0) return null;
    // `:is(.a, .b)` / `:where(…)` with nothing else to key on: each
    // alternative's key, when every one has one (a rule then sits in each).
    if (/^:(?:is|where)(?::|$)/i.test(flat)) {
      const open = __s_indexOf(comp, '(');
      let d = 0, from = open + 1;
      const alts = [];
      for (let i = open; i < comp.length; i++) {
        const c = comp[i];
        if (c === '\\') { i++; continue; }
        if (c === '(' || c === '[') d++;
        else if (c === ')' || c === ']') { d--; if (d === 0) { alts.push(__s_slice(comp, from, i)); break; } }
        else if (c === ',' && d === 1) { alts.push(__s_slice(comp, from, i)); from = i + 1; }
      }
      const keys = [];
      for (const a of alts) {
        const k = __ruleKey(__s_trim(a));
        if (k == null) return null;
        if (typeof k === 'string') { if (!keys.includes(k)) keys.push(k); }
        else for (const x of k) if (!keys.includes(x)) keys.push(x);
      }
      return keys.length === 1 ? keys[0] : keys.length ? keys : null;
    }
    let m = /#([\w-]+)/.exec(flat);
    if (m) return 'i' + m[1];
    m = /\.([\w-]+)/.exec(flat);
    if (m) return 'c' + m[1];
    m = /^([a-zA-Z][\w-]*)/.exec(flat);
    if (m) return 't' + __s_toLowerCase(m[1]);
    // `:root` (custom property blocks are mostly this) matches one element.
    if (/^:root(?![\w-])/i.test(flat)) return 'r';
    // Only an attribute test (`[data-theme=dark]`): keyed by the attribute's
    // name, so it is tried on elements that have that attribute, not on all.
    m = /^\[\s*([a-zA-Z_][\w-]*)\s*(?:[~|^$*]?=|\])/.exec(comp);
    // Whatever follows (`:not(…)`, more attributes), an element without the
    // first attribute cannot match.
    if (m) return 'a' + __s_toLowerCase(m[1]);
    return null;
  }
  const __ruleIndexes = new WeakMap();
  function __ruleIndex(rules) {
    let ix = __ruleIndexes.get(rules);
    if (ix && ix.n === rules.length) return ix;
    // `scoped`: some rule belongs to a shadow tree; without one every rule
    // applies to every element of the document and no filtering is needed.
    ix = { n: rules.length, keyed: new Map(), any: [], scoped: false, multi: false };
    const put = (k, r) => {
      if (k[0] === 'a') ix.attrs = true;
      let list = ix.keyed.get(k);
      if (!list) ix.keyed.set(k, (list = []));
      list.push(r);
    };
    for (const r of rules) {
      if (r.root && r.root.__ptType === 11) ix.scoped = true;
      const k = __ruleKey(r.sel);
      if (k == null) ix.any.push(r);
      else if (typeof k === 'string') put(k, r);
      else { ix.multi = true; for (const x of k) put(x, r); }
    }
    // Buckets at their length: a pushed-to array keeps room for 17 entries.
    for (const [k, l] of ix.keyed) ix.keyed.set(k, l.slice());
    ix.any = ix.any.slice();
    __ruleIndexes.set(rules, ix);
    return ix;
  }
  /// Rules that may match an element.
  // Tree root of an element: a shadow root or the document element.
  // Stylesheets apply only within their tree (in Chrome a div in a shadow root
  // does not see the page's `.x{display:flex}`).
  function __treeRootOf(el) {
    let n = el;
    while (n) {
      const p = n.__ptParent;
      if (!p) return n.__ptType === 11 && n.__ptHost ? n : (n.ownerDocument && n.ownerDocument.documentElement) || n;
      if (p.__ptType === 11 && p.__ptHost) return p;
      n = p;
    }
    return null;
  }
  // A rule that can never match an element here (a pseudo-element, a state
  // this engine never has, an unparsable selector) is no candidate. Decided
  // on first use and kept on the rule.
  const __ruleLive = (r) => {
    if (r.__ptNever === undefined) {
      if (r.__ptSel === undefined) r.__ptSel = __selCompiled(r.sel) || null;
      let never = !r.__ptSel;
      if (!never) { never = true; for (const cx of r.__ptSel) if (!cx.never) { never = false; break; } }
      r.__ptNever = never;
    }
    return !r.__ptNever;
  };
  function __candidateRules(el) {
    const ix = __ruleIndex(__rulesFor(el.__ptDoc));
    const root = __treeRootOf(el);
    const docEl = __docElement(el.__ptDoc);
    const inScope = (r) => !r.root || r.root === root || (root === docEl && r.root === docEl) || (root && root.__ptType !== 11 && r.root && r.root.__ptType !== 11);
    // A rule under several keys is taken once (`:is(.a, .b)` on `.a.b`).
    const all = !ix.scoped && !!root && root.__ptType !== 11;
    const id = __ptGetA(el, 'id');
    const cls = __ptGetA(el, 'class');
    // Elements alike in tag, id, classes and attribute names have the same
    // candidates (a list's thousand items cost one lookup). Read-only list.
    let memoKey = null;
    if (all) {
      memoKey = (el === docEl ? 'R' : '') + el.__ptLocal + '\x00' + (id || '') + '\x00' + (cls || '');
      if (ix.attrs && el.__ptAttrs) for (const name of el.__ptAttrs.keys()) memoKey += '\x00' + name;
      const hit = ix.memo && ix.memo.get(memoKey);
      if (hit) return hit;
    }
    const out = all ? ix.any.filter(__ruleLive) : ix.any.filter((r) => inScope(r) && __ruleLive(r));
    const once = ix.multi ? new Set() : null;
    const add = (k) => {
      const l = ix.keyed.get(k);
      if (!l) return;
      for (let i = 0; i < l.length; i++) {
        const r = l[i];
        if (!all && !inScope(r)) continue;
        if (!__ruleLive(r)) continue;
        if (once) { if (once.has(r)) continue; once.add(r); }
        out.push(r);
      }
    };
    if (el === docEl) add('r');
    add('t' + __s_toLowerCase(String(el.__ptLocal || '')));
    if (id) add('i' + id);
    if (cls) {
      const seen = new Set();
      for (const c of __s_split(cls, /[\t\n\f\r ]+/)) if (c && !seen.has(c)) { seen.add(c); add('c' + c); }
    }
    if (ix.attrs && el.__ptAttrs) for (const name of el.__ptAttrs.keys()) add('a' + __s_toLowerCase(String(name)));
    if (memoKey !== null) {
      if (!ix.memo || ix.memo.size >= 4096) ix.memo = new Map();
      const keep = out.slice();
      keep.__ptSig = memoKey;
      ix.memo.set(memoKey, keep);
      return keep;
    }
    return out;
  }

  /// A rule's declarations as written.
  function __ruleMap(rr) {
    const st = rr.rule && __cssom.get(rr.rule);
    return st ? __ruleDecls(st) : null;
  }

  function __rulesFor(doc) {
    if (!doc || doc === globalThis.document) return __rules;
    let hit = __foreignRules.get(doc);
    if (hit) return hit;
    hit = doc.documentElement ? __gatherRules(doc.documentElement, []) : [];
    __foreignRules.set(doc, hit);
    return hit;
  }

  // A `url()` computes to an absolute address, resolved against the sheet
  // that declared it (a linked or imported sheet's own URL, else the
  // document's base); the sheet is also the referrer when it is fetched.
  const __cssAbsMemo = new Map();
  const __cssUrlRef = new Map();
  const __CSS_URL = /url\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))\s*\)/g;
  function __cssAbs(v, rule) {
    if (__s_indexOf(v, 'url(') < 0) return v;
    const rst = rule && __cssom.get(rule);
    const href = rst ? __sheetHref(rst.sheet) : null;
    const base = href || String(document.baseURI || '');
    const key = base + '\n' + v;
    let hit = __cssAbsMemo.get(key);
    if (hit !== undefined) return hit;
    hit = __s_replace(v, __CSS_URL, (m, a, b, c) => {
      const raw = a !== undefined ? a : b !== undefined ? b : c;
      // Fragment-only references (`url(#clip)`) point into the document.
      if (!raw || __s_charCodeAt(raw, 0) === 35) return m;
      let abs;
      try { abs = new URL(raw, base).href; } catch (e) { return m; }
      if (href) __cssUrlRef.set(abs, href);
      return 'url("' + abs + '")';
    });
    if (__cssAbsMemo.size > 4096) __cssAbsMemo.clear();
    __cssAbsMemo.set(key, hit);
    return hit;
  }

  // What Chrome requests as it styles the page: background images of
  // rendered elements (not under `display: none`). Read off each element's
  // cascade, which the engine keeps per element until a mutation reaches it,
  // so a second pass only looks at what changed.
  let __cssScanAt = -1;
  let __cssScanSeen = new WeakMap();
  // `::before` / `::after` boxes exist when their `content` is not none; a
  // background of one is fetched then (measured in Chrome 151). Only rules
  // that can take part are indexed, keyed like the cascade, and only when one
  // of them carries an image.
  let __pseudoFrom = null, __pseudoIx = null;
  const __PSEUDO_TAIL = /^(.*?)::?(before|after)\s*$/i;
  function __pseudoIndex(rules) {
    if (__pseudoFrom === rules) return __pseudoIx;
    const keyed = new Map(), any = [];
    let images = false;
    for (const r of rules) {
      const m = __PSEUDO_TAIL.exec(r.sel);
      if (!m) continue;
      const d = __ruleMap(r);
      if (!d) continue;
      let bg = d.get('background-image');
      if (bg == null) { const sh = d.get('background'); if (sh != null) bg = sh; }
      const content = d.get('content');
      if (bg == null && content == null) continue;
      if (bg != null && __s_indexOf(String(bg), 'url(') >= 0) images = true;
      const base = __s_trim(m[1]) || '*';
      const entry = { r, sel: base, which: __s_toLowerCase(m[2]), bg: bg == null ? null : __cssAbs(String(bg), r.rule),
                      content: content == null ? null : __s_trim(String(content)) };
      const k = __ruleKey(base);
      if (typeof k !== 'string') any.push(entry);
      else { let l = keyed.get(k); if (!l) keyed.set(k, (l = [])); l.push(entry); }
    }
    __pseudoFrom = rules;
    __pseudoIx = images ? { keyed, any } : null;
    return __pseudoIx;
  }
  function __pseudoImages(e, ix, de) {
    const hits = [];
    const test = (x) => {
      try {
        if (x.__ptSel === undefined) x.__ptSel = __selCompiled(x.sel) || null;
        if (x.__ptSel && __bloomMayMatch(x.__ptSel, __ancBloom(e)) && __selAny(x.__ptSel, e, __CASCADE_CTX)) hits.push(x);
      } catch (err) {}
    };
    for (const x of ix.any) test(x);
    const by = (k) => { const l = ix.keyed.get(k); if (l) for (const x of l) test(x); };
    if (e === de) by('r');
    by('t' + __s_toLowerCase(String(e.__ptLocal || '')));
    const id = __ptGetA(e, 'id');
    if (id) by('i' + id);
    const set = __ptClassSet(e);
    if (set) for (const c of set) if (c) by('c' + c);
    if (e.__ptAttrs) for (const name of e.__ptAttrs.keys()) by('a' + __s_toLowerCase(String(name)));
    if (!hits.length) return;
    hits.sort((a, b) => (a.r.layer - b.r.layer) || (a.r.spec - b.r.spec) || (a.r.order - b.r.order));
    for (const which of ['before', 'after']) {
      let content = null, bg = null;
      for (const x of hits) {
        if (x.which !== which) continue;
        if (x.content != null) content = x.content;
        if (x.bg != null) bg = x.bg;
      }
      if (content == null || bg == null || /^(none|normal)$/i.test(content)) continue;
      __cssImagesOf(new Map([['background-image', bg]]));
    }
  }

  function __cssImagesOf(cs) {
    const v = cs.get('background-image');
    if (v == null || __s_indexOf(String(v), 'url(') < 0) return;
    // `image-set()` offers alternatives; a 1x screen takes the first.
    const out = [];
    for (const part of __ptCssParts(String(v))) {
      __CSS_URL.lastIndex = 0;
      if (/^(-webkit-)?image-set\(/i.test(part)) {
        const m = __CSS_URL.exec(part);
        if (m) out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
        continue;
      }
      let m;
      while ((m = __CSS_URL.exec(part))) out.push(m[1] !== undefined ? m[1] : m[2] !== undefined ? m[2] : m[3]);
    }
    __CSS_URL.lastIndex = 0;
    for (const u of out) {
      if (!u || !/^https?:/i.test(u) || __imageSkipped(u)) continue;
      if (globalThis.__pt_subresourceDone && __pt_subresourceDone(u)) continue;
      const rel = __holdLoad('css-image ' + u);
      __pt_subresource(u, 'css-image', __cssUrlRef.get(u) || null).then(rel, rel);
    }
  }

  // The document's `@font-face` rules as the FontFace objects `document.fonts`
  // holds, one per rule for the rule's life.
  const __faceOfRule = new WeakMap();
  let __facesFrom = null, __facesList = [];
  const __unquote = (v) => __s_replace(__s_trim(String(v)), /^(["'])(.*)\1$/, '$2');
  function __cssFaces() {
    const de = globalThis.document && document.documentElement;
    if (!de || typeof globalThis.__pt_cssFontFace !== 'function') return [];
    const hit = __gatherRulesCached(de);
    if (__facesFrom === hit) return __facesList;
    const out = [];
    for (const rule of hit.faces || []) {
      let face = __faceOfRule.get(rule);
      if (!face) {
        const m = __ruleMap({ rule });
        const family = m && m.get('font-family');
        const src = m && m.get('src');
        if (family == null || src == null) continue;
        const href = __sheetHref(__cssom.get(rule).sheet);
        const desc = {};
        for (const [k, css] of [['style', 'font-style'], ['weight', 'font-weight'], ['stretch', 'font-stretch'],
          ['unicodeRange', 'unicode-range'], ['variant', 'font-variant'], ['featureSettings', 'font-feature-settings'],
          ['variationSettings', 'font-variation-settings'], ['display', 'font-display'], ['ascentOverride', 'ascent-override'],
          ['descentOverride', 'descent-override'], ['lineGapOverride', 'line-gap-override'], ['sizeAdjust', 'size-adjust']]) {
          const v = m.get(css);
          if (v != null) desc[k] = __s_trim(String(v));
        }
        face = __pt_cssFontFace(__unquote(family), String(src), desc, href || String(document.baseURI || ''), href);
        __faceOfRule.set(rule, face);
      }
      out.push(face);
    }
    __facesFrom = hit;
    __facesList = out;
    return out;
  }
  Object.defineProperty(globalThis, '__pt_cssFaces', { value: __cssFaces, configurable: true, enumerable: false });
  // Parse the document's sheets, which starts their imports (a body sheet's
  // imports hold `DOMContentLoaded`). Styling, and with it CSS images and
  // fonts, comes after.
  globalThis.__pt_cssSheets = () => {
    const de = globalThis.document && document.documentElement;
    if (de) __gatherRulesCached(de);
  };

  // Which face a family list asks for: the first family that is a declared
  // face, unless a family before it is installed (the browser stops there).
  const __GENERIC = new Set(['serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui', 'emoji', 'math',
    'fangsong', 'ui-serif', 'ui-sans-serif', 'ui-monospace', 'ui-rounded']);
  // Without the font files (a build without `render`), the families Chrome 151
  // finds on the Linux profile, measured: the canvas substitution table.
  const __PROFILE_FAMILIES = new Set(['sans-serif', 'serif', 'monospace', 'system-ui', 'arial', 'helvetica',
    'times new roman', 'times', 'courier new', 'courier', 'liberation sans', 'liberation serif', 'liberation mono',
    'dejavu sans', 'dejavu serif', 'dejavu sans mono', 'noto sans mono', 'arimo', 'tinos', 'cousine', 'cantarell']);
  const __familyHere = new Map();
  function __familyInstalled(name, quoted) {
    const low = __s_toLowerCase(name);
    // A quoted generic is a family name nobody has.
    if (quoted && __GENERIC.has(low)) return false;
    let hit = __familyHere.get(low);
    if (hit === undefined) {
      hit = typeof globalThis.__pt_fontFamily === 'function' ? !!__pt_fontFamily(low) : __PROFILE_FAMILIES.has(low);
      __familyHere.set(low, hit);
    }
    return hit;
  }
  const __familyLists = new Map();
  function __familyList(v) {
    let hit = __familyLists.get(v);
    if (hit) return hit;
    hit = [];
    for (const raw of __s_split(String(v), ',')) {
      const t = __s_trim(raw);
      if (!t) continue;
      const quoted = /^["']/.test(t);
      hit.push([__s_toLowerCase(__unquote(t)), quoted]);
    }
    if (__familyLists.size > 2048) __familyLists.clear();
    __familyLists.set(v, hit);
    return hit;
  }
  // Faces of one family for this style and weight, as Chrome's matching picks
  // them: same style first, then the nearest weight.
  function __facesFor(byFamily, fam, italic, weight) {
    const list = byFamily.get(fam);
    if (!list || list.length < 2) return list || null;
    const want = italic ? 'italic' : 'normal';
    let pool = list.filter((x) => (/italic|oblique/.test(x.style) ? 'italic' : 'normal') === want);
    if (!pool.length) pool = list;
    let best = null, bestD = Infinity;
    for (const x of pool) { const d = Math.abs(x.weight - weight); if (d < bestD) { bestD = d; best = x.weight; } }
    return pool.filter((x) => x.weight === best);
  }
  const __WEIGHT = { normal: 400, bold: 700, lighter: 100, bolder: 900 };
  const __weightOf = (v) => { const t = __s_toLowerCase(__s_trim(String(v || 'normal'))); return __WEIGHT[t] || parseFloat(t) || 400; };
  // The face's `unicode-range` against the characters it would draw.
  function __rangeHits(range, text) {
    if (!range || /^u\+0-10ffff$/i.test(range)) return true;
    const spans = [];
    for (const part of __s_split(range, ',')) {
      const m = /^\s*u\+([0-9a-f?]+)(?:-([0-9a-f]+))?\s*$/i.exec(part);
      if (!m) continue;
      if (__s_indexOf(m[1], '?') >= 0) spans.push([parseInt(__s_replace(m[1], /\?/g, '0'), 16), parseInt(__s_replace(m[1], /\?/g, 'f'), 16)]);
      else spans.push([parseInt(m[1], 16), parseInt(m[2] || m[1], 16)]);
    }
    for (const ch of text) {
      const c = ch.codePointAt(0);
      for (const [a, b] of spans) if (c >= a && c <= b) return true;
    }
    return false;
  }
  // The element's own text, the characters its font draws.
  function __ownText(e) {
    let t = '';
    for (const k of (e.__ptKids || [])) if (k.__ptType === TEXT_NODE) t += k.data;
    return __s_trim(t);
  }

  // The engine calls this on every turn of its loop and after animation
  // frames; a pass runs only when the tree changed, and at most every
  // max(100 ms, 4x its last cost) unless `force` (the look before `load`).
  const __perfNow = globalThis.performance && typeof performance.now === 'function'
    ? performance.now.bind(performance) : Date.now;
  let __cssScanNext = 0;
  const __fontHeld = new WeakSet();
  globalThis.__pt_cssLoads = (force) => {
    const doc = globalThis.document;
    const de = doc && doc.documentElement;
    if (!de || !__rendered || typeof globalThis.__pt_subresource !== 'function') return;
    const at = __layoutSeq + ':' + LAYOUT.W + 'x' + LAYOUT.H;
    if (__cssScanAt === at) return;
    const t0 = __perfNow();
    if (!force && t0 < __cssScanNext) return;
    __cssScanAt = at;
    __styleBegin();
    // Web fonts still waiting for text that uses them. Measured in Chrome 151:
    // a face is requested when a rendered element's family list reaches it
    // (text or not); it holds `load` when it is the first family and the
    // element has text to draw.
    // Every face takes part in matching (a family already loading still ends
    // the list); the walk runs only while one is still unloaded.
    let byFamily = null, unloaded = false;
    const info = globalThis.__pt_faceInfo;
    for (const face of __cssFaces()) {
      const o = info && info(face);
      if (!o) continue;
      if (o.status === 'unloaded') unloaded = true;
      const fam = __s_toLowerCase(o.family);
      if (!byFamily) byFamily = new Map();
      let l = byFamily.get(fam);
      if (!l) byFamily.set(fam, (l = []));
      l.push({ face, style: __s_toLowerCase(o.style), weight: __weightOf(o.weight), range: o.unicodeRange });
    }
    if (!unloaded) byFamily = null;
    const fontsOf = (e, fams, italic, weight) => {
      for (let i = 0; i < fams.length; i++) {
        const [name, quoted] = fams[i];
        const faces = __facesFor(byFamily, name, italic, weight);
        if (faces) {
          const text = __ownText(e);
          for (const x of faces) {
            if (x.range && !/^u\+0-10ffff$/i.test(x.range) && !__rangeHits(x.range, text)) continue;
            const p = __pt_faceLoad(x.face);
            const st2 = info && info(x.face);
            // One hold per face, however many elements wait for it.
            if (i === 0 && text && st2 && st2.status === 'loading' && !__fontHeld.has(x.face)) {
              __fontHeld.add(x.face);
              const rel = __holdLoad('font ' + name);
              p.then(rel, rel);
            }
          }
          return;
        }
        if (__familyInstalled(name, quoted)) return;
      }
    };
    // Inherited font state rides along the walk: family list, italic, weight.
    const ROOT_FAMILY = __familyList('Times New Roman');
    const seen = __cssScanSeen;
    const pseudo = __pseudoIndex(__rules);
    const els = [de], famS = [ROOT_FAMILY], itS = [false], wS = [400];
    __lstats.cssScans++;
    while (els.length) {
      const e = els.pop(), pf = famS.pop(), pi = itS.pop(), pw = wS.pop();
      __lstats.cssScanEls++;
      if (__isUnboxed(e)) continue;
      const cs = __cascadeFor(e);
      if (seen.get(e) !== cs) {
        seen.set(e, cs);
        __cssImagesOf(cs);
        if (pseudo) __pseudoImages(e, pseudo, de);
      }
      let fams = pf, italic = pi, weight = pw;
      if (byFamily) {
        const f = cs.get('font-family');
        if (f != null) fams = __familyList(f);
        const st = cs.get('font-style');
        if (st != null) italic = /italic|oblique/i.test(String(st));
        const w = cs.get('font-weight');
        const tag = e.__ptLocal;
        if (w != null) {
          const t = __s_toLowerCase(__s_trim(String(w)));
          weight = t === 'bolder' ? (pw < 350 ? 400 : pw < 550 ? 700 : 900)
            : t === 'lighter' ? (pw < 550 ? 100 : pw < 750 ? 400 : 700) : __weightOf(t);
        } else if (tag === 'b' || tag === 'strong' || tag === 'th' || /^h[1-6]$/.test(tag)) {
          weight = pw < 550 ? 700 : 900;   // UA sheet: bolder
        }
        if (st == null && (tag === 'i' || tag === 'em' || tag === 'cite' || tag === 'var' || tag === 'address')) italic = true;
        fontsOf(e, fams, italic, weight);
      }
      const kids = e.__ptKids;
      if (kids) {
        for (let i = kids.length - 1; i >= 0; i--) {
          if (kids[i].__ptType !== ELEMENT_NODE) continue;
          els.push(kids[i]); famS.push(fams); itS.push(italic); wS.push(weight);
        }
      }
    }
    __lstats.cssScanMs += __perfNow() - t0;
    __cssScanNext = __perfNow() + Math.max(100, 4 * (__perfNow() - t0));
  };
  // Start of a style pass: the rule list, per-pass caches, and the cascades a
  // mutation reached dropped. Once per tree state and viewport (media rules
  // follow the viewport).
  let __styleAt = -1, __styleW = -1, __styleH = -1;
  function __styleBegin() {
    const d0 = globalThis.document;
    // A focus change restyles without a tree change (`input:focus`).
    if (__styleAt === __layoutSeq && __styleW === LAYOUT.W && __styleH === LAYOUT.H && (!d0 || d0.__ptActive === __styleActive)) return;
    __styleAt = __layoutSeq; __styleW = LAYOUT.W; __styleH = LAYOUT.H;
    __rules = [];
    __passBloom = new WeakMap();
    __passFont = new WeakMap();
    __passFold = new WeakMap();
    __passCustom = new WeakMap();
    __foreignRules = new WeakMap();
    const doc = globalThis.document;
    if (!doc || !doc.documentElement) return;
    __rules = __gatherRulesCached(doc.documentElement);
    __styleRevalidate();
  }

  // What a mutation can change through `:has()`: the elements the `:has()`
  // is attached to ("anchors") are ancestors of the mutated node. From each
  // rule the compound right before `:has(` gives the anchor's tag, classes
  // and id; a mutation then drops the cascades of the matching ancestors
  // (and their subtrees), as Blink's :has invalidation does. An anchor with
  // nothing to key on, a sibling `:has(+ …)`/`:has(~ …)`, or `:has` nested in
  // another pseudo-class falls back to dropping everything, still only when
  // something changed. Null when no rule uses `:has()`.
  function __hasAnchors(rules) {
    let found = false;
    // `sib`: anchors of `:has(+ …)`/`:has(~ …)`, which a change reaches
    // through their following siblings; `tilde` when any is `~`.
    // One item per `:has()` compound: where its anchors are (keys, sibling or
    // parent reach, or anywhere) and what its argument matches on. Each style
    // pass keeps only the items a recorded mutation can reach
    // (`__hasEffective`).
    const items = [];
    let H = null;
    // What a `:has()` argument can match on, all its compounds: a mutation
    // that touches none of these keys cannot change the result. Focus and
    // hover come through the focus/hover paths; any other pseudo-class, a
    // compound with nothing to key on, or a nested selector list makes any
    // mutation count.
    const STATE_OK = /^:(focus|focus-visible|focus-within|hover|active|visited|link|any-link)$/i;
    const newArg = () => ({ any: false, sibling: false, tags: new Set(), classes: new Set(), ids: new Set(), attrs: [] });
    const noteArg = (A, arg) => {
      if (A.any) return;
      if (/[+~]/.test(__s_replace(__s_replace(arg, /\[[^\]]*\]/g, ''), /\([^()]*\)/g, ''))) A.sibling = true;
      for (const [, comp] of compounds(__s_trim(__s_replace(arg, /^\s*[>+~]\s*/, '')))) {
        let rest = comp, keyed = false;
        rest = __s_replace(rest, /\[\s*([\w-]+)\s*(?:([~|^$*]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]*))\s*(i|s)?)?\s*\]/gi,
          (m, name, op, q1, q2, bare, flag) => {
            A.attrs.push({ name: __s_toLowerCase(name), op: op || null, value: q1 != null ? q1 : q2 != null ? q2 : (bare || ''), i: flag === 'i' || flag === 'I' });
            keyed = true; return '';
          });
        rest = __s_replace(rest, /#([\w-]+)/g, (m, id) => { A.ids.add(id); keyed = true; return ''; });
        rest = __s_replace(rest, /\.([\w-]+)/g, (m, c) => { A.classes.add(c); keyed = true; return ''; });
        rest = __s_replace(rest, /^([a-zA-Z][\w-]*)/, (m, t) => { A.tags.add(__s_toLowerCase(t)); keyed = true; return ''; });
        rest = __s_replace(rest, /:[\w-]+(?!\()/g, (m) => (STATE_OK.test(m) ? '' : m));
        if (__s_trim(rest) !== '' || !keyed) { A.any = true; return; }
      }
    };
    const hasArgs = (A, text) => {
      const low = __s_toLowerCase(text);
      let at = 0;
      for (;;) {
        const i = __s_indexOf(low, ':has(', at);
        if (i < 0) return;
        let d = 1, j = i + 5;
        for (; j < text.length && d; j++) { if (text[j] === '(') d++; else if (text[j] === ')') d--; }
        const arg = __s_slice(text, i + 5, j - 1);
        for (const one of __s_split(arg, /,(?![^()]*\))/)) noteArg(A, one);
        at = j;
      }
    };
    // A compound's keys: its id, else a class, else its tag. Parentheses
    // (`:has(…)`, `:not(…)`) are not looked into, except a leading
    // `:is()`/`:where()`: the element matches one of its alternatives, so the
    // key of each alternative's last compound (all of them, or none).
    const keyOf = (compound, depth) => {
      let flat = '', d = 0;
      for (const ch of compound) { if (ch === '(' || ch === '[') d++; else if (ch === ')' || ch === ']') d--; else if (d === 0) flat += ch; }
      const id = /#([\w-]+)/.exec(flat); if (id) return [['ids', id[1]]];
      const cl = /\.([\w-]+)/.exec(flat); if (cl) return [['classes', cl[1]]];
      const tg = /^([a-zA-Z][\w-]*)/.exec(flat); if (tg) return [['tags', __s_toLowerCase(tg[1])]];
      const is = /^:(?:is|where)\(/i.exec(compound);
      if (!is || (depth | 0) > 3) return null;
      let j = is[0].length, dd = 1;
      for (; j < compound.length && dd; j++) { if (compound[j] === '(') dd++; else if (compound[j] === ')') dd--; }
      const arg = __s_slice(compound, is[0].length, j - 1);
      const keys = [];
      for (const alt of __s_split(arg, /,(?![^()]*\))/)) {
        const cs = compounds(__s_trim(alt));
        const k = cs.length ? keyOf(cs[cs.length - 1][1], (depth | 0) + 1) : null;
        if (!k) return null;
        for (const x of k) keys.push(x);
      }
      return keys.length ? keys : null;
    };
    // Top-level compounds of one selector, each with the combinator before it.
    const compounds = (sel) => {
      const out = [];
      let cur = '', comb = '', d = 0, q = null;
      for (let i = 0; i < sel.length; i++) {
        const ch = sel[i];
        if (q) { cur += ch; if (ch === q) q = null; continue; }
        if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
        if (ch === '(' || ch === '[') d++;
        else if (ch === ')' || ch === ']') d--;
        if (d === 0 && (ch === ' ' || ch === '>' || ch === '+' || ch === '~' || ch === '\t' || ch === '\n')) {
          if (cur) { out.push([comb, cur]); cur = ''; comb = ' '; }
          if (ch !== ' ' && ch !== '\t' && ch !== '\n') comb = ch;
          continue;
        }
        cur += ch;
      }
      if (cur) out.push([comb, cur]);
      return out;
    };
    for (const r of rules) {
      const text = String(r.sel || '');
      if (__s_indexOf(__s_toLowerCase(text), ':has(') < 0) continue;
      found = true;
      for (const part of __s_split(text, /,(?![^()]*\))/)) {
        const cs = compounds(__s_trim(part));
        for (let i = 0; i < cs.length; i++) {
          const comp = cs[i][1];
          const lower = __s_toLowerCase(comp);
          if (__s_indexOf(lower, ':has(') < 0) continue;
          // Relative sibling combinator inside the `:has()`.
          const inner = __s_slice(comp, __s_indexOf(lower, ':has(') + 5);
          const sibling = /^\s*[+~]/.test(inner);
          let key = keyOf(comp);
          let above = false;
          if (!key) {
            // No key on the anchor: it lies under the nearest keyed compound
            // to its left (through descendant/child combinators), whose
            // subtree a change then drops. That ancestor also holds the
            // siblings a `:has(+ …)`/`:has(~ …)` looks at.
            for (let j = i; j > 0 && !key; j--) {
              if (cs[j][0] === '+' || cs[j][0] === '~') break;
              key = keyOf(cs[j - 1][1]);
            }
            above = !!key;
          }
          const arg = newArg();
          hasArgs(arg, comp);
          // `:has(> x)` with nothing to key on: the anchor is the parent of
          // a changed child, one level up.
          if (!key && !sibling && /^\s*>\s*[^\s>+~()]+\s*\)\s*$/.test(inner)) { items.push({ arg, parentAny: true }); continue; }
          if (!key) { items.push({ arg, any: true }); continue; }
          items.push({ arg, key, sib: sibling && !above, tilde: /^\s*~/.test(inner) });
        }
      }
    }
    return found ? { items } : null;
  }
  // The anchors to look for after the mutations recorded since the last
  // pass: the union over the `:has()` items whose argument they can reach.
  // Null when none can.
  function __hasEffective(HA) {
    let H = null;
    for (const it of HA.items) {
      if (!__hasMutRelevant(it.arg)) continue;
      if (!H) {
        H = { any: false, parentAny: false, tags: new Set(), classes: new Set(), ids: new Set(),
          sib: { tags: new Set(), classes: new Set(), ids: new Set() }, hasSib: false, tilde: false };
      }
      if (it.any) { H.any = true; break; }
      if (it.parentAny) { H.parentAny = true; continue; }
      const into = it.sib ? H.sib : H;
      if (it.sib) { H.hasSib = true; if (it.tilde) H.tilde = true; }
      for (const [set, v] of it.key) into[set].add(v);
    }
    return H;
  }
  function __hasAnchorMatch(e, H) {
    if (H.tags.size && H.tags.has(__s_toLowerCase(String(e.__ptLocal || '')))) return true;
    if (H.ids.size) { const id = __ptGetA(e, 'id'); if (id && H.ids.has(id)) return true; }
    if (H.classes.size) { const set = __ptClassSet(e); if (set) for (const c of set) if (H.classes.has(c)) return true; }
    return false;
  }

  // The rule list is rebuilt only when a stylesheet changed: every CSSOM
  // change replaces a sheet's `cssRules`, and `@media` follows the viewport.
  let __gatherKey = null, __gatherHit = null;
  function __gatherRulesCached(docEl) {
    const key = [docEl, LAYOUT.W, LAYOUT.H, __importGen];
    // Tree order, a shadow tree before the children, no stack frame per
    // level; the tag by the engine's field, not the page's `tagName`.
    const st = [docEl.__ptKids || __NO_NODES, 0, docEl];
    while (st.length) {
      const top = st.length - 3;
      const kids = st[top], i = st[top + 1], root = st[top + 2];
      if (i >= kids.length) { st.length = top; continue; }
      st[top + 1] = i + 1;
      const n = kids[i];
      if (n.__ptType !== ELEMENT_NODE) continue;
      if (__isHtmlEl(n) && (n.__ptLocal === 'style' || (n.__ptLocal === 'link' && n.__ptSheetText)) && n.sheet) key.push(root, __sheetRules(n.sheet), __ptGetA(n, 'media'));
      st.push(n.__ptKids || __NO_NODES, 0, root);
      if (n.__ptShadow) st.push(n.__ptShadow.__ptKids || __NO_NODES, 0, n.__ptShadow);
    }
    const old = __gatherKey;
    if (old && old.length === key.length && old.every((v, i) => v === key[i])) return __gatherHit;
    __gatherKey = key;
    const g0 = __perfNow();
    __gatherHit = __gatherRules(docEl, []);
    __lstats.gathers++; __lstats.gatherRules += __gatherHit.length; __lstats.gatherMs += __perfNow() - g0;
    __gatherHit.__ptHas = __hasAnchors(__gatherHit);
    return __gatherHit;
  }

  /// Declarations reaching the element: stylesheets by weight, then its own
  /// `style` attribute.
  /// Properties SVG writes as attributes. Chrome 151 list.
  const SVG_PRESENTATION = ['alignment-baseline', 'baseline-shift', 'clip-path', 'clip-rule',
    'color', 'color-interpolation', 'color-interpolation-filters', 'cursor', 'direction',
    'display', 'dominant-baseline', 'fill', 'fill-opacity', 'fill-rule', 'filter',
    'flood-color', 'flood-opacity', 'font-family', 'font-size', 'font-size-adjust',
    'font-stretch', 'font-style', 'font-variant', 'font-weight', 'image-rendering',
    'letter-spacing', 'lighting-color', 'marker-end', 'marker-mid', 'marker-start', 'mask',
    'mask-type', 'opacity', 'overflow', 'paint-order', 'pointer-events', 'shape-rendering',
    'stop-color', 'stop-opacity', 'stroke', 'stroke-dasharray', 'stroke-dashoffset',
    'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit', 'stroke-opacity',
    'stroke-width', 'text-anchor', 'text-decoration', 'text-overflow', 'text-rendering',
    'transform-origin', 'unicode-bidi', 'vector-effect', 'visibility', 'white-space',
    'word-spacing', 'writing-mode'];
  const SVG_LENGTH_ATTRS = new Set(['font-size', 'letter-spacing', 'word-spacing',
    'stroke-width', 'stroke-dashoffset', 'baseline-shift']);

  // Matching only reads the context; one object serves every test.
  const __CASCADE_CTX = Object.freeze({ scope: null });
  // Style sharing: siblings alike in tag, id, classes and attributes (values
  // too), with no style attribute, take one cascade when they also agree on
  // every candidate rule that could tell them apart: a sibling combinator or
  // a pseudo-class that reads position, content, focus or form state. Those
  // few are matched for each sibling (most fail the ancestor filter at once);
  // all other rules read only what the siblings share. Kept for one pass.
  let __shareMap = new WeakMap();
  const __SHARE_EXACT = new Set(['first-child', 'last-child', 'only-child', 'first-of-type', 'last-of-type',
    'only-of-type', 'nth-child', 'nth-last-child', 'nth-of-type', 'nth-last-of-type', 'empty', 'blank', 'has',
    'checked', 'indeterminate', 'placeholder-shown', 'valid', 'invalid', 'user-valid', 'user-invalid',
    'in-range', 'out-of-range', 'scope', 'host', 'host-context', 'state', 'focus', 'focus-within']);
  const __ruleSensitive = (r) => {
    if (r.__ptSens !== undefined) return r.__ptSens;
    const t = __s_replace(__s_replace(String(r.sel), /\[[^\]]*\]|"[^"]*"|'[^']*'/g, ''), /\\./g, '');
    let v = /[+~]/.test(t);
    if (!v) {
      const re = /(::?)([\w-]+)/g;
      let m;
      while ((m = re.exec(t)) !== null) if (m[1] === ':' && __SHARE_EXACT.has(__s_toLowerCase(m[2]))) { v = true; break; }
    }
    r.__ptSens = v;
    return v;
  };
  // The key two siblings must agree on, or null when this element cannot
  // share: what its candidate list was keyed by, its attribute values, and
  // which of the sensitive candidates it matches.
  const __shareKey = (el, cands, bloom) => {
    const sig = cands.__ptSig;
    if (sig === undefined || el.__ptStyle || (el.__ptNS !== undefined && el.__ptNS !== 'http://www.w3.org/1999/xhtml')) return null;
    let sens = cands.__ptSensList;
    if (sens === undefined) {
      sens = [];
      for (let i = 0; i < cands.length; i++) if (__ruleSensitive(cands[i])) sens.push(cands[i]);
      cands.__ptSensList = sens;
    }
    let key = sig;
    const attrs = el.__ptAttrs;
    if (attrs) for (const [n, v] of attrs) { if (n === 'style') return null; key += '\x01' + n + '\x02' + v; }
    key += '\x03';
    for (let i = 0; i < sens.length; i++) {
      const r = sens[i];
      if (r.__ptSel === undefined) r.__ptSel = __selCompiled(r.sel) || null;
      let ok = false;
      try { ok = !!r.__ptSel && __bloomMayMatch(r.__ptSel, bloom); } catch (e) {}
      if (!ok) { key += '0'; continue; }
      if (r.__ptVol === undefined) r.__ptVol = __STATE_PSEUDO.test(r.sel);
      if (r.__ptVol) return null;
      try { ok = __selAny(r.__ptSel, el, __CASCADE_CTX); } catch (e) { ok = false; }
      key += ok ? '1' : '0';
    }
    return key;
  };
  function __cascadeFor(el) {
    if (!el || el.__ptType !== ELEMENT_NODE) return new Map();
    const hit = __styleCache.get(el) || __stylePass.get(el);
    if (hit) return hit;
    // State-dependent ancestors make this one state-dependent too.
    let volatile = el.__ptDoc !== globalThis.document;
    const up = el.__ptParent;
    if (!volatile && up && up.__ptType === ELEMENT_NODE) {
      // Ancestors first, from the top, without a stack frame per level.
      if (!(__styleCache.get(up) || __stylePass.get(up))) {
        const chain = [];
        for (let a = up.__ptParent; a && a.__ptType === ELEMENT_NODE && !(__styleCache.get(a) || __stylePass.get(a)); a = a.__ptParent) {
          chain.push(a);
          if (a.__ptDoc !== globalThis.document) break;
        }
        for (let i = chain.length - 1; i >= 0; i--) __cascadeFor(chain[i]);
      }
      __cascadeFor(up);
      volatile = __styleVolatile.has(up);
    }
    const out = new Map();
    __lstats.cascades++;
    // SVG presentation attributes are declarations of the lowest weight:
    // `<text font-size="150">` measures at 150px, not 16.
    if (el.__ptNS === 'http://www.w3.org/2000/svg' && el.hasAttribute) {
      for (const name of SVG_PRESENTATION) {
        const raw = __ptGetA(el, name);
        if (raw == null) continue;
        const v = __s_trim(String(raw));
        // A bare number in SVG is user units, i.e. pixels.
        const norm = SVG_LENGTH_ATTRS.has(name) && /^-?[\d.]+$/.test(v) ? v + 'px' : v;
        out.set(name, norm);
      }
    }
    const cands = __candidateRules(el);
    const bloom = __ancBloom(el);
    const shareKey = volatile || !up || up.__ptType !== ELEMENT_NODE ? null : __shareKey(el, cands, bloom);
    if (shareKey !== null) {
      const sm = __shareMap.get(up);
      const twin = sm && sm.get(shareKey);
      if (twin) { __lstats.shared++; __lstats.cascades--; __styleCache.set(el, twin); return twin; }
    }
    const won = [];
    for (const r of cands) {
      let ok = false;
      // A rule's selector is parsed once and cached on the rule; a shared
      // cache (5000 entries, cleared whole) made a page with 128 stylesheets
      // reparse selectors per element per layout.
      try {
        if (r.__ptSel === undefined) r.__ptSel = __selCompiled(r.sel) || null;
        if (r.__ptVol === undefined) r.__ptVol = __STATE_PSEUDO.test(r.sel);
        ok = !!r.__ptSel && __bloomMayMatch(r.__ptSel, bloom);
        if (ok && r.__ptVol) volatile = true;
        ok = ok && __selAny(r.__ptSel, el, __CASCADE_CTX);
      } catch (e) {}
      if (ok) won.push(r);
    }
    // Cascade order (CSS Cascade 5): layers by their order, unlayered rules
    // above them, then specificity and source order.
    won.sort((a, b) => (a.layer - b.layer) || (a.spec - b.spec) || (a.order - b.order));
    // Shorthands are expanded here, not on output: layout, used font size and
    // computed style all need `font: 14px/1.5 Georgia` to set `font-size`.
    const take = (n, v) => {
      const pairs = typeof __ptExpand === 'function' ? __ptExpand(n, v) : null;
      if (pairs) { for (const [k, val] of pairs) out.set(k, val); return; }
      out.set(n, v);
    };
    // Custom properties (`--*`) and `var()` substitution.
    const decls = [];
    const mine = new Map();
    const note = (n, v) => {
      if (__s_charCodeAt(n, 0) === 45 && __s_charCodeAt(n, 1) === 45) mine.set(n, v);
      else decls.push([n, v]);
    };
    const noteAll = (m, important) => {
      const I = m.__ptImp;
      for (const [n] of m) if (!!(I && I.has(n)) === important) note(n, __cssAbs(String(__cssPreciseGet(m, n)), null));
    };
    // Normal declarations: the rules in cascade order, then the style
    // attribute. Important ones after all of them: unlayered rules, layers
    // in reverse (an earlier layer's `!important` wins), the attribute last.
    let anyImportant = false;
    for (const r of won) {
      const m = __ruleMap(r);
      if (!m) continue;
      const I = m.__ptImp;
      if (I && I.size) anyImportant = true;
      for (const [n, v] of m) if (!I || !I.has(n)) note(n, __cssAbs(String(v), r.rule));
    }
    const own = __inlineDecls(el);
    if (own) noteAll(own, false);
    if (anyImportant) {
      const imp = won.filter((r) => { const m = __ruleMap(r); return m && m.__ptImp && m.__ptImp.size; });
      const rank = (r) => (r.layer === __UNLAYERED ? -1 : __UNLAYERED - r.layer);
      imp.sort((a, b) => (rank(a) - rank(b)) || (a.spec - b.spec) || (a.order - b.order));
      for (const r of imp) {
        const m = __ruleMap(r), I = m.__ptImp;
        for (const [n, v] of m) if (I.has(n)) note(n, __cssAbs(String(v), r.rule));
      }
    }
    if (own) noteAll(own, true);
    const vars = __customsFor(el, mine);
    // `inherit` takes the parent's cascaded value; `initial` and `unset` act
    // as if unset (`* { box-sizing: inherit }` must propagate `border-box`).
    let readsParent = false;
    const parentOf = () => {
      readsParent = true;
      const p = el.__ptParent;
      return p && p.__ptType === ELEMENT_NODE ? __cascadeFor(p) : null;
    };
    for (let k = 0; k < decls.length; k++) {
      const v = __s_toLowerCase(__s_trim(String(decls[k][1])));
      if (v === 'initial' || v === 'unset' || v === 'revert' || v === 'revert-layer') { decls[k][1] = null; continue; }
      if (v !== 'inherit') continue;
      const pc = parentOf();
      const got = pc ? pc.get(decls[k][0]) : undefined;
      decls[k][1] = got != null ? got : null;
    }
    let readsVars = mine.size > 0;
    for (const [n, v] of decls) {
      if (v == null) { out.delete(n); continue; }
      if (__s_indexOf(v, 'var(') < 0) { take(n, v); continue; }
      readsVars = true;
      // A failed substitution makes the declaration invalid: as if not written.
      const sub = __ptSubstVars(v, vars);
      if (sub != null) take(n, sub);
    }
    out.__ptVars = vars;
    if (readsVars) __varReaders.add(out);
    if (readsParent) __inheritReaders.add(out);
    if (volatile) { __styleVolatile.add(el); __stylePass.set(el, out); } else {
      __styleCache.set(el, out);
      if (shareKey !== null && !__styleVolatile.has(el)) {
        let sm = __shareMap.get(up);
        if (!sm) __shareMap.set(up, (sm = new Map()));
        sm.set(shareKey, out);
      }
    }
    return out;
  }

  /// Element custom properties: own over inherited. Kept as a prototype chain,
  /// not a copy (hundreds at the root, thousands of nodes).
  function __customsFor(el, mine) {
    const hit = __passCustom.get(el);
    if (hit) return hit;
    const parent = el.__ptParent && el.__ptParent.__ptType === ELEMENT_NODE ? el.__ptParent
      : (el.__ptParent && el.__ptParent.host) || null;
    let base = null;
    // The parent's variables: from this pass, or kept with its cascade when
    // that came from the cache (a change below it does not recompute it).
    if (parent) { const pc = __cascadeFor(parent); base = __passCustom.get(parent) || pc.__ptVars || null; }
    if (!mine || !mine.size) {
      const same = base || Object.create(null);
      __passCustom.set(el, same);
      return same;
    }
    const out = Object.create(base);
    for (const [n, v] of mine) out[n] = v;
    // Own values may reference variables, own or inherited. A cycle makes the
    // value invalid.
    for (const n of mine.keys()) {
      const v = out[n];
      if (typeof v !== 'string' || __s_indexOf(v, 'var(') < 0) continue;
      const sub = __ptSubstVars(v, out, new Set([n]));
      if (sub == null) out[n] = undefined; else out[n] = sub;
    }
    __passCustom.set(el, out);
    return out;
  }

  /// Substitute `var(--name[, fallback])`. Returns null if substitution fails
  /// and there is no fallback.
  function __ptSubstVars(v, vars, busy) {
    let out = '', i = 0, bad = false;
    while (i < v.length) {
      const at = __s_indexOf(v, 'var(', i);
      if (at < 0) { out += __s_slice(v, i); break; }
      // `var(` never follows a name char (`--my-var(`), but `somevar(` exists.
      if (at > 0 && /[\w-]/.test(v[at - 1])) { out += __s_slice(v, i, at + 4); i = at + 4; continue; }
      out += __s_slice(v, i, at);
      let depth = 1, j = at + 4, comma = -1;
      for (; j < v.length && depth; j++) {
        const c = v[j];
        if (c === '(') depth++;
        else if (c === ')') { if (--depth === 0) break; }
        else if (c === ',' && depth === 1 && comma < 0) comma = j;
      }
      const name = __s_trim(__s_slice(v, at + 4, comma < 0 ? j : comma));
      const fallback = comma < 0 ? null : __s_trim(__s_slice(v, comma + 1, j));
      let val = null;
      if (!(busy && busy.has(name))) {
        const raw = vars ? vars[name] : undefined;
        if (typeof raw === 'string') {
          if (__s_indexOf(raw, 'var(') < 0) val = raw;
          else {
            const b = new Set(busy || []); b.add(name);
            val = __ptSubstVars(raw, vars, b);
          }
        }
      }
      if (val == null && fallback != null) {
        val = __s_indexOf(fallback, 'var(') < 0 ? fallback : __ptSubstVars(fallback, vars, busy);
      }
      if (val == null) { bad = true; break; }
      out += val;
      i = j + 1;
    }
    return bad ? null : __s_trim(out);
  }

  // Layout: normal block flow with padding, borders, margins, percentages,
  // `em` from the font size, line widths from font metrics. Pixel-exactness is
  // not the goal, but fingerprinters read these numbers, and a full-window
  // width where the style says 200px is a contradiction.
  const __BLOCKISH = /^(block|flow-root|list-item|table|flex|grid|table-cell|table-row|table-caption)$/;
  const __INLINEISH = /^(inline|inline-block|inline-flex|inline-grid|inline-table)$/;

  /// Grid tracks: `[{px}|{fr}|{auto}]`. Handles lengths, fractions, `auto`,
  /// `minmax()`, `repeat()` (incl. `auto-fill`/`auto-fit`); skips line names.
  /// Empty means one `auto` track.
  // Grid item placement: explicit (`grid-area: 1/1`, `grid-column: 2`) and
  // row-wise auto-placement into free cells; as many columns as needed
  // (implicit ones auto). Shared by layout and max-content.
  function __gridPlacement(flow, nTracks) {
    const lineOf = (c, prop) => { const v = __s_trim(String(__cascadeFor(c).get(prop) || 'auto')); const m = /^(\d+)$/.exec(v); return m ? +m[1] : null; };
    const want = flow.map((c) => ({ col: lineOf(c, 'grid-column-start'), row: lineOf(c, 'grid-row-start') }));
    let n = Math.max(nTracks, ...want.map((w) => w.col || 0));
    const taken = new Set(); const place = new Array(flow.length);
    want.forEach((w, i) => { if (w.col && w.row) { place[i] = { k: w.col - 1, r: w.row - 1 }; taken.add((w.row - 1) + ':' + (w.col - 1)); } });
    want.forEach((w, i) => { if (place[i] || !w.row) return; let k = 0; while (taken.has((w.row - 1) + ':' + k)) k++; if (k >= n) n = k + 1; place[i] = { k, r: w.row - 1 }; taken.add((w.row - 1) + ':' + k); });
    want.forEach((w, i) => { if (place[i] || !w.col) return; let r = 0; while (taken.has(r + ':' + (w.col - 1))) r++; place[i] = { k: w.col - 1, r }; taken.add(r + ':' + (w.col - 1)); });
    { let cur = 0; want.forEach((w, i) => { if (place[i]) return; while (taken.has(((cur / n) | 0) + ':' + (cur % n))) cur++; place[i] = { k: cur % n, r: (cur / n) | 0 }; taken.add(((cur / n) | 0) + ':' + (cur % n)); cur++; }); }
    return { place, n, want };
  }
  function __gridTracks(raw, avail, gap, fs, rows) {
    const v = raw == null ? 'none' : __s_trim(String(raw));
    if (!v || /^(none|auto|subgrid|masonry)$/i.test(v)) return rows ? [] : [{ auto: true }];
    const split = (t) => {
      const out = []; let depth = 0, cur = '';
      for (const ch of t) {
        if (ch === '(' || ch === '[') depth++;
        if (ch === ')' || ch === ']') depth--;
        if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
        cur += ch;
      }
      if (cur) out.push(cur);
      return out.filter((x) => x[0] !== '[');
    };
    const one = (t) => {
      const low = __s_toLowerCase(t);
      let m;
      if ((m = /^(-?[\d.]+)fr$/.exec(low))) return { fr: parseFloat(m[1]) };
      if (/^(auto|min-content|max-content)$/.test(low) || /^fit-content\(/.test(low)) return { auto: true };
      if ((m = /^minmax\((.*)\)$/.exec(low))) {
        const [a, b] = __selSplit(m[1]);
        const hi = one(b || 'auto');
        if (hi.fr) return { fr: hi.fr };
        if (hi.px != null) {
          const lo = one(a || '0');
          return { px: lo.px != null ? Math.max(lo.px, hi.px) : hi.px };
        }
        const lo = one(a || 'auto');
        return lo.px != null ? { px: lo.px, grow: true } : { auto: true };
      }
      const px = __lengthPx(t, fs, avail);
      return px != null ? { px } : { auto: true };
    };
    const out = [];
    for (const t of split(v)) {
      const m = /^repeat\(\s*([^,]+?)\s*,(.*)\)$/i.exec(t);
      if (!m) { out.push(one(t)); continue; }
      const list = split(__s_trim(m[2])).map(one);
      let count = parseInt(m[1], 10);
      if (!Number.isFinite(count)) {
        // auto-fill / auto-fit: as many as fit at the minimum size.
        const size = list.reduce((a, d) => a + (d.px || 0), 0) + gap * list.length;
        count = size > 0 ? Math.max(1, Math.floor((avail + gap) / size)) : 1;
      }
      for (let r = 0; r < Math.min(count, 1000); r++) for (const d of list) out.push(Object.assign({}, d));
    }
    // `minmax(200px, auto)` grows like `auto`.
    for (const d of out) if (d.grow) { delete d.grow; }
    return out.length ? out : (rows ? [] : [{ auto: true }]);
  }

  /// Root font size, the base for `rem` (pages often set
  /// `html { font-size: 62.5% }`).
  function __rootFontSize() {
    const doc = globalThis.document;
    const root = doc && doc.documentElement;
    return root ? __usedFontSize(root) : 16;
  }

  /// One number with a unit to pixels. `base` is the percentage base; without
  /// it percentages are not resolved.
  function __unitPx(x, u, fs, base) {
    switch (u) {
      case 'px': case '': return x;
      case 'em': return x * fs;
      case 'rem': return x * __rootFontSize();
      case 'pt': return x * 4 / 3;
      case 'pc': return x * 16;
      case 'in': return x * 96;
      case 'cm': return x * 96 / 2.54;
      case 'mm': return x * 96 / 25.4;
      case 'q': return x * 96 / 101.6;
      case 'ex': return x * fs / 2;
      case 'ch': return x * fs / 2;
      case '%': return base == null ? null : x / 100 * base;
    }
    // Viewport units, new ones too (`dvh`, `svh`, `lvh`): without toolbars
    // and keyboard all three equal the plain one.
    const m = /^[dsl]?(vh|vw|vmin|vmax|vi|vb)$/.exec(u);
    if (m) {
      const k = m[1];
      const vb = k === 'vh' || k === 'vb' ? LAYOUT.H : k === 'vw' || k === 'vi' ? LAYOUT.W
        : k === 'vmin' ? Math.min(LAYOUT.W, LAYOUT.H) : Math.max(LAYOUT.W, LAYOUT.H);
      return x / 100 * vb;
    }
    return null;
  }

  /// A `calc()`, `min()`, `max()` or `clamp()` expression to pixels, or null.
  function __ptCalcPx(v, fs, base) {
    const toks = [];
    const re = /\s*(?:([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)([a-z%]*)|([a-z-]+)\(|([()*/,+-]))/iy;
    let pos = 0;
    while (pos < v.length) {
      re.lastIndex = pos;
      const m = re.exec(v);
      if (!m) { if (/^\s*$/.test(__s_slice(v, pos))) break; return null; }
      pos = re.lastIndex;
      if (m[1] != null) {
        // `a -1px` is subtraction, not a signed number, after an operand.
        const prev = toks[toks.length - 1];
        if (/^[+-]/.test(m[1]) && prev && (prev.t === 'n' || prev.t === ')')) {
          toks.push({ t: m[1][0] });
          toks.push({ t: 'n', x: parseFloat(__s_slice(m[1], 1)), u: __s_toLowerCase(m[2]) });
        } else toks.push({ t: 'n', x: parseFloat(m[1]), u: __s_toLowerCase(m[2]) });
      } else if (m[3] != null) toks.push({ t: 'f', f: __s_toLowerCase(m[3]) });
      else toks.push({ t: m[4] });
    }
    let i = 0, fail = false;
    const peek = () => toks[i] || { t: 'end' };
    // A value is a pair: pixels and a "bare number" flag, so `2 * 10px` and
    // `10px / 2` work but `10px * 10px` does not.
    const expr = () => {
      let a = term();
      while (!fail && (peek().t === '+' || peek().t === '-')) {
        const op = toks[i++].t, b = term();
        if (fail) break;
        a = { x: op === '+' ? a.x + b.x : a.x - b.x, num: a.num && b.num };
      }
      return a;
    };
    const term = () => {
      let a = factor();
      while (!fail && (peek().t === '*' || peek().t === '/')) {
        const op = toks[i++].t, b = factor();
        if (fail) break;
        if (op === '*') a = { x: a.x * b.x, num: a.num && b.num };
        else { if (!b.num || b.x === 0) { fail = true; break; } a = { x: a.x / b.x, num: a.num }; }
      }
      return a;
    };
    const args = () => {
      const out = [expr()];
      while (!fail && peek().t === ',') { i++; out.push(expr()); }
      if (peek().t !== ')') fail = true; else i++;
      return out;
    };
    const factor = () => {
      const t = toks[i++];
      if (!t) { fail = true; return { x: 0 }; }
      if (t.t === 'n') {
        if (t.u === '') return { x: t.x, num: true };
        const px = __unitPx(t.x, t.u, fs, base);
        if (px == null) fail = true;
        return { x: px || 0, num: false };
      }
      if (t.t === '(') {
        const a = expr();
        if (peek().t !== ')') fail = true; else i++;
        return a;
      }
      if (t.t === '-') { const a = factor(); return { x: -a.x, num: a.num }; }
      if (t.t === 'f') {
        const xs = args();
        if (fail) return { x: 0 };
        const num = xs.every((a) => a.num);
        switch (t.f) {
          case 'calc': case '-webkit-calc':
            if (xs.length !== 1) fail = true;
            return xs[0];
          case 'min': return { x: Math.min(...xs.map((a) => a.x)), num };
          case 'max': return { x: Math.max(...xs.map((a) => a.x)), num };
          case 'clamp':
            if (xs.length !== 3) { fail = true; return { x: 0 }; }
            return { x: Math.max(xs[0].x, Math.min(xs[1].x, xs[2].x)), num };
        }
      }
      fail = true;
      return { x: 0 };
    };
    const r = expr();
    if (fail || i !== toks.length || !isFinite(r.x)) return null;
    return r.x;
  }

  const __CALC_FN = /(?:^|[^\w-])(?:-webkit-)?(?:calc|min|max|clamp)\(/i;

  // Values parsed once by their text, resolved per call: layout asks for
  // twenty lengths per element, mostly the same few strings.
  let __lengthParsed = new Map();
  const __LENGTH_NONE = { none: true };
  function __lengthParse(raw) {
    const v = __s_trim(raw);
    const m = /^(-?(?:\d+\.?\d*|\.\d+))([a-z%]*)$/i.exec(v);
    if (m) {
      const u = __s_toLowerCase(m[2]);
      // Viewport units and percentages are kept at 1/64 px precision.
      return { n: parseFloat(m[1]), u, fine: u === '%' || /v/.test(u), calc: null };
    }
    if (__CALC_FN.test(v)) return { n: 0, u: '', fine: true, calc: v };
    return __LENGTH_NONE;
  }
  function __lengthPx(raw, fs, base) {
    if (raw == null) return null;
    const key = typeof raw === 'string' ? raw : String(raw);
    let p = __lengthParsed.get(key);
    if (p === undefined) {
      if (__lengthParsed.size >= 4096) __lengthParsed = new Map();
      p = __lengthParse(key);
      __lengthParsed.set(key, p);
    }
    if (p === __LENGTH_NONE) return null;
    const px = p.calc !== null ? __ptCalcPx(p.calc, fs, base) : __unitPx(p.n, p.u, fs, base);
    if (px == null) return null;
    return p.fine ? Math.round(px * 64) / 64 : px;
  }

  // `line-height: normal` and baseline ascent come from the face, not a fixed
  // ratio: Liberation Sans is 1.15 of the size, other faces differ.
  function __fontBox(fs, family) {
    if (typeof __pt_canvasMeasureText === 'function') {
      try {
        const m = __pt_canvasMeasureText('', fs, family || 'sans-serif', false, false);
        return { line: Math.round(m[7] || fs * 1.15), asc: m[5] || Math.round(fs * 0.9), desc: m[6] || Math.round(fs * 0.2) };
      } catch (e) {}
    }
    return { line: Math.round(fs * 1.15), asc: Math.round(fs * 0.9), desc: Math.round(fs * 0.2) };
  }
  const __normalLine = (fs, family) => __fontBox(fs, family).line;

  // Measuring a string is expensive (HarfBuzz shaping with per-glyph font
  // fallback), and layout re-measures the same words on every mutation. The
  // result depends only on string and font; cache it, and restart when full so
  // the map does not grow on pages printing unique text.
  // By font, then by text: a line's words share one font key.
  let __widths = new Map(), __widthsN = 0;
  // SVG whitespace collapses: newlines dropped, tabs become spaces, runs
  // squeezed, ends trimmed. `<text>  ii  </text>` measures as "ii".
  const __svgText = (el) => __s_trim(__s_replace(__s_replace(__s_replace(String((el && el.textContent) || ''), /[\r\n]/g, ''), /\t/g, ' '), / +/g, ' '));

  function __fontWidths(fs, family, bold, italic) {
    const key = fs + '|' + (family || 'sans-serif') + '|' + (bold ? 1 : 0) + (italic ? 1 : 0);
    let byText = __widths.get(key);
    if (byText === undefined) __widths.set(key, (byText = new Map()));
    return byText;
  }
  function __textMetricsIn(byText, text, fs, family, bold, italic) {
    const t = typeof text === 'string' ? text : String(text);
    const hit = byText.get(t);
    if (hit !== undefined) return hit;
    let m = null;
    if (typeof __pt_canvasMeasureText === 'function') {
      try { m = __pt_canvasMeasureText(t, fs, family || 'sans-serif', !!bold, !!italic); }
      catch (e) {}
    }
    if (!m) m = [t.length * fs * 0.5, 0, t.length * fs * 0.5, fs * 0.9, fs * 0.2, fs * 0.9, fs * 0.2, fs * 1.15];
    // Restart when full, so pages printing unique text do not grow it.
    if (++__widthsN > 20000) {
      __widths = new Map();
      __widthsN = 1;
      byText = __fontWidths(fs, family, bold, italic);
    }
    byText.set(t, m);
    return m;
  }
  function __textMetrics(text, fs, family, bold, italic) {
    return __textMetricsIn(__fontWidths(fs, family, bold, italic), text, fs, family, bold, italic);
  }

  function __textWidth(text, fs, family, bold, italic) {
    // Text width rounds up to 1/64 px, like Chrome's LayoutUnit: flooring
    // wrapped a word in a column shrunk to its text.
    const w = __textMetrics(text, fs, family, bold, italic)[0] || 0;
    return Math.ceil(w * 64 - 1e-6) / 64;
  }

  // Where a word may break across lines, as Chrome 151 breaks it: between
  // two ASCII characters by Blink's own table (measured: no break after `/`
  // or a backslash, one after `-` and `?`, and after closing punctuation
  // before an opening one; `-` before a digit only after a letter or digit),
  // elsewhere by ICU's line rules, the same `Intl.v8BreakIterator` Chrome
  // has. A soft hyphen does not break here: Chrome draws a hyphen there.
  const __ASCII_PUNCT_BREAK = "!\"#%&)*+,.:;=>\\]|}~";
  const __ASCII_BREAKS = new Map([
    ["-", "\"#%&'(*+-0123456789<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\^_`abcdefghijklmnopqrstuvwxyz{|~"],
    ["?", "#$%&(*+-0123456789<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\^_`abcdefghijklmnopqrstuvwxyz{|~"],
  ]);
  const __ASCII_ALNUM = /^[A-Za-z0-9]*$/;
  const __alnum = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
  // The iterator is made at first use (its ICU object cannot go into the
  // startup snapshot), from the constructor and member getters taken now,
  // before a page can replace them.
  let __lineIter = null;
  const __lineIterMake = (() => {
    try {
      const C = Intl.v8BreakIterator, P = C.prototype;
      const g = (k) => Object.getOwnPropertyDescriptor(P, k).get;
      const adopt = g('adoptText'), first = g('first'), next = g('next');
      return () => {
        const it = new C(['en'], { type: 'line' });
        return { adopt: adopt.call(it), first: first.call(it), next: next.call(it) };
      };
    } catch (e) { return null; }
  })();
  // Letters and digits of scripts with no breaks between them (UAX #14 AL,
  // HL, NU, CM): most words, answered without ICU. CJK and South-East Asian
  // scripts are not among them. Other words' answers are kept, as text
  // repeats its words.
  const __NO_INNER_BREAK = /^[[[\p{Script=Latin}\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Georgian}\p{Script=Hebrew}\p{Script=Arabic}\p{M}0-9]&&[\p{L}\p{M}0-9]]--[\uFF00-\uFFEF]]*$/v;
  const __NONE = [];
  let __breaksMemo = new Map();
  const __lineBreaks = (t) => {
    if (__ASCII_ALNUM.test(t) || __NO_INNER_BREAK.test(t)) return __NONE;
    const hit = __breaksMemo.get(t);
    if (hit !== undefined) return hit;
    const out = __lineBreaksOf(t);
    if (__breaksMemo.size >= 20000) __breaksMemo = new Map();
    __breaksMemo.set(t, out);
    return out;
  };
  const __lineBreaksOf = (t) => {
    const out = [];
    let icu = null;
    for (let i = 1; i < t.length; i++) {
      const a = __s_charCodeAt(t, i - 1), b = __s_charCodeAt(t, i);
      if (a >= 0x21 && a <= 0x7e && b >= 0x21 && b <= 0x7e) {
        if (a === 45 && b >= 48 && b <= 57) { if (i >= 2 && __alnum(__s_charCodeAt(t, i - 2))) out.push(i); continue; }
        const row = __ASCII_BREAKS.get(String.fromCharCode(a));
        const B = String.fromCharCode(b);
        if (row ? __s_indexOf(row, B) >= 0 : __s_indexOf(__ASCII_PUNCT_BREAK, String.fromCharCode(a)) >= 0 && __s_indexOf('(<[{', B) >= 0) out.push(i);
        continue;
      }
      if (a === 0xad || (b >= 0xdc00 && b <= 0xdfff)) continue;
      if (!icu) {
        icu = new Set();
        if (!__lineIter && __lineIterMake) { try { __lineIter = __lineIterMake(); } catch (e) {} }
        if (__lineIter) {
          __lineIter.adopt(t);
          __lineIter.first();
          for (let n = __lineIter.next(); n !== -1; n = __lineIter.next()) icu.add(n);
        }
      }
      if (icu.has(i)) out.push(i);
    }
    return out;
  };

  // A line height in LayoutUnits, as Blink makes it (measured): a multiplier
  // times the font size in 1/64 px, floored (1.6 x 15.44px is 24.6875, of
  // 15.4375px); a length or percentage rounded (1.6em of 15.4px is
  // 24.640625).
  function __lineHeightPx(t, fs, base, fallback) {
    if (/^[\d.]+$/.test(t)) return Math.floor(parseFloat(t) * (Math.round(fs * 64) / 64) * 64 + 1e-6) / 64;
    const px = /^[\d.]+%$/.test(t) ? parseFloat(t) / 100 * fs : __lengthPx(t, fs, base);
    return px ? Math.round(px * 64) / 64 : fallback;
  }

  // Word wrapping: greedy, at spaces and where a word may break inside
  // (`__lineBreaks`); the trailing space does not count toward the line
  // width, as in Chrome.
  function __wrapLines(text, maxWidth, fs, family, bold) {
    const words = __s_split(String(text), ' ').filter((w) => w.length);
    const out = [];
    if (!words.length) return out;
    if (!(maxWidth > 0)) {
      const all = words.join(' ');
      return [{ text: all, width: Math.round(__textWidth(all, fs, family, bold, false) * 64) / 64 }];
    }
    // Pieces of words, each with whether a space comes before it.
    const parts = [], gap = [];
    for (let i = 0; i < words.length; i++) {
      const t = words[i];
      let from = 0;
      for (const at of __lineBreaks(t)) { parts.push(__s_slice(t, from, at)); gap.push(from === 0 && i > 0); from = at; }
      parts.push(__s_slice(t, from)); gap.push(from === 0 && i > 0);
    }
    // Pieces are shaped one at a time (Chrome caches a run per word), so a
    // line is its pieces and the spaces between them: each is measured
    // once, not every prefix of the line again (quadratic in the words).
    const ceil64 = (v) => Math.ceil(v * 64 - 1e-6) / 64;
    const byText = __fontWidths(fs, family, bold, false);
    const space = __textMetricsIn(byText, ' ', fs, family, bold, false)[0] || 0;
    let start = 0, acc = __textMetricsIn(byText, parts[0], fs, family, bold, false)[0] || 0;
    const flush = (end) => {
      let text = '';
      for (let k = start; k < end; k++) text += (k > start && gap[k] ? ' ' : '') + parts[k];
      out.push({ text, width: __textWidth(text, fs, family, bold, false) });
    };
    for (let i = 1; i < parts.length; i++) {
      const w = __textMetricsIn(byText, parts[i], fs, family, bold, false)[0] || 0;
      const next = acc + (gap[i] ? space : 0) + w;
      if (ceil64(next) > maxWidth) {
        flush(i);
        start = i;
        acc = w;
      } else {
        acc = next;
      }
    }
    flush(parts.length);
    // Line widths are kept in 1/64 px too.
    for (const l of out) l.width = Math.round(l.width * 64) / 64;
    return out;
  }

  const __OWN_TEXT = (el) => {
    let t = '';
    for (const c of (el.__ptKids || [])) if (c.__ptType === TEXT_NODE) t += c.data || '';
    return __s_trim(__s_replace(t, /\s+/g, ' '));
  };

  // Sizes the UA gives form controls, from Chrome 151: checkbox 13x13, input
  // 177x15 with border 2 and padding 2/1, button shrinks to its label with
  // padding 6/1. Form controls use 13.3333px text.
  const UA_FORM_FONT = 13.3333;
  function __uaBox(el, tag) {
    if (tag === 'input') {
      const t = __s_toLowerCase(String((el.getAttribute && __ptGetA(el, 'type')) || 'text'));
      if (t === 'checkbox') return { w: 13, h: 13, p: [0, 0], b: 0, m: [3, 3] };
      if (t === 'radio') return { w: 13, h: 13, p: [0, 0], b: 0, m: [3, 3] };
      if (t === 'range') return { w: 129, h: 16, p: [0, 0], b: 0, m: [2, 2] };
      if (t === 'file') return { w: 253, h: 21, p: [0, 0], b: 0, m: [0, 0] };
      if (t === 'submit' || t === 'button' || t === 'reset') {
        // An unlabelled submit button gets its label from the UA.
        const dflt = t === 'submit' ? 'Submit' : t === 'reset' ? 'Reset' : '';
        return { label: true, dflt, h: 15, p: [1, 6], b: 2, m: [0, 0] };
      }
      if (t === 'hidden') return null;
      return { w: 177, h: 15, p: [1, 2], b: 2, m: [0, 0] };
    }
    if (tag === 'button') return { label: true, h: 15, p: [1, 6], b: 2, m: [0, 0] };
    // A select is sized by its outer border, not content.
    if (tag === 'select') return { w: 28, h: 17, p: [0, 0], b: 1, m: [0, 0] };
    if (tag === 'textarea') return { w: 195, h: 36, p: [2, 2], b: 1, m: [0, 0] };
    if (tag === 'iframe') return { w: 300, h: 150, p: [0, 0], b: 2, m: [0, 0] };
    if (tag === 'img' || tag === 'canvas' || tag === 'video') return { w: 0, h: 0, p: [0, 0], b: 0, m: [0, 0] };
    return null;
  }

  // UA stylesheet margins for block elements. First number: top/bottom in em
  // (relative to the element's own font size, so `h1` differs by font);
  // second: sides in px.
  const UA_MARGIN = {
    p: [1, 0], blockquote: [1, 40], figure: [1, 40], ul: [1, 0], ol: [1, 0],
    dir: [1, 0], menu: [1, 0], dl: [1, 0], dd: [0, 40], pre: [1, 0], form: [0, 0],
    h1: [0.67, 0], h2: [0.83, 0], h3: [1, 0], h4: [1.33, 0], h5: [1.67, 0], h6: [2.33, 0],
  };
  // Margins set in pixels (body has 8px on all sides).
  const UA_MARGIN_PX = { body: [8, 8], hr: [8, 0], fieldset: [0, 2] };

  // A list inside a list (`dl dl`, `ul ol`, `dl ul`... at any depth) has no
  // block margins in Chrome's UA sheet.
  const UA_LISTS = new Set(['dir', 'dl', 'menu', 'ol', 'ul']);
  function __uaMargin(tag, fs, el) {
    const px = UA_MARGIN_PX[tag];
    if (px) return px;
    const em = UA_MARGIN[tag];
    if (!em) return null;
    if (el && UA_LISTS.has(tag)) {
      for (let p = el.__ptParent; p && p.__ptType === ELEMENT_NODE; p = p.__ptParent) {
        if (UA_LISTS.has(p.__ptLocal) && (p.__ptNS === undefined || p.__ptNS === 'http://www.w3.org/1999/xhtml')) return [0, em[1]];
      }
    }
    return [em[0] * (fs || 16), em[1]];
  }

  // unicode-bidi from the UA sheet: initial is `normal`; `isolate` is given
  // to a list of block elements that excludes body and inputs.
  const UA_BIDI = {
    html: 'normal', body: 'normal', input: 'normal', button: 'normal', select: 'normal',
    textarea: 'normal', fieldset: 'normal', option: 'normal', optgroup: 'normal',
    meter: 'normal', progress: 'normal', details: 'normal', template: 'normal',
    output: 'isolate',
  };

  // UA font size and weight. Headings scale from the parent, `small` is 1.2x
  // smaller, and it compounds (`small` in `small`), as in Chrome.
  const UA_FONT_SIZE = {
    h1: 2, h2: 1.5, h3: 1.17, h4: 1, h5: 0.83, h6: 0.67,
    small: 1 / 1.2, sub: 1 / 1.2, sup: 1 / 1.2, big: 1.2,
  };
  const UA_BOLD = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'b', 'strong', 'th']);

  // Monospace in the UA sheet: its own size (13px vs 16px) and family.
  // Textarea uses 13.33px like other form controls.
  const UA_MONO = new Set(['pre', 'code', 'kbd', 'samp', 'tt', 'textarea', 'xmp', 'plaintext', 'listing']);

  // Whether a child is inline-level: such children share a line.
  /// Two margins collapsed into one: largest positive plus most negative.
  const __collapseM = (a, b) => Math.max(0, a, b) + Math.min(0, a, b);

  /// Max-content width, border included: what the element takes unconstrained.
  /// A flex item's basis is this width, not the whole line (Turnstile's api.js
  /// inserts an empty `div` into a centred row, and its position feeds the
  /// widget's report).
  function __maxContentW(el, depth) {
    depth = depth || 0;
    if (depth > 40 || !el || el.__ptType !== ELEMENT_NODE || __isUnboxed(el)) return 0;
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = __s_toLowerCase(el.__ptLocal || '');
    const len = (n) => __lengthPx(cs.get(n), fs, null);
    const bbox = /^border-box$/i.test(__s_trim(String(cs.get('box-sizing') || '')));
    const pad = (len('padding-left') || 0) + (len('padding-right') || 0)
      + (len('border-left-width') || 0) + (len('border-right-width') || 0);
    const clamp = (w) => {
      const hi = len('max-width'), lo = len('min-width');
      if (hi != null && w > (bbox ? hi : hi + pad)) w = bbox ? hi : hi + pad;
      if (lo != null && w < (bbox ? lo : lo + pad)) w = bbox ? lo : lo + pad;
      return w;
    };
    const w = len('width');
    if (w != null) return clamp(bbox ? w : w + pad);
    const ua = __uaBox(el, tag);
    if (ua && ua.w != null) return clamp(ua.w + pad);
    let familyRaw = cs.get('font-family');
    if (familyRaw == null) familyRaw = __inheritedValue(el, 'font-family');
    const family = __s_trim(String(familyRaw || '')) || 'sans-serif';
    const weight = cs.get('font-weight') || __inheritedValue(el, 'font-weight') || (UA_BOLD.has(tag) ? '700' : '');
    const bold = /(^|\s)(bold|[5-9]00)(\s|$)/i.test(String(weight));
    const text = __OWN_TEXT(el);
    let inner = text ? __textWidth(text, fs, family, bold, false) : 0;
    const kids = [];
    for (const c of (el.__ptKids || [])) {
      if (c.__ptType !== ELEMENT_NODE || __isUnboxed(c)) continue;
      const p = __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
      if (p !== 'absolute' && p !== 'fixed') kids.push(c);
    }
    const display = __s_toLowerCase(String(cs.get('display') || CS_DISPLAY[tag] || 'block'));
    const outer = (c) => {
      const ccs = __cascadeFor(c), cfs = __usedFontSize(c);
      return __maxContentW(c, depth + 1) + (__lengthPx(ccs.get('margin-left'), cfs, null) || 0)
        + (__lengthPx(ccs.get('margin-right'), cfs, null) || 0);
    };
    const gap = (n) => { const v = cs.get(n); return v == null || /normal/i.test(String(v)) ? 0 : (__lengthPx(v, fs, null) || 0); };
    if (/flex$/.test(display) && !/^column/.test(String(cs.get('flex-direction') || 'row'))) {
      inner += kids.reduce((a, c) => a + outer(c), 0) + gap('column-gap') * Math.max(0, kids.length - 1);
    } else if (/grid$/.test(display)) {
      const { place, n } = __gridPlacement(kids, Math.max(1, __gridTracks(cs.get('grid-template-columns'), 0, 0, fs).length));
      const cols = new Array(n).fill(0);
      kids.forEach((c, i) => { const k = place[i].k; cols[k] = Math.max(cols[k], outer(c)); });
      inner += cols.reduce((a, x) => a + x, 0) + gap('column-gap') * (n - 1);
    } else {
      // Inline children share a line; each block gets its own.
      let line = inner, widest = 0;
      for (const c of kids) {
        if (__isInlineLevel(c)) line += outer(c);
        else { widest = Math.max(widest, line, outer(c)); line = 0; }
      }
      inner = Math.max(widest, line);
    }
    return clamp(inner + pad);
  }

  function __isInlineLevel(el) {
    const tag = __s_toLowerCase(el.__ptLocal || '');
    const d = __s_toLowerCase(String(__cascadeFor(el).get('display') || CS_DISPLAY[tag] || 'block'));
    return /^inline(-block|-flex|-grid|-table)?$/.test(d);
  }

  // Atomic inline: a box placed whole on the line (`inline-block`, image,
  // input). A plain `<span>` is not: it flows and takes its font's height.
  const __ATOMIC_TAGS = new Set(['img', 'input', 'button', 'select', 'textarea', 'svg',
    'canvas', 'video', 'audio', 'object', 'embed', 'iframe', 'meter', 'progress']);
  function __isAtomicInline(el) {
    const tag = __s_toLowerCase(el.__ptLocal || '');
    const d = __s_toLowerCase(String(__cascadeFor(el).get('display') || CS_DISPLAY[tag] || 'block'));
    return d !== 'inline' || __ATOMIC_TAGS.has(tag);
  }

  // Inline run: left to right, wrapped by width, aligned on the baseline. An
  // atomic child sits on the baseline with its bottom edge, like `inline-block`.
  function __layoutInlineRun(run, originX, originY, availW, strut, strutLine) {
    const q = (v) => Math.floor(v * 64) / 64;
    const sAsc = strut ? strut.asc : strutLine * 0.8;
    const sDesc = Math.max(0, strutLine - sAsc);
    let y = originY, widest = 0;
    let line = [];
    let lineW = 0;
    const flush = () => {
      if (!line.length) return;
      // Empty inline boxes make no line: `<span></span>` has no height.
      const solid = line.some((it) => it.atomic || it.text);
      let asc = solid ? sAsc : 0, desc = solid ? sDesc : 0;
      for (const it of line) {
        const over = it.atomic ? it.box.h + it.mt + it.mb : (it.box.asc || sAsc);
        const under = it.atomic ? 0 : Math.max(0, (it.box.h || 0) - (it.box.asc || sAsc));
        asc = Math.max(asc, over);
        desc = Math.max(desc, under);
      }
      const height = solid ? asc + desc : 0;
      for (const it of line) {
        const top = it.atomic ? y + asc - it.box.h - it.mb : y + asc - (it.box.asc || sAsc);
        __ptShiftBox(it.el, it.x, q(top));
        widest = Math.max(widest, it.x + it.box.w + it.mr - originX);
      }
      y = q(y + height);
      line = [];
      lineW = 0;
    };
    for (const el of run) {
      const box = __layoutOne(el, originX, y, availW, strut);
      if (!box) continue;
      const cs = __cascadeFor(el);
      const cfs = __usedFontSize(el);
      const m = (name) => __lengthPx(cs.get(name), cfs, availW) || 0;
      const kids = (el.__ptKids || []).filter((k) => k.__ptType === ELEMENT_NODE);
      const it = {
        el, box, atomic: __isAtomicInline(el),
        text: !!__s_trim(String(__OWN_TEXT(el) || '')) || kids.length > 0,
        ml: m('margin-left'), mr: m('margin-right'), mt: m('margin-top'), mb: m('margin-bottom'),
        x: 0,
      };
      const outer = box.w + it.ml + it.mr;
      if (line.length && lineW + outer > availW + 0.5) flush();
      it.x = q(originX + lineW + it.ml);
      lineW += outer;
      line.push(it);
    }
    flush();
    return { y, widest };
  }

  // Move an already laid-out box with everything inside it. The box moves at
  // once; what is inside moves when the pass ends (`__layoutSettle`), by the
  // offsets collected on the way down: moving the subtree here copied every
  // box below once per level a move happened on (63% of a Wikipedia layout).
  // A box moved by (dx, dy), built with the layout literal's shape:
  // `Object.assign({}, box)` leaves a 23-field copy in dictionary mode, three
  // times larger and slower to read.
  function __boxAt(b, dx, dy) {
    return {
      x: b.x + dx, y: b.y + dy, w: b.w, h: b.h,
      cw: b.cw, ch: b.ch, cx: b.cx + dx, cy: b.cy + dy,
      bx: b.bx, by: b.by, mb: b.mb,
      mt: b.mt, mr: b.mr, ml: b.ml,
      line: b.line, inline: b.inline, lineTop: b.lineTop != null ? b.lineTop + dy : b.lineTop, lines: b.lines,
      asc: b.asc, desc: b.desc,
      sw: b.sw, sh: b.sh,
      bar: b.bar,
    };
  }
  function __ptShiftBox(el, x, y) {
    const b = el.__ptBox;
    if (!b) return;
    const dx = x - b.x, dy = y - b.y;
    if (!dx && !dy) return;
    // A moved box is a new object: layout results are kept by reference
    // (see `__layoutOne`) and must not change under them.
    el.__ptBox = __boxAt(b, dx, dy);
    const off = el.__ptOff;
    if (off) { off[0] += dx; off[1] += dy; } else el.__ptOff = [dx, dy];
  }
  // Apply the moves `__ptShiftBox` left pending: one walk down the tree,
  // each box moved by what its ancestors moved since it was laid out.
  function __layoutSettle(root) {
    const stack = [root, 0, 0];
    while (stack.length) {
      const ay = stack.pop(), ax = stack.pop(), node = stack.pop();
      let cx = ax, cy = ay;
      const b = node.__ptBox;
      if (b && node.__ptBoxV === __layoutBuilt && (ax || ay)) {
        node.__ptBox = __boxAt(b, ax, ay);
      }
      const off = node.__ptOff;
      if (off) { cx += off[0]; cy += off[1]; node.__ptOff = null; }
      for (const k of (node.__ptKids || [])) if (k.__ptType === ELEMENT_NODE) stack.push(k, cx, cy);
      if (node.__ptShadow) for (const k of (node.__ptShadow.__ptKids || [])) if (k.__ptType === ELEMENT_NODE) stack.push(k, cx, cy);
    }
  }

  // Flex and grid lay a child out more than once (measure, then place), so
  // nested containers repeated whole subtrees exponentially: 60 s on a store
  // locator page. A call with the same constraints as an earlier one (in this
  // pass, or an earlier one if no change reached the element since, see
  // `__layoutForget`) restores that result instead, moved to the new origin. Only
  // moves on the 1/64 px grid: lengths are floored to it, and such a move
  // floors the same as a fresh layout (off-grid positions may differ in the
  // last bit of the double).
  // Frames told their size during this pass, in order: a restored subtree
  // tells them again exactly as a fresh layout would.
  let __tellLog = [];
  function __ptTellLogged(el, box) {
    __tellLog.push([el, box && __boxAt(box, 0, 0)]);
    // A pass laid out in bands tells frames once, from its final log.
    if (!__layoutDeep) __ptTellFrame(el, box);
  }
  const __on64 = (v) => typeof v === 'number' && Number.isInteger(v * 64) && Math.abs(v) < 2 ** 40;
  // A kept layout is a tree: the element's own result and, per child laid
  // out under it (in first-call order), the child's last entry and where
  // the child ended up (the parent may move it after). A flat copy of the
  // whole subtree per element cost depth x size: 228,000 records for 12,800
  // elements on a Wikipedia article.
  // `__layoutKids`: the children laid out so far by the call in progress
  // (a Map), `true` while it has none yet, null outside a layout.
  let __layoutKids = null;
  const __NO_KIDS = [];
  const __offCopy = (off) => (off ? [off[0], off[1]] : null);
  // Mostly empty, and the first write of an engine field on an element
  // defines a property: unset stays unset.
  const __setDefH = (el, v) => { if (v != null || el.__ptDefH != null) el.__ptDefH = v; };
  const __setOff = (el, v) => { if (v || el.__ptOff) el.__ptOff = v; };
  // Depth first without recursion: (entry, node, next child index) runs.
  // A child is set from its own entry, then from where its parent left it.
  function __layoutRestore(ent, el) {
    __boxes.push(el);
    const stack = [ent, el, 0];
    while (stack.length) {
      const top = stack.length - 3;
      const e = stack[top], i = stack[top + 2], kids = e.kids;
      if (i < kids.length) {
        stack[top + 2] = i + 5;
        __boxes.push(kids[i]);
        stack.push(kids[i + 1], kids[i], 0);
        continue;
      }
      const node = stack[top + 1];
      stack.length = top;
      if (e.box) {
        node.__ptBox = e.box;
        node.__ptBoxV = __layoutBuilt;
        __setDefH(node, e.defH);
        __setOff(node, __offCopy(e.off));
      }
      if (!stack.length) break;
      const rec = stack[stack.length - 3].kids, j = stack[stack.length - 1] - 5;
      if (rec[j + 2]) {
        node.__ptBox = rec[j + 2];
        node.__ptBoxV = __layoutBuilt;
        __setDefH(node, rec[j + 3]);
        __setOff(node, __offCopy(rec[j + 4]));
      }
    }
  }
  // Layout recurses a few frames per level, and the JS stack a page sees is
  // Chrome's size: 467 nested blocks threw RangeError (Chrome lays out
  // tens of thousands). A pass goes at most `__LAYOUT_BAND` levels deep; an
  // element below is put off (its ancestors' results are not kept), laid
  // out from a shallow stack into the kept layouts, and the band above is
  // laid out again, restoring it.
  const __LAYOUT_BAND = 64;
  let __layoutDepth = 0, __layoutDeferred = [], __layoutTaint = 0;
  // Some element was put off in this pass: frames are told at its end.
  let __layoutDeep = false;
  // The next call is a put-off element's own: kept even when absolute.
  let __layoutForceKeep = false;
  // A solve that has not settled after many rounds lays out unbanded.
  let __layoutUnbanded = false;
  function __layoutSolve(call) {
    for (let round = 0; ; round++) {
      const sDepth = __layoutDepth, sDef = __layoutDeferred, sKids = __layoutKids;
      __layoutDepth = 0;
      __layoutDeferred = [];
      __layoutKids = null;
      const sUnb = __layoutUnbanded;
      if (round >= 64) __layoutUnbanded = true;
      let put;
      try { call(); } finally {
        __layoutUnbanded = sUnb;
        put = __layoutDeferred;
        __layoutDepth = sDepth;
        __layoutDeferred = sDef;
        __layoutKids = sKids;
      }
      if (!put.length) return;
      for (const d of put) {
        __layoutSolve(() => {
          __layoutForceKeep = true;
          __layoutOne(d.el, d.x, d.y, d.w, d.strut, d.forced);
        });
      }
    }
  }
  function __layoutOne(el, originX, originY, availW, strut, forced) {
    // Absolute children are placed against a containing block: kept only
    // when put off below a band, keyed by that block and the origin.
    const cb = forced && forced.cb;
    const forceKeep = __layoutForceKeep;
    __layoutForceKeep = false;
    const keep = !cb || forceKeep;
    let key = null, mine;
    {
      const up = el.__ptParent;
      key = availW + '|' + (strut ? strut.line + ',' + strut.asc + ',' + strut.desc : '-') + '|'
        + (forced ? (forced.w === undefined ? 'u' : forced.w) + ',' + (forced.h === undefined ? 'u' : forced.h) + ',' + (forced.block ? 1 : 0) : '-')
        + '|' + (up && up.__ptType === ELEMENT_NODE ? (up.__ptDefH == null ? null : up.__ptDefH) : '-');
      if (cb) key += '|cb' + cb.x + ',' + cb.y + ',' + cb.w + ',' + cb.h + '|' + originX + ',' + originY;
      mine = __layoutMemo.get(el);
      const hit = mine && mine.get(key);
      if (hit) {
        const dx = originX - hit.ox, dy = originY - hit.oy;
        if (__on64(dx) && __on64(dy)) {
          __layoutRestore(hit, el);
          // The subtree moves with its root, pending like any other move.
          if ((dx || dy) && el.__ptBox) __ptShiftBox(el, el.__ptBox.x + dx, el.__ptBox.y + dy);
          for (const [n, b] of hit.tells) __ptTellLogged(n, b);
          if (__layoutKids !== null) {
            if (__layoutKids === true) __layoutKids = new Map();
            __layoutKids.set(el, hit);
          }
          return el.__ptBox;
        }
      }
    }
    if (__layoutDepth >= __LAYOUT_BAND && !__layoutUnbanded) {
      __layoutTaint++;
      __layoutDeep = true;
      __layoutDeferred.push({ el, x: originX, y: originY, w: availW, strut, forced });
      return null;
    }
    const outer = __layoutKids, tellStart = __tellLog.length, taint = __layoutTaint;
    __layoutKids = true;
    __layoutDepth++;
    let ret, kids;
    try {
      ret = __layoutOneRaw(el, originX, originY, availW, strut, forced);
    } finally {
      kids = __layoutKids;
      __layoutKids = outer;
      __layoutDepth--;
    }
    const list = [];
    if (kids !== true) {
      for (const [c, e] of kids) list.push(c, e, c.__ptBox, c.__ptDefH, __offCopy(c.__ptOff));
    }
    const ent = {
      ox: originX, oy: originY, box: el.__ptBox, defH: el.__ptDefH, off: __offCopy(el.__ptOff),
      // At their length: a pushed-to array keeps spare room.
      kids: list.length ? list.slice() : __NO_KIDS,
      tells: __tellLog.length > tellStart ? __s_slice(__tellLog, tellStart) : __NO_KIDS,
    };
    if (outer !== null) {
      if (outer === true) __layoutKids = new Map();
      __layoutKids.set(el, ent);
    }
    // A result built on a put-off element's stand-in is not kept.
    if (keep && taint === __layoutTaint) {
      __lstats.keptRecords += 1 + list.length / 5;
      if (!mine) __layoutMemo.set(el, (mine = new Map()));
      // Kept across passes now: a few constraint sets per element, not all of
      // them ever seen.
      else if (mine.size >= 8) mine.clear();
      mine.set(key, ent);
    }
    return ret;
  }

  const __MARGIN_SIDES = ['margin-top', 'margin-right', 'margin-bottom', 'margin-left'];
  const __PADDING_SIDES = ['padding-top', 'padding-right', 'padding-bottom', 'padding-left'];
  function __layoutOneRaw(el, originX, originY, availW, strut, forced) {
    __lstats.layoutEls++;
    __setOff(el, null);
    // Document order, not after children: hit testing scans from the end and a
    // deeper element must come after its parent.
    __boxes.push(el);
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = __s_toLowerCase(el.__ptLocal || '');
    // Font is inherited; without it a `<span>` was measured in the fallback
    // face and word widths and line heights were off.
    let familyRaw = cs.get('font-family');
    if (familyRaw == null) familyRaw = cs.get('font');
    if (familyRaw == null && typeof __inheritedValue === 'function') {
      familyRaw = __inheritedValue(el, 'font-family');
    }
    const family = __s_trim(String(familyRaw || '')) || 'sans-serif';
    let weight = cs.get('font-weight') || cs.get('font');
    // The UA sheet beats inheritance: `<b>` is bold whatever the parent weight.
    if (weight == null && UA_BOLD.has(tag)) weight = '700';
    if (weight == null && typeof __inheritedValue === 'function') {
      weight = __inheritedValue(el, 'font-weight');
    }
    const bold = /(^|\s)(bold|[5-9]00)(\s|$)/i.test(String(weight || ''));
    const len = (name, base) => __lengthPx(cs.get(name), fs, base);
    const side = (prefix, names) => {
      const one = [len(names[0], availW), len(names[1], availW), len(names[2], availW), len(names[3], availW)];
      const all = cs.get(prefix);
      if (all != null) {
        const parts = __s_split(__s_trim(String(all)), /\s+/);
        for (let i = 0; i < 4; i++) {
          if (one[i] == null) one[i] = __lengthPx(parts[Math.min(i, parts.length - 1)], fs, availW);
        }
      }
      return one;
    };
    const rawM = side('margin', __MARGIN_SIDES);
    // An author 0 is a set value: `body { margin: 0 }` must not get the UA 8px.
    const setM = [rawM[0] != null, rawM[1] != null, rawM[2] != null, rawM[3] != null];
    let mt = rawM[0] || 0, mr = rawM[1] || 0, mb = rawM[2] || 0, ml = rawM[3] || 0;
    const rawP = side('padding', __PADDING_SIDES);
    let pt_ = rawP[0] || 0, pr = rawP[1] || 0, pb = rawP[2] || 0, pl = rawP[3] || 0;
    let bt = len('border-top-width', availW) || 0, br = len('border-right-width', availW) || 0,
      bb = len('border-bottom-width', availW) || 0, bl = len('border-left-width', availW) || 0;
    const borderAll = cs.get('border') || cs.get('border-width');
    if (borderAll != null && !bt && !br && !bb && !bl) {
      const m = /(-?[\d.]+)px/.exec(String(borderAll));
      const w = m && !/\bnone\b/.test(String(borderAll)) ? parseFloat(m[1]) : 0;
      bt = br = bb = bl = w;
    }
    const display = __s_toLowerCase(String(cs.get('display') || CS_DISPLAY[tag] || 'block'));
    const ovAll = __s_toLowerCase(String(cs.get('overflow') || ''));
    const ovX = __s_toLowerCase(String(cs.get('overflow-x') || ovAll || 'visible'));
    const ovY = __s_toLowerCase(String(cs.get('overflow-y') || ovAll || 'visible'));
    // A flex item is blockified whatever its `display`; its height is the line,
    // not the ink.
    const forcedW = !!(forced && forced.w != null);
    const inlineish = __INLINEISH.test(display) && !(forced && forced.block);
    const position = __s_toLowerCase(String(cs.get('position') || 'static'));

    // UA margins side by side: an author's `margin-bottom: 0` keeps the
    // UA's top margin.
    const uam = __uaMargin(tag, fs, el);
    if (uam) {
      if (!setM[0]) mt = uam[0];
      if (!setM[2]) mb = uam[0];
      if (!setM[3]) ml = uam[1];
      if (!setM[1]) mr = uam[1];
    }
    const ua = __uaBox(el, tag);
    if (ua) {
      if (!pt_ && !pb && ua.p) { pt_ = ua.p[0]; pb = ua.p[0]; }
      if (!pl && !pr && ua.p) { pl = ua.p[1]; pr = ua.p[1]; }
      if (!bt && !br && !bb && !bl && ua.b) { bt = br = bb = bl = ua.b; }
      if (ua.m) {
        if (!setM[0]) mt = ua.m[0];
        if (!setM[2]) mb = ua.m[0];
        if (!setM[3]) ml = ua.m[1];
        if (!setM[1]) mr = ua.m[1];
      }
    }
    // `box-sizing: border-box`: the size includes padding and border.
    const bbox = /^border-box$/i.test(__s_trim(String(cs.get('box-sizing') || '')));
    const inW = (v) => (v == null ? null : bbox ? Math.max(0, v - pl - pr - bl - br) : v);
    const inH = (v) => (v == null ? null : bbox ? Math.max(0, v - pt_ - pb - bt - bb) : v);
    // Percent heights are relative to the parent's set height; the root's is
    // the viewport.
    const up = el.__ptParent;
    // An absolute child resolves percentages against the containing block the
    // parent passed (its padding box), not the page.
    const __cb = (position === 'absolute' || position === 'fixed') && forced && forced.cb ? forced.cb : null;
    const baseH = __cb && __cb.h != null ? __cb.h : (up && up.__ptType === ELEMENT_NODE
      ? (up.__ptDefH != null ? up.__ptDefH : null) : LAYOUT.H);
    if (__cb && __cb.w != null) availW = __cb.w;
    const explicitW = inW(len('width', availW));
    const explicitH = inH(len('height', baseH));
    __setDefH(el, explicitH);
    const frame = tag === 'iframe' || tag === 'img' || tag === 'canvas' || tag === 'video';
    const attrW = frame && el.getAttribute ? __lengthPx(__ptGetA(el, 'width'), fs, availW) : null;
    const attrH = frame && el.getAttribute ? __lengthPx(__ptGetA(el, 'height'), fs, availW) : null;

    let cw = explicitW != null ? explicitW : attrW;
    if (cw == null && ua) {
      cw = ua.label
        ? __textWidth((el.getAttribute && __ptGetA(el, 'value')) || __OWN_TEXT(el) || ua.dflt || '',
                      fs, family, bold, false)
        : ua.w;
    }
    // Measuring with no available width (`availW` null: shrink-to-fit for a
    // grid column or flex item) sizes the block by its children, not NaN.
    const shrinkToFit = cw == null && !inlineish && availW == null;
    if (cw == null && !inlineish && availW != null) cw = Math.max(0, availW - ml - mr - bl - br - pl - pr);
    // Width limits; without them a `max-width` column took the whole window.
    if (cw != null) {
      const maxW = inW(len('max-width', availW));
      const minW = inW(len('min-width', availW));
      if (maxW != null && cw > maxW) cw = maxW;
      if (minW != null && cw < minW) cw = minW;
    }
    // `margin: 0 auto` centres the block; the challenge reads rects of ~15
    // nodes.
    const autoSide = (name) => {
      const v = cs.get(name);
      if (v != null) return /^auto$/i.test(__s_trim(String(v)));
      const all = cs.get('margin');
      if (all == null) return false;
      const parts = __s_split(__s_trim(String(all)), /\s+/);
      const i = name === 'margin-left' ? 3 : 1;
      return /^auto$/i.test(parts[[0, 1, 2, 3].map((k) => Math.min(k, parts.length - 1))[i]] || '');
    };
    if (!inlineish && cw != null && (autoSide('margin-left') || autoSide('margin-right'))) {
      const free = Math.max(0, availW - cw - bl - br - pl - pr);
      const left = autoSide('margin-left'), right = autoSide('margin-right');
      if (left && right) { ml = free / 2; mr = free / 2; }
      else if (left) ml = free - mr;
      else mr = free - ml;
    }
    // A flex parent assigns the child's size before the child lays out its
    // content, so lines wrap at the right width.
    if (forced && forced.w != null) cw = Math.max(0, forced.w - pl - pr - bl - br);

    let boxX = originX + ml, boxY = originY + mt;
    if (position === 'absolute' || position === 'fixed') {
      // Offsets are from the containing block (padding box of the positioned
      // ancestor), not the page: `inset:0` inside a padded block is its corner.
      const ox = __cb ? __cb.x : originX, oy = __cb ? __cb.y : originY;
      const cbw = __cb && __cb.w != null ? __cb.w : availW, cbh = __cb && __cb.h != null ? __cb.h : null;
      const left = len('left', cbw), top = len('top', cbh), right = len('right', cbw), bottom = len('bottom', cbh);
      if (left != null) boxX = ox + left + ml;
      else if (right != null && cbw != null && explicitW != null) boxX = ox + cbw - right - mr - (explicitW + pl + pr + bl + br);
      if (top != null) boxY = oy + top + mt;
      else if (bottom != null && cbh != null && explicitH != null) boxY = oy + cbh - bottom - mb - (explicitH + pt_ + pb + bt + bb);
    }

    const kids = [];
    if (el.__ptShadow) for (const c of el.__ptShadow.__ptKids) kids.push(c);
    for (const c of (el.__ptKids || [])) kids.push(c);
    const boxedKids = kids.filter((c) => c.__ptType === ELEMENT_NODE && !__isUnboxed(c));

    // An inline element shrinks to its children, or else to its own text
    // measured in the real face.
    if (cw == null) {
      cw = boxedKids.length ? 0 : __textWidth(__OWN_TEXT(el), fs, family, bold, false);
    }
    if (forcedW) cw = Math.max(0, forced.w - pl - pr - bl - br);

    const fbox = __fontBox(fs, family);
    // Line height comes from the style, not font metrics: `font: 16px/1.4`
    // makes a 22.4px line, and a flex item is exactly that tall.
    let lineH = fbox.line;
    {
      let lh = cs.get('line-height');
      if (lh == null && typeof __inheritedValue === 'function') lh = __inheritedValue(el, 'line-height');
      const t = lh == null ? '' : __s_trim(String(lh));
      if (t && t !== 'normal') {
        // Multiplier and percentage are relative to the font size.
        lineH = __lineHeightPx(t, fs, availW, fbox.line);
      }
    }
    const contentX = boxX + bl + pl;
    let contentY = boxY + bt + pt_;
    // Child margins escaping through the parent's empty edge.
    let escapedTop = 0, escapedBottom = 0, hasEscapedTop = false;
    let y = contentY, widest = 0, deepest = 0;
    // Flex container: children in a row (or column), free space split by
    // `flex-grow`, shortfall by `flex-shrink`, stretched on the cross axis by
    // default. Widgets are almost always flex.
    const flexish = display === 'flex' || display === 'inline-flex';
    // Grid: children in cells, rows as tall as the tallest, `gap` gutters,
    // stretch within the cell.
    const gridish = display === 'grid' || display === 'inline-grid';
    if (gridish && boxedKids.length) {
      const gapLen = (n) => {
        const v = cs.get(n);
        if (v == null || /^normal$/i.test(__s_trim(String(v)))) return 0;
        return __lengthPx(v, fs, cw) || 0;
      };
      const colGap = gapLen('column-gap'), rowGap = gapLen('row-gap');
      const flow = boxedKids.filter((c) => {
        const p = __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
        return p !== 'absolute' && p !== 'fixed';
      });
      // Without a column template every column is `auto`, including implicit
      // ones created by `grid-column: 2`.
      const tmplCols = __s_toLowerCase(__s_trim(String(cs.get('grid-template-columns') == null ? 'none' : cs.get('grid-template-columns'))));
      const cols = tmplCols === 'none' || tmplCols === 'auto' || tmplCols === '' ? [{ auto: true }] : __gridTracks(cs.get('grid-template-columns'), cw, colGap, fs);
      // Explicit placement (`grid-area: 1/1`, `grid-column: 2`) and row-wise
      // auto-placement into free cells; implicit columns are `auto`.
      const { place, n, want } = __gridPlacement(flow, cols.length);
      while (cols.length < n) cols.push({ auto: true });
      const marg = (c, a, b) => {
        const ccs = __cascadeFor(c), cfs = __usedFontSize(c);
        return (__lengthPx(ccs.get(a), cfs, cw) || 0) + (__lengthPx(ccs.get(b), cfs, cw) || 0);
      };
      // Column widths: fixed as is, fractions from the remainder, `auto` by
      // content; a remainder without fractions is split evenly among `auto`.
      const widths = cols.map((t) => (t.px != null ? t.px : 0));
      const frTotal = cols.reduce((a, t) => a + (t.fr || 0), 0);
      const autos = [];
      cols.forEach((t, k) => { if (t.auto) autos.push(k); });
      // A grid with no set width inside a flex or grid parent (or an inline
      // grid) shrinks to content: auto columns take the widest child, no free
      // space.
      const parentDisp = __s_toLowerCase(String((el.__ptParent && el.__ptParent.__ptType === ELEMENT_NODE ? __cascadeFor(el.__ptParent).get('display') : '') || ''));
      const shrinkGrid = !forcedW && explicitW == null && (inlineish || /flex|grid/.test(parentDisp));
      if (autos.length) {
        flow.forEach((c, i) => {
          const k = place[i].k;
          if (!cols[k].auto) return;
          // A child's contribution to an auto column is its max-content
          // (measured with no width); otherwise a block child takes it all.
          const b = __layoutOne(c, contentX, contentY, null, fbox) || { w: 0 };
          widths[k] = Math.max(widths[k], b.w + marg(c, 'margin-left', 'margin-right'));
        });
      }
      const usedW = widths.reduce((a, w) => a + w, 0) + colGap * Math.max(0, n - 1);
      let freeW = shrinkGrid ? 0 : Math.max(0, cw - usedW);
      if (frTotal) cols.forEach((t, k) => { if (t.fr) widths[k] = freeW * t.fr / frTotal; });
      else if (autos.length && !shrinkGrid) { for (const k of autos) widths[k] += freeW / autos.length; freeW = 0; }
      const totalW = widths.reduce((a, w) => a + w, 0) + colGap * Math.max(0, n - 1);
      if (globalThis.__pt_gridTrace) { try { (globalThis.__pt_parentConsole || console).error('[grid] ' + __ptJSON.stringify({ tag: el.__ptLocal, id: el.id, availW, cw, shrinkGrid, forcedW: !!forcedW, explicitW, n, place, widths, totalW, want })); } catch (e) {} }
      const jc = __s_toLowerCase(String(cs.get('justify-content') || 'normal'));
      const slackW = Math.max(0, cw - totalW);
      const leadX = jc === 'center' ? slackW / 2 : (jc === 'end' || jc === 'flex-end' || jc === 'right') ? slackW : 0;
      const colX = [];
      { let x = contentX + leadX; for (let k = 0; k < n; k++) { colX.push(x); x += widths[k] + colGap; } }
      const rowsT = __gridTracks(cs.get('grid-template-rows'), explicitH != null ? explicitH : 0, rowGap, fs, true);
      const ji = __s_toLowerCase(String(cs.get('justify-items') || 'normal'));
      const ai = __s_toLowerCase(String(cs.get('align-items') || 'normal'));
      const selfOf = (c, prop, dflt) => {
        const v = __s_toLowerCase(String(__cascadeFor(c).get(prop) || 'auto'));
        return v === 'auto' ? dflt : v;
      };
      const stretchy = (v) => v === 'normal' || v === 'stretch' || v === 'legacy';
      // First pass: row heights.
      const nRows = Math.max(1, ...place.map((p) => p.r + 1));
      const rowH = new Array(nRows).fill(0);
      flow.forEach((c, i) => {
        const { k, r } = place[i];
        const ccs = __cascadeFor(c);
        const js = selfOf(c, 'justify-self', ji);
        const fixedW = ccs.get('width') != null && !/^auto$/i.test(__s_trim(String(ccs.get('width'))));
        const mx = marg(c, 'margin-left', 'margin-right');
        const b = __layoutOne(c, colX[k], contentY, widths[k], fbox,
          stretchy(js) && !fixedW ? { w: Math.max(0, widths[k] - mx), block: true } : { block: true }) || { h: 0 };
        rowH[r] = Math.max(rowH[r], b.h + marg(c, 'margin-top', 'margin-bottom'));
      });
      for (let r = 0; r < nRows; r++) {
        const t = rowsT[r];
        if (t && t.px != null) rowH[r] = t.px;
      }
      const totalH = rowH.reduce((a, h) => a + h, 0) + rowGap * Math.max(0, nRows - 1);
      const ac = __s_toLowerCase(String(cs.get('align-content') || 'normal'));
      const boxH = explicitH != null ? explicitH : null;
      const slackH = boxH != null ? Math.max(0, boxH - totalH) : 0;
      const leadY = ac === 'center' ? slackH / 2 : (ac === 'end' || ac === 'flex-end') ? slackH : 0;
      // Second pass: final positions.
      const rowY = [];
      { let yy = contentY + leadY; for (let r = 0; r < nRows; r++) { rowY.push(yy); yy += rowH[r] + rowGap; } }
      flow.forEach((c, i) => {
        const { k, r } = place[i];
        const ccs = __cascadeFor(c);
        const js = selfOf(c, 'justify-self', ji), as = selfOf(c, 'align-self', ai);
        const fixedW = ccs.get('width') != null && !/^auto$/i.test(__s_trim(String(ccs.get('width'))));
        const fixedH = ccs.get('height') != null && !/^auto$/i.test(__s_trim(String(ccs.get('height'))));
        const mx = marg(c, 'margin-left', 'margin-right'), my = marg(c, 'margin-top', 'margin-bottom');
        const sw = stretchy(js) && !fixedW, sh = stretchy(as) && !fixedH;
        let x = colX[k], yy = rowY[r];
        if (!sw || !sh) {
          const probe = __layoutOne(c, x, yy, widths[k], fbox,
            { w: sw ? Math.max(0, widths[k] - mx) : null, h: null, block: true }) || { w: 0, h: 0 };
          if (!sw) {
            const free = widths[k] - probe.w - mx;
            if (js === 'center') x += free / 2;
            else if (js === 'end' || js === 'flex-end' || js === 'right' || js === 'self-end') x += free;
          }
          if (!sh) {
            const free = rowH[r] - probe.h - my;
            if (as === 'center') yy += free / 2;
            else if (as === 'end' || as === 'flex-end' || as === 'self-end') yy += free;
          }
        }
        const cb = __layoutOne(c, x, yy, widths[k], fbox, {
          w: sw ? Math.max(0, widths[k] - mx) : null,
          h: sh ? Math.max(0, rowH[r] - my) : null,
          block: true,
        });
        if (cb) {
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
        }
      });
      y = contentY + Math.max(totalH, 0);
      if ((inlineish || shrinkGrid) && !forcedW && explicitW == null) cw = Math.min(cw || totalW, totalW) || totalW;
      for (const c of boxedKids) {
        const p = __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
        if (p === 'absolute' || p === 'fixed') __layoutOne(c, contentX, contentY, cw, fbox, { cb: { x: boxX + bl, y: boxY + bt, w: cw + pl + pr, h: (y - contentY) + pt_ + pb } });
      }
    } else if (flexish && boxedKids.length) {
      const dir = __s_toLowerCase(String(cs.get('flex-direction') || 'row'));
      const row = __s_lastIndexOf(dir, 'column', 0) !== 0;
      const reverse = /-reverse$/.test(dir);
      const gapMain = len(row ? 'column-gap' : 'row-gap', cw) || 0;
      const align = __s_toLowerCase(String(cs.get('align-items') || 'normal'));
      const justify = __s_toLowerCase(String(cs.get('justify-content') || 'normal'));
      const flow = boxedKids.filter((c) => {
        const p = __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
        return p !== 'absolute' && p !== 'fixed';
      });
      // First pass: natural sizes.
      const items = flow.map((c) => {
        const ccs = __cascadeFor(c);
        // A shrink-to-fit container measures its children by content too, not
        // at zero width.
        const cb = __layoutOne(c, contentX, contentY, shrinkToFit ? null : cw, fbox) || { w: 0, h: 0 };
        const cfs = __usedFontSize(c);
        const mw = (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0)
                 + (__lengthPx(ccs.get('margin-right'), cfs, cw) || 0);
        const mh = (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0)
                 + (__lengthPx(ccs.get('margin-bottom'), cfs, cw) || 0);
        const num = (v, dflt) => { const n = parseFloat(v); return Number.isFinite(n) ? n : dflt; };
        const basis = __s_toLowerCase(String(ccs.get('flex-basis') || 'auto'));
        const basisPx = basis === 'auto' || basis === 'content'
          ? null : __lengthPx(basis, cfs, cw);
        // Basis in a row is the content width when no width is set.
        const autoW = ccs.get('width') == null || /^auto$/i.test(__s_trim(String(ccs.get('width'))));
        const natural = row ? (autoW ? (shrinkToFit ? cb.w : Math.min(cb.w, __maxContentW(c))) : cb.w) : cb.h;
        return {
          el: c, box: cb,
          grow: num(ccs.get('flex-grow'), 0),
          shrink: num(ccs.get('flex-shrink'), 1),
          base: basisPx != null ? basisPx : natural,
          mMain: row ? mw : mh, mCross: row ? mh : mw,
        };
      });
      const gaps = gapMain * Math.max(0, items.length - 1);
      const used = items.reduce((a, it) => a + it.base + it.mMain, 0) + gaps;
      if (row && shrinkToFit) cw = used;
      // A column with no set height is as tall as its content, clamped by
      // `min-height`/`max-height`.
      let inner = cw;
      if (!row) {
        if (explicitH != null) inner = explicitH;
        else {
          const lo = inH(len('min-height', baseH)), hi = inH(len('max-height', baseH));
          inner = used;
          if (hi != null && inner > hi) inner = hi;
          if (lo != null && inner < lo) inner = lo;
        }
      }
      let free = inner - used;
      if (free > 0) {
        const total = items.reduce((a, it) => a + it.grow, 0);
        if (total > 0) for (const it of items) it.main = it.base + free * (it.grow / total);
        else for (const it of items) it.main = it.base;
      } else if (free < 0) {
        const total = items.reduce((a, it) => a + it.shrink * it.base, 0);
        for (const it of items) {
          it.main = total > 0
            ? Math.max(0, it.base + free * ((it.shrink * it.base) / total))
            : it.base;
        }
      } else for (const it of items) it.main = it.base;
      const taken = items.reduce((a, it) => a + it.main + it.mMain, 0) + gaps;
      const slack = Math.max(0, inner - taken);
      let lead = 0, between = gapMain;
      if (justify === 'center') lead = slack / 2;
      else if (justify === 'flex-end' || justify === 'end' || justify === 'right') lead = slack;
      else if (justify === 'space-between' && items.length > 1) between += slack / (items.length - 1);
      else if (justify === 'space-around' && items.length) {
        lead = slack / items.length / 2; between += slack / items.length;
      } else if (justify === 'space-evenly' && items.length) {
        lead = slack / (items.length + 1); between += slack / (items.length + 1);
      }
      // Cross size of the line: the container's set height or the tallest
      // child.
      const crossOuter = items.reduce((a, it) => Math.max(a, (row ? it.box.h : it.box.w) + it.mCross), 0);
      const lineCross = row
        ? (explicitH != null ? explicitH : crossOuter)
        : cw;
      const order = reverse ? __s_slice(items).reverse() : items;
      let along = lead;
      for (const it of order) {
        const ccs = __cascadeFor(it.el);
        const self = __s_toLowerCase(String(ccs.get('align-self') || 'auto'));
        const how = self !== 'auto' && self !== 'normal' ? self : align;
        const cfs = __usedFontSize(it.el);
        const mLead = row ? (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0)
                          : (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0);
        const mCrossLead = row ? (__lengthPx(ccs.get('margin-top'), cfs, cw) || 0)
                               : (__lengthPx(ccs.get('margin-left'), cfs, cw) || 0);
        const natCross = row ? it.box.h : it.box.w;
        const stretch = (how === 'normal' || how === 'stretch')
          && (row ? explicitH != null || items.length > 0 : true);
        const crossSize = stretch ? Math.max(0, lineCross - it.mCross) : natCross;
        let crossPos = mCrossLead;
        if (!stretch) {
          if (how === 'center') crossPos = Math.max(0, (lineCross - natCross - it.mCross) / 2) + mCrossLead;
          else if (how === 'flex-end' || how === 'end') crossPos = Math.max(0, lineCross - natCross - it.mCross) + mCrossLead;
        }
        const x = row ? contentX + along + mLead : contentX + crossPos;
        const yy = row ? contentY + crossPos : contentY + along + mLead;
        const cb = __layoutOne(it.el, x - mLead, yy - (row ? mCrossLead : mLead), cw, fbox,
          row ? { w: it.main, h: stretch ? crossSize : null, block: true }
              : { w: stretch ? crossSize : null, h: it.main, block: true });
        if (cb) {
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
        }
        along += it.main + it.mMain + between;
      }
      // The gap goes between children, not after the last.
      y = contentY + (row ? lineCross : Math.max(0, along - (order.length ? between : 0)));
      // Otherwise as a block: absolute children are placed on their own.
      for (const c of boxedKids) {
        const p = __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
        if (p === 'absolute' || p === 'fixed') __layoutOne(c, contentX, contentY, cw, fbox, { cb: { x: boxX + bl, y: boxY + bt, w: cw + pl + pr, h: (y - contentY) + pt_ + pb } });
      }
    } else {
      // Blocks stack, inline content flows into lines wrapped at the content
      // width.
      let i = 0;
      // Adjacent margins collapse (16px between two paragraphs, not 32). The
      // first and last child's margin escapes to the parent when the parent
      // has no border or padding on that side.
      let carry = 0;          // previous block's bottom margin, pending collapse
      let firstFlow = true;
      const positionOf = (c) => __s_toLowerCase(String(__cascadeFor(c).get('position') || 'static'));
      while (i < boxedKids.length) {
        const c = boxedKids[i];
        const cpos = positionOf(c);
        if (cpos === 'absolute' || cpos === 'fixed') {
          const cb = __layoutOne(c, contentX, y, cw, fbox, { cb: { x: boxX + bl, y: boxY + bt, w: cw + pl + pr, h: explicitH != null ? explicitH + pt_ + pb : null } });
          if (cb) {
            widest = Math.max(widest, cb.x - contentX + cb.w);
            deepest = Math.max(deepest, cb.y - contentY + cb.h);
          }
          i++;
          continue;
        }
        if (!__isInlineLevel(c)) {
          let cb = __layoutOne(c, contentX, y, cw, fbox);
          i++;
          if (!cb) continue;
          const cmt = cb.mt || 0;
          // Only the first in flow escapes, and only through an empty edge.
          // Sibling margins collapse to the larger: the box already sits on its
          // own margin, so add only the difference. Negative margins collapse
          // too: largest positive plus most negative.
          const escapes = firstFlow && !bt && !pt_;
          const shift = escapes ? -cmt : __collapseM(carry, cmt) - cmt;
          if (escapes) { escapedTop = cmt; hasEscapedTop = true; }
          if (shift) { __ptShiftBox(c, cb.x, cb.y + shift); cb = c.__ptBox; }
          widest = Math.max(widest, cb.x - contentX + cb.w);
          deepest = Math.max(deepest, cb.y - contentY + cb.h);
          y = cb.y + cb.h;
          carry = cb.mb || 0;
          firstFlow = false;
          continue;
        }
        const run = [];
        while (i < boxedKids.length && __isInlineLevel(boxedKids[i])
               && positionOf(boxedKids[i]) !== 'absolute' && positionOf(boxedKids[i]) !== 'fixed') {
          run.push(boxedKids[i++]);
        }
        // A line next to a block uses the full margin: nothing to collapse.
        const done = __layoutInlineRun(run, contentX, y + carry, cw, fbox, lineH);
        y = done.y;
        carry = 0;
        firstFlow = false;
        widest = Math.max(widest, done.widest);
        deepest = Math.max(deepest, y - contentY);
      }
      // The last child's bottom margin stays inside only if the parent's edge
      // is not empty.
      if (carry && (bb || pb)) y += carry;
      else if (carry) escapedBottom = carry;
    }
    // An escaped margin becomes the parent's own margin: the block moves down,
    // the children stay where they were.
    const collapsedTop = hasEscapedTop ? __collapseM(mt, escapedTop) : mt;
    if (collapsedTop !== mt) {
      const delta = collapsedTop - mt;
      for (const c of boxedKids) {
        if (c.__ptBox) __ptShiftBox(c, c.__ptBox.x, c.__ptBox.y + delta);
      }
      boxY += delta; contentY += delta; y += delta;
      mt = collapsedTop;
    }
    if (escapedBottom) mb = __collapseM(mb, escapedBottom);
    if ((inlineish || shrinkToFit) && explicitW == null && !forcedW && boxedKids.length) cw = widest;

    let ch;
    let lines = null;
    const ownText = __OWN_TEXT(el);
    if (ownText && !boxedKids.length) {
      lines = __wrapLines(ownText, inlineish && explicitW == null && !forcedW ? 0 : cw, fs, family, bold);
      if (inlineish && explicitW == null && !forcedW && lines.length === 1) cw = lines[0].width;
    }
    if (forced && forced.h != null) ch = Math.max(0, forced.h - pt_ - pb - bt - bb);
    else if (explicitH != null) ch = explicitH;
    else if (attrH != null) ch = attrH;
    else if (boxedKids.length) ch = Math.max(0, y - contentY);
    else if (lines && lines.length) ch = lines.length * lineH;
    // An empty inline box has no height: an empty `inline-block` is 0 tall.
    else ch = (inlineish && display === 'inline') ? Math.round(lineH) : 0;

    // An inline element is as tall as its ink, not the whole line. Not for
    // replaced elements: `<iframe width height>` takes the attribute size.
    if (inlineish && display === 'inline' && !frame
        && explicitH == null && attrH == null && !boxedKids.length && !(lines && lines.length)) {
      ch = fbox.asc + fbox.desc;
    }
    if (ua && explicitH == null && attrH == null) ch = ua.h;
    {
      const maxH = inH(len('max-height', baseH));
      const minH = inH(len('min-height', baseH));
      if (maxH != null && ch > maxH) ch = maxH;
      if (minH != null && ch < minH) ch = minH;
    }

    // Chrome keeps lengths in 1/64 px and truncates rather than rounds:
    // line height 22.4 becomes 22.390625, not 22.40625.
    const q = (v) => Math.floor(v * 64) / 64;
    const box = {
      x: q(boxX), y: q(boxY),
      w: q(cw + pl + pr + bl + br),
      h: q(ch + pt_ + pb + bt + bb),
      cw: q(cw), ch: q(ch), cx: q(contentX), cy: q(contentY),
      bx: bl + br, by: bt + bb, mb,
      mt: q(mt), mr: q(mr), ml: q(ml),
      line: lineH, inline: inlineish, lineTop: q(boxY), lines,
      asc: fbox.asc, desc: fbox.desc,
      // Scroll area is the content extent; a scrollbar, if any, takes 15px off
      // the visible part.
      sw: q(Math.max(cw, widest)), sh: q(Math.max(ch, deepest)),
      bar: [0, 0],
    };
    // A scrollbar takes space: an `overflow: auto` block whose content does not
    // fit is 15px narrower and shorter inside.
    {
      const needX = (ovX === 'scroll') || (ovX === 'auto' && widest > cw + 0.5);
      const needY = (ovY === 'scroll') || (ovY === 'auto' && deepest > ch + 0.5);
      box.bar = [needY ? 15 : 0, needX ? 15 : 0];
    }
    if (box.inline && strut) {
      // Baseline alignment, not centring: a 13px `<span>` in 16px text drops by
      // the ascent difference (2px).
      const shift = Math.max(0, strut.asc - fbox.asc);
      box.y = q(box.y + shift);
      box.cy = q(box.cy + shift);
    }
    el.__ptBox = box;
    el.__ptBoxV = __layoutBuilt;
    // A resized frame changes its window's viewport.
    if (tag === 'iframe' && el.__ptRealm) __ptTellLogged(el, box);
    return box;
  }

  // Tell a frame's window its size. A `display: none` frame is not laid out
  // at all, and its window must be told that too.
  function __ptTellFrame(el, box) {
    const w = el.__ptRealm;
    if (!w) return;
    try {
      if (!box) {
        if (typeof w.__pt_setRendered === 'function') w.__pt_setRendered(false);
        // A boxless frame's window is zero-sized: innerWidth/innerHeight 0 in Chrome.
        if ((el.__ptSeenW !== 0 || el.__ptSeenH !== 0) && typeof w.__pt_setViewport === 'function') {
          el.__ptSeenW = 0; el.__ptSeenH = 0;
          w.__pt_setViewport(0, 0);
        }
        return;
      }
      if (typeof w.__pt_setRendered === 'function') w.__pt_setRendered(true);
      if (el.__ptSeenW === box.cw && el.__ptSeenH === box.ch) return;
      el.__ptSeenW = box.cw; el.__ptSeenH = box.ch;
      if (typeof w.__pt_setViewport === 'function') w.__pt_setViewport(box.cw, box.ch);
    } catch (e) {}
  }

  // Frames with their own window; after every layout each is told its size,
  // hidden ones included.
  const __realmFrames = new Set();

  // Cost counters for profiling the style and layout engine (always on: a few
  // integer increments). `__pt_layoutStats()` reads them.
  const __lstats = { relayouts: 0, cascades: 0, allStale: 0, dropped: 0, layoutEls: 0, cssScans: 0, cssScanEls: 0, cssScanMs: 0, shared: 0, gathers: 0, gatherRules: 0, gatherMs: 0, relayoutMs: 0, lazyRuns: 0, lazyMs: 0, keptRecords: 0, fontSteps: 0 };
  Object.defineProperty(globalThis, '__pt_layoutStats', { value: () => Object.assign({}, __lstats), configurable: true, enumerable: false });
  // Drop every cached cascade: checks compare incremental styles with a
  // full recomputation.
  Object.defineProperty(globalThis, '__pt_styleFlush', { value: () => { __styleAllStale = true; __layoutSeq++; }, configurable: true, enumerable: false });
  function __relayout() {
    if (__layoutBuilt === __layoutSeq) return;
    __layoutBuilt = __layoutSeq;
    __lstats.relayouts++;
    __styleBegin();
    __rows = [];
    __boxes = [];
    const doc = globalThis.document;
    const de = doc && doc.documentElement;
    if (!de) return;
    // The layout stamp lives on the document: another realm reads its boxes
    // (a page measures its frame's body), and per-realm counters gave empty or
    // stale boxes.
    try {
      Object.defineProperty(doc, '__ptLayoutV', { value: __layoutBuilt, configurable: true, enumerable: false, writable: true });
      if (typeof doc.__ptRelayout !== 'function') {
        Object.defineProperty(doc, '__ptRelayout', { value: () => __relayout(), configurable: true, enumerable: false });
      }
    } catch (e) {}
    if (!__rendered) return;
    __layoutForget();
    __tellLog = [];
    const r0 = __perfNow();
    __layoutDeep = false;
    __layoutSolve(() => {
      __boxes = [];
      __tellLog = [];
      __layoutOne(de, 0, 0, LAYOUT.W);
    });
    if (__layoutDeep) {
      __layoutDeep = false;
      for (const [n, b] of __tellLog) __ptTellFrame(n, b);
    }
    __layoutSettle(de);
    __lstats.relayoutMs += __perfNow() - r0;
    // In quirks mode the root and body stretch to the viewport: an empty
    // 300x150 frame gives `html` 150 and body 134, not a line height. Frames
    // without a doctype (`about:blank`, `srcdoc`) are common.
    try {
      if (doc.compatMode === 'BackCompat') {
        const stretch = (el, avail) => {
          const b = el && el.__ptBox;
          if (!b || avail == null) return null;
          const outer = b.h + (b.mt || 0) + (b.mb || 0);
          if (outer >= avail) return b.ch;
          const grown = avail - (b.mt || 0) - (b.mb || 0) - (b.by || 0);
          b.ch = grown;
          b.h = grown + (b.by || 0);
          return grown;
        };
        const inner = stretch(de, LAYOUT.H);
        stretch(doc.body, inner);
      }
    } catch (e) {}
    // Traversal order is paint order: hit testing scans from the end, deepest
    // and latest first.
    __rows = __boxes;
    // Hidden frames are not traversed but must still be told, or they keep a
    // stale layout.
    for (const f of __realmFrames) {
      if (!f.isConnected) { __realmFrames.delete(f); continue; }
      if (f.__ptBoxV !== __layoutBuilt) __ptTellFrame(f, null);
    }
  }

  // Width/height an element declares for itself: the CSS `width`/`height` it was
  // given, else the presentational attributes `<iframe width height>`/`<img>`/
  // `<canvas>` carry. Percentages and other units are left to the row default —
  // guessing at them would be worse than admitting we do not lay out.
  function __declaredSize(el) {
    const out = { w: null, h: null };
    const px = (v) => {
      if (v == null) return null;
      const m = /^\s*(\d+(?:\.\d+)?)(px)?\s*$/.exec(String(v));
      return m ? Math.round(parseFloat(m[1])) : null;
    };
    const st = el.style;
    if (st) { out.w = px(st.width); out.h = px(st.height); }
    if (out.w == null && el.getAttribute) out.w = px(__ptGetA(el, 'width'));
    if (out.h == null && el.getAttribute) out.h = px(__ptGetA(el, 'height'));
    return out;
  }

  // getComputedStyle: Chrome exposes 456 resolved properties. Cloudflare's
  // loader measures its widget with `getComputedStyle(iframe)` and treats an
  // empty answer as "not visible". Tables from Chrome 148: name order, block
  // element defaults, deltas for inline and replaced elements.
const CS_ORDER = ["accent-color","align-content","align-items","align-self","alignment-baseline","anchor-name","anchor-scope","animation-composition","animation-delay","animation-direction","animation-duration","animation-fill-mode","animation-iteration-count","animation-name","animation-play-state","animation-range-end","animation-range-start","animation-timeline","animation-timing-function","animation-trigger","app-region","appearance","aspect-ratio","backdrop-filter","backface-visibility","background-attachment","background-blend-mode","background-clip","background-color","background-image","background-origin","background-position","background-repeat","background-size","baseline-shift","baseline-source","block-size","border-block-end-color","border-block-end-style","border-block-end-width","border-block-start-color","border-block-start-style","border-block-start-width","border-bottom-color","border-bottom-left-radius","border-bottom-right-radius","border-bottom-style","border-bottom-width","border-collapse","border-end-end-radius","border-end-start-radius","border-image-outset","border-image-repeat","border-image-slice","border-image-source","border-image-width","border-inline-end-color","border-inline-end-style","border-inline-end-width","border-inline-start-color","border-inline-start-style","border-inline-start-width","border-left-color","border-left-style","border-left-width","border-right-color","border-right-style","border-right-width","border-shape","border-start-end-radius","border-start-start-radius","border-top-color","border-top-left-radius","border-top-right-radius","border-top-style","border-top-width","bottom","box-decoration-break","box-shadow","box-sizing","break-after","break-before","break-inside","buffered-rendering","caption-side","caret-animation","caret-color","caret-shape","clear","clip","clip-path","clip-rule","color","color-interpolation","color-interpolation-filters","color-rendering","color-scheme","column-count","column-fill","column-gap","column-height","column-rule-break","column-rule-color","column-rule-inset-cap-end","column-rule-inset-cap-start","column-rule-inset-junction-end","column-rule-inset-junction-start","column-rule-style","column-rule-visibility-items","column-rule-width","column-span","column-width","column-wrap","contain","contain-intrinsic-block-size","contain-intrinsic-height","contain-intrinsic-inline-size","contain-intrinsic-size","contain-intrinsic-width","container-name","container-type","content","content-visibility","corner-bottom-left-shape","corner-bottom-right-shape","corner-end-end-shape","corner-end-start-shape","corner-start-end-shape","corner-start-start-shape","corner-top-left-shape","corner-top-right-shape","counter-increment","counter-reset","counter-set","cursor","cx","cy","d","direction","display","dominant-baseline","dynamic-range-limit","empty-cells","field-sizing","fill","fill-opacity","fill-rule","filter","flex-basis","flex-direction","flex-grow","flex-line-count","flex-shrink","flex-wrap","float","flood-color","flood-opacity","font-family","font-feature-settings","font-kerning","font-language-override","font-optical-sizing","font-palette","font-size","font-size-adjust","font-stretch","font-style","font-synthesis-small-caps","font-synthesis-style","font-synthesis-weight","font-variant","font-variant-alternates","font-variant-caps","font-variant-east-asian","font-variant-emoji","font-variant-ligatures","font-variant-numeric","font-variant-position","font-variation-settings","font-weight","forced-color-adjust","grid-auto-columns","grid-auto-flow","grid-auto-rows","grid-column-end","grid-column-start","grid-row-end","grid-row-start","grid-template-areas","grid-template-columns","grid-template-rows","height","hyphenate-character","hyphenate-limit-chars","hyphens","image-orientation","image-rendering","initial-letter","inline-size","inset-block-end","inset-block-start","inset-inline-end","inset-inline-start","interactivity","interest-delay-end","interest-delay-start","interpolate-size","isolation","justify-content","justify-items","justify-self","left","letter-spacing","lighting-color","line-break","line-height","list-style-image","list-style-position","list-style-type","margin-block-end","margin-block-start","margin-bottom","margin-inline-end","margin-inline-start","margin-left","margin-right","margin-top","marker-end","marker-mid","marker-start","mask-clip","mask-composite","mask-image","mask-mode","mask-origin","mask-position","mask-repeat","mask-size","mask-type","math-depth","math-shift","math-style","max-block-size","max-height","max-inline-size","max-width","min-block-size","min-height","min-inline-size","min-width","mix-blend-mode","object-fit","object-position","object-view-box","offset-anchor","offset-distance","offset-path","offset-position","offset-rotate","opacity","order","orphans","outline-color","outline-offset","outline-style","outline-width","overflow-anchor","overflow-block","overflow-clip-margin","overflow-inline","overflow-wrap","overflow-x","overflow-y","overlay","overscroll-behavior-block","overscroll-behavior-inline","overscroll-behavior-x","overscroll-behavior-y","padding-block-end","padding-block-start","padding-bottom","padding-inline-end","padding-inline-start","padding-left","padding-right","padding-top","paint-order","perspective","perspective-origin","pointer-events","position","position-anchor","position-area","position-try-fallbacks","position-try-order","position-visibility","print-color-adjust","quotes","r","reading-flow","reading-order","resize","right","rotate","row-gap","row-rule-break","row-rule-color","row-rule-inset-cap-end","row-rule-inset-cap-start","row-rule-inset-junction-end","row-rule-inset-junction-start","row-rule-style","row-rule-visibility-items","row-rule-width","ruby-align","ruby-overhang","ruby-position","rule-overlap","rx","ry","scale","scroll-behavior","scroll-initial-target","scroll-margin-block-end","scroll-margin-block-start","scroll-margin-bottom","scroll-margin-inline-end","scroll-margin-inline-start","scroll-margin-left","scroll-margin-right","scroll-margin-top","scroll-marker-group","scroll-padding-block-end","scroll-padding-block-start","scroll-padding-bottom","scroll-padding-inline-end","scroll-padding-inline-start","scroll-padding-left","scroll-padding-right","scroll-padding-top","scroll-snap-align","scroll-snap-stop","scroll-snap-type","scroll-target-group","scroll-timeline-axis","scroll-timeline-name","scrollbar-color","scrollbar-gutter","scrollbar-width","shape-image-threshold","shape-margin","shape-outside","shape-rendering","speak","stop-color","stop-opacity","stroke","stroke-dasharray","stroke-dashoffset","stroke-linecap","stroke-linejoin","stroke-miterlimit","stroke-opacity","stroke-width","tab-size","table-layout","text-align","text-align-last","text-anchor","text-autospace","text-box-edge","text-box-trim","text-combine-upright","text-decoration","text-decoration-color","text-decoration-line","text-decoration-skip-ink","text-decoration-style","text-decoration-thickness","text-emphasis-color","text-emphasis-position","text-emphasis-style","text-fit","text-indent","text-justify","text-orientation","text-overflow","text-rendering","text-shadow","text-size-adjust","text-spacing-trim","text-transform","text-underline-offset","text-underline-position","text-wrap-mode","text-wrap-style","timeline-scope","timeline-trigger-activation-range-end","timeline-trigger-activation-range-start","timeline-trigger-active-range-end","timeline-trigger-active-range-start","timeline-trigger-name","timeline-trigger-source","top","touch-action","transform","transform-box","transform-origin","transform-style","transition-behavior","transition-delay","transition-duration","transition-property","transition-timing-function","translate","trigger-scope","unicode-bidi","user-select","vector-effect","vertical-align","view-timeline-axis","view-timeline-inset","view-timeline-name","view-transition-class","view-transition-group","view-transition-name","view-transition-scope","visibility","white-space-collapse","widows","width","will-change","word-break","word-spacing","writing-mode","x","y","z-index","zoom","-webkit-border-horizontal-spacing","-webkit-border-image","-webkit-border-vertical-spacing","-webkit-box-align","-webkit-box-decoration-break","-webkit-box-direction","-webkit-box-flex","-webkit-box-ordinal-group","-webkit-box-orient","-webkit-box-pack","-webkit-box-reflect","-webkit-font-smoothing","-webkit-line-break","-webkit-line-clamp","-webkit-locale","-webkit-mask-box-image","-webkit-mask-box-image-outset","-webkit-mask-box-image-repeat","-webkit-mask-box-image-slice","-webkit-mask-box-image-source","-webkit-mask-box-image-width","-webkit-mask-position-x","-webkit-mask-position-y","-webkit-rtl-ordering","-webkit-ruby-position","-webkit-tap-highlight-color","-webkit-text-combine","-webkit-text-decorations-in-effect","-webkit-text-fill-color","-webkit-text-orientation","-webkit-text-security","-webkit-text-stroke-color","-webkit-text-stroke-width","-webkit-user-drag","-webkit-user-modify","-webkit-writing-mode"];
const CS_BASE = {"accent-color":"auto","align-content":"normal","align-items":"normal","align-self":"auto","alignment-baseline":"auto","anchor-name":"none","anchor-scope":"none","animation-composition":"replace","animation-delay":"0s","animation-direction":"normal","animation-duration":"0s","animation-fill-mode":"none","animation-iteration-count":"1","animation-name":"none","animation-play-state":"running","animation-range-end":"normal","animation-range-start":"normal","animation-timeline":"auto","animation-timing-function":"ease","animation-trigger":"none","app-region":"none","appearance":"none","aspect-ratio":"auto","backdrop-filter":"none","backface-visibility":"visible","background-attachment":"scroll","background-blend-mode":"normal","background-clip":"border-box","background-color":"rgba(0, 0, 0, 0)","background-image":"none","background-origin":"padding-box","background-position":"0% 0%","background-repeat":"repeat","background-size":"auto","baseline-shift":"0px","baseline-source":"auto","block-size":"auto","border-block-end-color":"rgb(0, 0, 0)","border-block-end-style":"none","border-block-end-width":"0px","border-block-start-color":"rgb(0, 0, 0)","border-block-start-style":"none","border-block-start-width":"0px","border-bottom-color":"rgb(0, 0, 0)","border-bottom-left-radius":"0px","border-bottom-right-radius":"0px","border-bottom-style":"none","border-bottom-width":"0px","border-collapse":"separate","border-end-end-radius":"0px","border-end-start-radius":"0px","border-image-outset":"0","border-image-repeat":"stretch","border-image-slice":"100%","border-image-source":"none","border-image-width":"1","border-inline-end-color":"rgb(0, 0, 0)","border-inline-end-style":"none","border-inline-end-width":"0px","border-inline-start-color":"rgb(0, 0, 0)","border-inline-start-style":"none","border-inline-start-width":"0px","border-left-color":"rgb(0, 0, 0)","border-left-style":"none","border-left-width":"0px","border-right-color":"rgb(0, 0, 0)","border-right-style":"none","border-right-width":"0px","border-shape":"none","border-start-end-radius":"0px","border-start-start-radius":"0px","border-top-color":"rgb(0, 0, 0)","border-top-left-radius":"0px","border-top-right-radius":"0px","border-top-style":"none","border-top-width":"0px","bottom":"auto","box-decoration-break":"slice","box-shadow":"none","box-sizing":"content-box","break-after":"auto","break-before":"auto","break-inside":"auto","buffered-rendering":"auto","caption-side":"top","caret-animation":"auto","caret-color":"rgb(0, 0, 0)","caret-shape":"auto","clear":"none","clip":"auto","clip-path":"none","clip-rule":"nonzero","color":"rgb(0, 0, 0)","color-interpolation":"srgb","color-interpolation-filters":"linearrgb","color-rendering":"auto","color-scheme":"normal","column-count":"auto","column-fill":"balance","column-gap":"normal","column-height":"auto","column-rule-break":"normal","column-rule-color":"rgb(0, 0, 0)","column-rule-inset-cap-end":"0px","column-rule-inset-cap-start":"0px","column-rule-inset-junction-end":"0px","column-rule-inset-junction-start":"0px","column-rule-style":"none","column-rule-visibility-items":"normal","column-rule-width":"3px","column-span":"none","column-width":"auto","column-wrap":"auto","contain":"none","contain-intrinsic-block-size":"none","contain-intrinsic-height":"none","contain-intrinsic-inline-size":"none","contain-intrinsic-size":"none","contain-intrinsic-width":"none","container-name":"none","container-type":"normal","content":"normal","content-visibility":"visible","corner-bottom-left-shape":"round","corner-bottom-right-shape":"round","corner-end-end-shape":"round","corner-end-start-shape":"round","corner-start-end-shape":"round","corner-start-start-shape":"round","corner-top-left-shape":"round","corner-top-right-shape":"round","counter-increment":"none","counter-reset":"none","counter-set":"none","cursor":"auto","cx":"0px","cy":"0px","d":"none","direction":"ltr","display":"block","dominant-baseline":"auto","dynamic-range-limit":"no-limit","empty-cells":"show","field-sizing":"fixed","fill":"rgb(0, 0, 0)","fill-opacity":"1","fill-rule":"nonzero","filter":"none","flex-basis":"auto","flex-direction":"row","flex-grow":"0","flex-line-count":"1","flex-shrink":"1","flex-wrap":"nowrap","float":"none","flood-color":"rgb(0, 0, 0)","flood-opacity":"1","font-family":"\"Times New Roman\"","font-feature-settings":"normal","font-kerning":"auto","font-language-override":"normal","font-optical-sizing":"auto","font-palette":"normal","font-size":"16px","font-size-adjust":"none","font-stretch":"100%","font-style":"normal","font-synthesis-small-caps":"auto","font-synthesis-style":"auto","font-synthesis-weight":"auto","font-variant":"normal","font-variant-alternates":"normal","font-variant-caps":"normal","font-variant-east-asian":"normal","font-variant-emoji":"normal","font-variant-ligatures":"normal","font-variant-numeric":"normal","font-variant-position":"normal","font-variation-settings":"normal","font-weight":"400","forced-color-adjust":"auto","grid-auto-columns":"auto","grid-auto-flow":"row","grid-auto-rows":"auto","grid-column-end":"auto","grid-column-start":"auto","grid-row-end":"auto","grid-row-start":"auto","grid-template-areas":"none","grid-template-columns":"none","grid-template-rows":"none","height":"auto","hyphenate-character":"auto","hyphenate-limit-chars":"auto","hyphens":"manual","image-orientation":"from-image","image-rendering":"auto","initial-letter":"normal","inline-size":"auto","inset-block-end":"auto","inset-block-start":"auto","inset-inline-end":"auto","inset-inline-start":"auto","interactivity":"auto","interest-delay-end":"normal","interest-delay-start":"normal","interpolate-size":"numeric-only","isolation":"auto","justify-content":"normal","justify-items":"normal","justify-self":"auto","left":"auto","letter-spacing":"normal","lighting-color":"rgb(255, 255, 255)","line-break":"auto","line-height":"normal","list-style-image":"none","list-style-position":"outside","list-style-type":"disc","margin-block-end":"0px","margin-block-start":"0px","margin-bottom":"0px","margin-inline-end":"0px","margin-inline-start":"0px","margin-left":"0px","margin-right":"0px","margin-top":"0px","marker-end":"none","marker-mid":"none","marker-start":"none","mask-clip":"border-box","mask-composite":"add","mask-image":"none","mask-mode":"match-source","mask-origin":"border-box","mask-position":"0% 0%","mask-repeat":"repeat","mask-size":"auto","mask-type":"luminance","math-depth":"0","math-shift":"normal","math-style":"normal","max-block-size":"none","max-height":"none","max-inline-size":"none","max-width":"none","min-block-size":"0px","min-height":"0px","min-inline-size":"0px","min-width":"0px","mix-blend-mode":"normal","object-fit":"fill","object-position":"50% 50%","object-view-box":"none","offset-anchor":"auto","offset-distance":"0px","offset-path":"none","offset-position":"normal","offset-rotate":"auto 0deg","opacity":"1","order":"0","orphans":"2","outline-color":"rgb(0, 0, 0)","outline-offset":"0px","outline-style":"none","outline-width":"3px","overflow-anchor":"auto","overflow-block":"visible","overflow-clip-margin":"0px","overflow-inline":"visible","overflow-wrap":"normal","overflow-x":"visible","overflow-y":"visible","overlay":"none","overscroll-behavior-block":"auto","overscroll-behavior-inline":"auto","overscroll-behavior-x":"auto","overscroll-behavior-y":"auto","padding-block-end":"0px","padding-block-start":"0px","padding-bottom":"0px","padding-inline-end":"0px","padding-inline-start":"0px","padding-left":"0px","padding-right":"0px","padding-top":"0px","paint-order":"normal","perspective":"none","perspective-origin":"50% 50%","pointer-events":"auto","position":"static","position-anchor":"normal","position-area":"none","position-try-fallbacks":"none","position-try-order":"normal","position-visibility":"anchors-visible","print-color-adjust":"economy","quotes":"auto","r":"0px","reading-flow":"normal","reading-order":"0","resize":"none","right":"auto","rotate":"none","row-gap":"normal","row-rule-break":"normal","row-rule-color":"rgb(0, 0, 0)","row-rule-inset-cap-end":"0px","row-rule-inset-cap-start":"0px","row-rule-inset-junction-end":"0px","row-rule-inset-junction-start":"0px","row-rule-style":"none","row-rule-visibility-items":"normal","row-rule-width":"3px","ruby-align":"space-around","ruby-overhang":"auto","ruby-position":"over","rule-overlap":"row-over-column","rx":"auto","ry":"auto","scale":"none","scroll-behavior":"auto","scroll-initial-target":"none","scroll-margin-block-end":"0px","scroll-margin-block-start":"0px","scroll-margin-bottom":"0px","scroll-margin-inline-end":"0px","scroll-margin-inline-start":"0px","scroll-margin-left":"0px","scroll-margin-right":"0px","scroll-margin-top":"0px","scroll-marker-group":"none","scroll-padding-block-end":"auto","scroll-padding-block-start":"auto","scroll-padding-bottom":"auto","scroll-padding-inline-end":"auto","scroll-padding-inline-start":"auto","scroll-padding-left":"auto","scroll-padding-right":"auto","scroll-padding-top":"auto","scroll-snap-align":"none","scroll-snap-stop":"normal","scroll-snap-type":"none","scroll-target-group":"none","scroll-timeline-axis":"block","scroll-timeline-name":"none","scrollbar-color":"auto","scrollbar-gutter":"auto","scrollbar-width":"auto","shape-image-threshold":"0","shape-margin":"0px","shape-outside":"none","shape-rendering":"auto","speak":"normal","stop-color":"rgb(0, 0, 0)","stop-opacity":"1","stroke":"none","stroke-dasharray":"none","stroke-dashoffset":"0px","stroke-linecap":"butt","stroke-linejoin":"miter","stroke-miterlimit":"4","stroke-opacity":"1","stroke-width":"1px","tab-size":"8","table-layout":"auto","text-align":"start","text-align-last":"auto","text-anchor":"start","text-autospace":"no-autospace","text-box-edge":"auto","text-box-trim":"none","text-combine-upright":"none","text-decoration":"none","text-decoration-color":"rgb(0, 0, 0)","text-decoration-line":"none","text-decoration-skip-ink":"auto","text-decoration-style":"solid","text-decoration-thickness":"auto","text-emphasis-color":"rgb(0, 0, 0)","text-emphasis-position":"over","text-emphasis-style":"none","text-fit":"none","text-indent":"0px","text-justify":"auto","text-orientation":"mixed","text-overflow":"clip","text-rendering":"auto","text-shadow":"none","text-size-adjust":"auto","text-spacing-trim":"normal","text-transform":"none","text-underline-offset":"auto","text-underline-position":"auto","text-wrap-mode":"wrap","text-wrap-style":"auto","timeline-scope":"none","timeline-trigger-activation-range-end":"normal","timeline-trigger-activation-range-start":"normal","timeline-trigger-active-range-end":"auto","timeline-trigger-active-range-start":"auto","timeline-trigger-name":"none","timeline-trigger-source":"auto","top":"auto","touch-action":"auto","transform":"none","transform-box":"view-box","transform-origin":"50% 50%","transform-style":"flat","transition-behavior":"normal","transition-delay":"0s","transition-duration":"0s","transition-property":"all","transition-timing-function":"ease","translate":"none","trigger-scope":"none","unicode-bidi":"isolate","user-select":"auto","vector-effect":"none","vertical-align":"baseline","view-timeline-axis":"block","view-timeline-inset":"auto","view-timeline-name":"none","view-transition-class":"none","view-transition-group":"normal","view-transition-name":"none","view-transition-scope":"none","visibility":"visible","white-space-collapse":"collapse","widows":"2","width":"auto","will-change":"auto","word-break":"normal","word-spacing":"0px","writing-mode":"horizontal-tb","x":"0px","y":"0px","z-index":"auto","zoom":"1","-webkit-border-horizontal-spacing":"0px","-webkit-border-image":"none","-webkit-border-vertical-spacing":"0px","-webkit-box-align":"stretch","-webkit-box-decoration-break":"slice","-webkit-box-direction":"normal","-webkit-box-flex":"0","-webkit-box-ordinal-group":"1","-webkit-box-orient":"horizontal","-webkit-box-pack":"start","-webkit-box-reflect":"none","-webkit-font-smoothing":"auto","-webkit-line-break":"auto","-webkit-line-clamp":"none","-webkit-locale":"auto","-webkit-mask-box-image":"none","-webkit-mask-box-image-outset":"0","-webkit-mask-box-image-repeat":"stretch","-webkit-mask-box-image-slice":"0 fill","-webkit-mask-box-image-source":"none","-webkit-mask-box-image-width":"auto","-webkit-mask-position-x":"0%","-webkit-mask-position-y":"0%","-webkit-rtl-ordering":"logical","-webkit-ruby-position":"before","-webkit-tap-highlight-color":"rgba(0, 0, 0, 0.18)","-webkit-text-combine":"none","-webkit-text-decorations-in-effect":"none","-webkit-text-fill-color":"rgb(0, 0, 0)","-webkit-text-orientation":"vertical-right","-webkit-text-security":"none","-webkit-text-stroke-color":"rgb(0, 0, 0)","-webkit-text-stroke-width":"0px","-webkit-user-drag":"auto","-webkit-user-modify":"read-only","-webkit-writing-mode":"horizontal-tb"};
const CS_INLINE = {"block-size":"auto","display":"inline","height":"auto","inline-size":"auto","perspective-origin":"0px 0px","transform-origin":"0px 0px","unicode-bidi":"normal","width":"auto"};
const CS_REPLACED = {"block-size":"150px","border-block-end-style":"inset","border-block-end-width":"2px","border-block-start-style":"inset","border-block-start-width":"2px","border-bottom-style":"inset","border-bottom-width":"2px","border-inline-end-style":"inset","border-inline-end-width":"2px","border-inline-start-style":"inset","border-inline-start-width":"2px","border-left-style":"inset","border-left-width":"2px","border-right-style":"inset","border-right-width":"2px","border-top-style":"inset","border-top-width":"2px","display":"inline","height":"150px","inline-size":"300px","overflow-block":"clip","overflow-clip-margin":"content-box","overflow-inline":"clip","overflow-x":"clip","overflow-y":"clip","perspective-origin":"152px 77px","transform-origin":"152px 77px","unicode-bidi":"normal","width":"300px"};
  const CS_DISPLAY = {
    span: 'inline', a: 'inline', b: 'inline', i: 'inline', em: 'inline', strong: 'inline',
    small: 'inline', code: 'inline', label: 'inline', abbr: 'inline', cite: 'inline',
    q: 'inline', s: 'inline', u: 'inline', sub: 'inline', sup: 'inline', mark: 'inline',
    time: 'inline', var: 'inline', samp: 'inline', kbd: 'inline', bdi: 'inline', bdo: 'inline',
    img: 'inline', iframe: 'inline', canvas: 'inline', video: 'inline', audio: 'inline',
    circle: 'inline', path: 'inline', line: 'inline', g: 'inline', text: 'inline',
    rect: 'inline', ellipse: 'inline', polyline: 'inline', polygon: 'inline',
    object: 'inline', embed: 'inline', svg: 'inline', input: 'inline-block',
    button: 'inline-block', select: 'inline-block', textarea: 'inline-block',
    meter: 'inline-block', progress: 'inline-block', li: 'list-item', table: 'table',
    thead: 'table-header-group', tbody: 'table-row-group', tfoot: 'table-footer-group',
    tr: 'table-row', td: 'table-cell', th: 'table-cell', caption: 'table-caption',
    head: 'none', style: 'none', script: 'none', link: 'none', meta: 'none',
    title: 'none', template: 'none', base: 'none', param: 'none', source: 'none',
    track: 'none', option: 'block', optgroup: 'block',
    output: 'inline', tt: 'inline', br: 'inline', wbr: 'inline',
    col: 'table-column', colgroup: 'table-column-group', audio: 'none',
  };
  const CS_REPLACED_TAGS = new Set(['iframe', 'img', 'canvas', 'video', 'audio', 'object', 'embed']);
  const CS_CAMEL = (n) => __s_replace(n, /-([a-z])/g, (_, c) => __s_toUpperCase(c));

  // Inherited properties, per spec; verified in Chrome on colour, font, line
  // height and alignment.
  const CSS_INHERITED = new Set([
    'azimuth', 'border-collapse', 'border-spacing', 'caption-side', 'caret-color',
    'color', 'color-scheme', 'cursor', 'direction', 'empty-cells', 'font',
    'font-family', 'font-feature-settings', 'font-kerning', 'font-language-override',
    'font-optical-sizing', 'font-palette', 'font-size', 'font-size-adjust',
    'font-stretch', 'font-style', 'font-synthesis-small-caps', 'font-synthesis-style',
    'font-synthesis-weight', 'font-variant', 'font-variant-alternates',
    'font-variant-caps', 'font-variant-east-asian', 'font-variant-emoji',
    'font-variant-ligatures', 'font-variant-numeric', 'font-variant-position',
    'font-variation-settings', 'font-weight', 'forced-color-adjust', 'hyphenate-character',
    'hyphenate-limit-chars', 'hyphens', 'image-orientation', 'image-rendering',
    'letter-spacing', 'line-break', 'line-height', 'list-style', 'list-style-image',
    'list-style-position', 'list-style-type', 'math-depth', 'math-shift', 'math-style',
    'orphans', 'overflow-wrap', 'paint-order', 'pointer-events', 'print-color-adjust',
    'quotes', 'ruby-align', 'ruby-position', 'scrollbar-color', 'speak',
    'tab-size', 'text-align', 'text-align-last', 'text-anchor', 'text-autospace',
    'text-combine-upright', 'text-decoration-skip-ink', 'text-emphasis-color',
    'text-emphasis-position', 'text-emphasis-style', 'text-indent', 'text-justify',
    'text-orientation', 'text-rendering', 'text-shadow', 'text-size-adjust',
    'text-spacing-trim', 'text-transform', 'text-underline-offset',
    'text-underline-position', 'text-wrap-mode', 'text-wrap-style', 'visibility',
    'white-space-collapse', 'widows', 'word-break', 'word-spacing', 'writing-mode',
    'fill', 'fill-opacity', 'fill-rule', 'stroke', 'stroke-dasharray',
    'stroke-dashoffset', 'stroke-linecap', 'stroke-linejoin', 'stroke-miterlimit',
    'stroke-opacity', 'stroke-width', 'clip-rule', 'color-interpolation',
    'color-rendering', 'dominant-baseline', 'marker-end', 'marker-mid', 'marker-start',
    'shape-rendering', 'stop-color', 'stop-opacity', '-webkit-font-smoothing',
    '-webkit-locale', '-webkit-text-fill-color', '-webkit-text-stroke-color',
    '-webkit-text-stroke-width', '-webkit-rtl-ordering', '-webkit-line-break',
    '-webkit-text-orientation', '-webkit-text-security', '-webkit-user-modify',
    '-webkit-writing-mode', '-webkit-border-horizontal-spacing',
    '-webkit-border-vertical-spacing', '-webkit-ruby-position',
    '-webkit-tap-highlight-color', '-webkit-text-combine',
  ]);
  /// Value of an inherited property: the nearest ancestor that sets it. One
  /// step at a time, each answer kept with the element's cascade (dropped
  /// with it), so a tree costs one lookup per element and property, not one
  /// walk to the root.
  // Up to the nearest ancestor that sets it or has it kept, then each one's
  // kept value on the way back down: no stack frame per level.
  const __inheritedValue = (el, prop) => {
    if (!el || el.__ptType !== ELEMENT_NODE) return null;
    {
      const inh = __cascadeFor(el).__ptInh;
      const hit = inh && inh.get(prop);
      if (hit !== undefined) return hit;
    }
    const chain = [];
    let out = null;
    for (let e = el; ; ) {
      const cs = __cascadeFor(e);
      const own = cs.__ptInh || (cs.__ptInh = new Map());
      const hit = own.get(prop);
      if (hit !== undefined) { out = hit; break; }
      chain.push(own);
      const p = e.__ptParent;
      if (!p || p.__ptType !== ELEMENT_NODE) { out = null; break; }
      const raw = __cascadeFor(p).get(prop);
      if (raw != null) {
        out = __resolveLength(raw, prop, __usedFontSize(p), p);
        own.set(prop, out);
        chain.pop();
        break;
      }
      e = p;
    }
    for (let i = chain.length - 1; i >= 0; i--) chain[i].set(prop, out);
    return out;
  };

  // Shorthands: computed style never lists them, only the longhands they
  // expand to (`background: blue` sets `background-color`).
  const CS_SIDES = ['top', 'right', 'bottom', 'left'];
  const __ptIsColour = (t) => !!(globalThis.__pt_cssColour && globalThis.__pt_cssColour(t))
    || /^(currentcolor|transparent)$/i.test(t)
    || /^(color|lab|lch|oklab|oklch|color-mix|light-dark)\(/i.test(t);
  const CS_BORDER_STYLES = new Set(['none', 'hidden', 'dotted', 'dashed', 'solid', 'double',
    'groove', 'ridge', 'inset', 'outset']);
  const CS_WIDTH_WORDS = { thin: '1px', medium: '3px', thick: '5px' };
  // Split on top-level spaces: `rgba(1, 2, 3, .4) solid 1px` is three parts.
  const __ptCssParts = (v) => {
    const out = [];
    let depth = 0, cur = '';
    for (const ch of String(v)) {
      if (ch === '(') depth++;
      if (ch === ')') depth--;
      if (/\s/.test(ch) && depth === 0) { if (cur) out.push(cur); cur = ''; continue; }
      cur += ch;
    }
    if (cur) out.push(cur);
    return out;
  };
  const __ptFourWay = (name, value) => {
    const parts = __ptCssParts(value);
    if (!parts.length) return [];
    const pick = [0, 1, 2, 3].map((i) => parts[[0, 0, 0, 0][i] === 0 ? Math.min(i, parts.length - 1) : i]);
    const order = parts.length === 1 ? [parts[0], parts[0], parts[0], parts[0]]
      : parts.length === 2 ? [parts[0], parts[1], parts[0], parts[1]]
      : parts.length === 3 ? [parts[0], parts[1], parts[2], parts[1]]
      : [parts[0], parts[1], parts[2], parts[3]];
    void pick;
    return CS_SIDES.map((side, i) => [__s_replace(name, '*', side), order[i]]);
  };
  // Returns [longhand, value] pairs, or null if not a shorthand.
  const __ptExpand = (prop, value) => {
    const v = __s_trim(String(value));
    const parts = __ptCssParts(v);
    const out = [];
    const borderSide = /^border-(top|right|bottom|left|block-start|block-end|inline-start|inline-end)$/.exec(prop);
    if (prop === 'border' || borderSide) {
      const sides = borderSide ? [borderSide[1]] : CS_SIDES;
      let width = 'medium', style = 'none', colour = 'currentcolor';
      for (const t of parts) {
        const low = __s_toLowerCase(t);
        if (CS_BORDER_STYLES.has(low)) style = low;
        else if (CS_WIDTH_WORDS[low] || /^[\d.]/.test(low)) width = CS_WIDTH_WORDS[low] || t;
        else if (__ptIsColour(t)) colour = t;
      }
      if (style === 'none' || style === 'hidden') width = '0px';
      for (const side of sides) {
        out.push(['border-' + side + '-width', width === 'medium' ? '3px' : width]);
        out.push(['border-' + side + '-style', style]);
        out.push(['border-' + side + '-color', colour]);
      }
      return out;
    }
    if (prop === 'border-width' || prop === 'border-style' || prop === 'border-color') {
      const kind = __s_slice(prop, 'border-'.length);
      return __ptFourWay('border-*-' + kind, v);
    }
    if (prop === 'margin' || prop === 'padding') return __ptFourWay(prop + '-*', v);
    if (prop === 'inset') {
      const four = __ptFourWay('*', v);
      return CS_SIDES.map((side, i) => [side, four[i][1]]);
    }
    if (prop === 'border-radius') {
      const corners = ['top-left', 'top-right', 'bottom-right', 'bottom-left'];
      const round = __s_trim(__s_split(v, '/')[0]);
      const p = __ptCssParts(round);
      const order = p.length === 1 ? [p[0], p[0], p[0], p[0]]
        : p.length === 2 ? [p[0], p[1], p[0], p[1]]
        : p.length === 3 ? [p[0], p[1], p[2], p[1]]
        : [p[0], p[1], p[2], p[3]];
      return corners.map((c, i) => ['border-' + c + '-radius', order[i]]);
    }
    if (prop === 'background') {
      let colour = null, image = null;
      for (const t of parts) {
        if (/^(url|linear-gradient|radial-gradient|conic-gradient|image-set)\(/i.test(t)) image = t;
        else if (__ptIsColour(t)) colour = t;
      }
      if (colour) out.push(['background-color', colour]);
      if (image) out.push(['background-image', image]);
      if (!out.length) return [];
      return out;
    }
    if (prop === 'outline') {
      let width = 'medium', style = 'none', colour = 'currentcolor';
      for (const t of parts) {
        const low = __s_toLowerCase(t);
        if (CS_BORDER_STYLES.has(low) || low === 'auto') style = low;
        else if (CS_WIDTH_WORDS[low] || /^[\d.]/.test(low)) width = CS_WIDTH_WORDS[low] || t;
        else if (__ptIsColour(t)) colour = t;
      }
      return [['outline-width', width === 'medium' ? '3px' : width],
              ['outline-style', style], ['outline-color', colour]];
    }
    if (prop === 'font') {
      // `font: italic small-caps bold 14px/1.5 Georgia, serif`
      const m = /(^|\s)((?:[\d.]+[a-z%]*|smaller|larger|x?x-(?:small|large)|small|medium|large))(?:\s*\/\s*([^\s]+))?\s+(.+)$/i.exec(v);
      if (!m) return [];
      const before = __s_split(__s_toLowerCase(__s_trim(__s_slice(v, 0, m.index))), /\s+/).filter(Boolean);
      for (const w of before) {
        if (w === 'italic' || w === 'oblique') out.push(['font-style', w]);
        else if (w === 'small-caps') out.push(['font-variant-caps', w]);
        else if (/^(bold|bolder|lighter|[1-9]00)$/.test(w)) out.push(['font-weight', w === 'bold' ? '700' : w]);
        else if (/^(ultra|extra|semi)?-?(condensed|expanded)$/.test(w)) out.push(['font-stretch', w]);
      }
      out.push(['font-size', m[2]]);
      if (m[3]) out.push(['line-height', m[3]]);
      out.push(['font-family', __s_trim(m[4])]);
      return out;
    }
    if (prop === 'flex') {
      const grow = parts[0] || '0', shrink = parts[1] || '1';
      const basis = parts[2] || (parts.length === 1 && /^[\d.]+$/.test(grow) ? '0%' : 'auto');
      return [['flex-grow', grow], ['flex-shrink', /^[\d.]+$/.test(shrink) ? shrink : '1'],
              ['flex-basis', basis]];
    }
    if (prop === 'gap') {
      const row = parts[0] || 'normal';
      return [['row-gap', row], ['column-gap', parts[1] || row]];
    }
    if (prop === 'overflow') {
      const x = parts[0] || 'visible';
      return [['overflow-x', x], ['overflow-y', parts[1] || x]];
    }
    if (prop === 'place-items' || prop === 'place-content' || prop === 'place-self') {
      const kind = __s_slice(prop, 'place-'.length);
      const a = parts[0] || 'normal';
      return [['align-' + kind, a], ['justify-' + kind, parts[1] || a]];
    }
    if (prop === 'grid-area') {
      const p = __s_split(v, '/').map((x) => __s_trim(x));
      const names = ['grid-row-start', 'grid-column-start', 'grid-row-end', 'grid-column-end'];
      return names.map((n, i) => [n, p[i] || 'auto']).filter(([, x]) => x);
    }
    if (prop === 'grid-row' || prop === 'grid-column') {
      const p = __s_split(v, '/').map((x) => __s_trim(x));
      return [[prop + '-start', p[0] || 'auto'], [prop + '-end', p[1] || 'auto']];
    }
    if (prop === 'list-style') {
      for (const t of parts) {
        const low = __s_toLowerCase(t);
        if (low === 'inside' || low === 'outside') out.push(['list-style-position', low]);
        else if (/^(url|linear-gradient|image-set)\(/i.test(t) || low === 'none') out.push(['list-style-image', low === 'none' ? 'none' : t]);
        else out.push(['list-style-type', t]);
      }
      return out;
    }
    if (prop === 'transition') {
      // First layer only: lists print per layer, and pages almost always have one.
      const layer = __s_trim(__s_split(v, ',')[0]);
      const p = __ptCssParts(layer);
      const times = p.filter((x) => /^[\d.]+m?s$/i.test(x));
      const ease = p.find((x) => /^(ease|ease-in|ease-out|ease-in-out|linear|step-start|step-end|cubic-bezier\(|steps\()/i.test(x));
      const name = p.find((x) => !/^[\d.]+m?s$/i.test(x) && x !== ease);
      const secs = (t) => (/ms$/i.test(t) ? (parseFloat(t) / 1000) : parseFloat(t)) + 's';
      return [['transition-property', name || 'all'],
              ['transition-duration', times[0] ? secs(times[0]) : '0s'],
              ['transition-timing-function', ease || 'ease'],
              ['transition-delay', times[1] ? secs(times[1]) : '0s']];
    }
    if (prop === 'text-decoration') {
      for (const t of parts) {
        const low = __s_toLowerCase(t);
        if (/^(none|underline|overline|line-through|blink)$/.test(low)) out.push(['text-decoration-line', low]);
        else if (/^(solid|double|dotted|dashed|wavy)$/.test(low)) out.push(['text-decoration-style', low]);
        else if (__ptIsColour(t)) out.push(['text-decoration-color', t]);
        else out.push(['text-decoration-thickness', t]);
      }
      return out;
    }
    return null;
  };
  // Colours whose initial value is `currentColor`; Chrome prints the
  // element's colour there.
  const CS_CURRENT_COLOUR = ['caret-color', 'column-rule-color', 'row-rule-color', 'outline-color',
    'text-decoration-color', 'text-emphasis-color', '-webkit-text-fill-color',
    '-webkit-text-stroke-color', 'border-top-color', 'border-right-color',
    'border-bottom-color', 'border-left-color', 'border-block-start-color',
    'border-block-end-color', 'border-inline-start-color', 'border-inline-end-color'];
  // Logical names print the same values as physical ones.
  const CS_LOGICAL = [
    ['border-block-start-color', 'border-top-color'], ['border-block-end-color', 'border-bottom-color'],
    ['border-inline-start-color', 'border-left-color'], ['border-inline-end-color', 'border-right-color'],
    ['border-block-start-style', 'border-top-style'], ['border-block-end-style', 'border-bottom-style'],
    ['border-inline-start-style', 'border-left-style'], ['border-inline-end-style', 'border-right-style'],
    ['border-block-start-width', 'border-top-width'], ['border-block-end-width', 'border-bottom-width'],
    ['border-inline-start-width', 'border-left-width'], ['border-inline-end-width', 'border-right-width'],
    ['margin-block-start', 'margin-top'], ['margin-block-end', 'margin-bottom'],
    ['margin-inline-start', 'margin-left'], ['margin-inline-end', 'margin-right'],
    ['padding-block-start', 'padding-top'], ['padding-block-end', 'padding-bottom'],
    ['padding-inline-start', 'padding-left'], ['padding-inline-end', 'padding-right'],
    ['inset-block-start', 'top'], ['inset-block-end', 'bottom'],
    ['inset-inline-start', 'left'], ['inset-inline-end', 'right'],
    ['inline-size', 'width'], ['block-size', 'height'],
    ['overflow-block', 'overflow-y'], ['overflow-inline', 'overflow-x'],
    ['border-start-start-radius', 'border-top-left-radius'],
    ['border-start-end-radius', 'border-top-right-radius'],
    ['border-end-start-radius', 'border-bottom-left-radius'],
    ['border-end-end-radius', 'border-bottom-right-radius'],
    ['min-inline-size', 'min-width'], ['min-block-size', 'min-height'],
    ['max-inline-size', 'max-width'], ['max-block-size', 'max-height'],
  ];

  // Known properties: Chrome's `CSS.supports` answers `false` for an
  // unknown name.
  try {
    const known = new Set(CS_ORDER);
    for (const name of CSS_PROPS) {
      const plain = __s_toLowerCase(__s_replace(name, /[A-Z]/g, (c) => '-' + __s_toLowerCase(c)));
      known.add(plain);
      if (/^(webkit|moz|ms|o)-/.test(plain)) known.add('-' + plain);
    }
    Object.defineProperty(globalThis, '__pt_cssKnown', {
      value: (name) => known.has(__s_toLowerCase(__s_trim(String(name)))),
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}


  // Whether a node is in the flat tree: a shadow host's child gets there only
  // through a slot of the same name; the rest are hidden and have no style.
  function __inFlatTree(el) {
    // Every step goes up (a slot is below the host it leads back to), so no
    // cap: a cap of 10,000 gave elements deeper than that no style.
    let n = el;
    while (n) {
      const p = n.__ptParent;
      // The root is a document (the caller checks which one via ownerDocument:
      // in a realm the tree root and the global `document` differ).
      if (!p) return n.__ptType === 9;
      if (p.__ptType === ELEMENT_NODE && p.__ptShadow) {
        const sr = p.__ptShadow;
        const want = n.__ptType === ELEMENT_NODE ? (__ptGetA(n, 'slot') || '') : '';
        let slot = null;
        try { __walkTree(sr, (x) => { if (!slot && x.__ptType === ELEMENT_NODE && x.__ptLocal === 'slot' && (__ptGetA(x, 'name') || '') === want) slot = x; }); } catch (e) {}
        if (!slot) return false;
        n = slot;
        continue;
      }
      if (p.__ptType === 11 && p.__ptHost) { n = p.__ptHost; continue; }
      n = p;
    }
    return false;
  }
  globalThis.__pt_inFlatTree = __inFlatTree;

  // One element's computed values. Without `withLayout` nothing is laid out:
  // sizes keep their declared values and `flags` says which answers need the
  // boxes (auto margins, percentages).
  function __computedBuild(el, withLayout) {
    const flags = { auto: false, pct: null };
    let map = new Map();
    // An element outside the rendered tree has no computed style: Chrome
    // returns '' for every property and `length` 0.
    const connected = !!(el && el.__ptType === ELEMENT_NODE && el.isConnected);
    // A windowless document (DOMParser, createHTMLDocument): empty, length 0.
    // A node in the window but outside the flat tree (unslotted shadow host
    // child): names present, values empty.
    const inView = connected && (!el.ownerDocument || el.ownerDocument === document || !!el.ownerDocument.defaultView);
    if (!connected || !inView) {
      for (const k of CS_ORDER) map.set(k, '');
      return { map, names: [], flags };
    }
    if (!__inFlatTree(el)) {
      for (const k of CS_ORDER) map.set(k, '');
      const names = [...map.keys()];
      __addShorthands(map);
      return { map, names, flags };
    }
    map = new Map(__csBaseMap());
    const tag = (el && el.__ptLocal) || 'div';
    if (CS_DISPLAY[tag] === 'inline' || CS_INLINE) {
      const inlineish = CS_DISPLAY[tag] === 'inline';
      if (inlineish) for (const [k, v] of Object.entries(CS_INLINE)) map.set(k, v);
    }
    if (CS_REPLACED_TAGS.has(tag)) for (const [k, v] of Object.entries(CS_REPLACED)) map.set(k, v);
    if (CS_DISPLAY[tag]) map.set('display', CS_DISPLAY[tag]);
    if (UA_BIDI[tag]) map.set('unicode-bidi', UA_BIDI[tag]);
    // Author declarations (stylesheets and `style`) over defaults, then used
    // sizes.
    try {
      if (withLayout) __relayout(); else __styleBegin();
      const cascade = el ? __cascadeFor(el) : new Map();
      const fs = el ? __usedFontSize(el) : 16;
      // Inherited values first, then own on top.
      for (const prop of CSS_INHERITED) {
        if (cascade.has(prop)) continue;
        const v = __inheritedValue(el, prop);
        if (v == null) continue;
        const pairs = __expandMemo(prop, v);
        if (pairs) { for (const [k, val] of pairs) if (map.has(k)) map.set(k, val); continue; }
        if (map.has(prop)) map.set(prop, v);
      }
      if (UA_BOLD.has(tag)) map.set('font-weight', '700');
      // The UA stylesheet sets monospace and beats inheritance: `<pre>` in a
      // body with a set font is still monospace.
      if (UA_MONO.has(tag)) map.set('font-family', 'monospace');
      // Longhands only: computed style never lists shorthands.
      const put = (k, raw) => {
        if (!map.has(k)) return;
        // A percentage of the containing block is known only after layout.
        if (k !== 'font-size' && k !== 'line-height' && __s_indexOf(String(raw), '%') >= 0 && __LENGTH_PROPS.test(k)) {
          (flags.pct || (flags.pct = new Set())).add(k);
        }
        map.set(k, __resolveLength(__s_trim(String(raw)), k, fs, el));
      };
      const written = new Set();
      for (const [n, raw] of cascade) {
        const v = __resolveLength(raw, n, fs, el);
        const pairs = __expandMemo(n, v);
        if (pairs) {
          for (const [k, val] of pairs) { put(k, val); written.add(k); }
          continue;
        }
        put(n, v);
        written.add(n);
      }
      // UA stylesheet margins where the author set none (body 8px, p, h*).
      {
        const q = (v) => (Math.round(v * 1e4) / 1e4) + 'px';
        const uam = __uaMargin(tag, fs, el);
        if (uam) {
          for (const [k, v] of [['margin-top', uam[0]], ['margin-bottom', uam[0]],
                                ['margin-left', uam[1]], ['margin-right', uam[1]]]) {
            if (!written.has(k) && map.has(k)) map.set(k, q(v));
          }
        }
        // Chrome prints the used margin, not `auto` (half the free space when
        // centred).
        for (const k of ['margin-top', 'margin-bottom', 'margin-left', 'margin-right']) {
          if (/^auto$/i.test(String(map.get(k) || ''))) flags.auto = true;
        }
        const ab = withLayout && flags.auto ? __boxOf(el) : null;
        if (ab) {
          for (const [k, v] of [['margin-top', ab.mt], ['margin-bottom', ab.mb],
                                ['margin-left', ab.ml], ['margin-right', ab.mr]]) {
            if (v != null && /^auto$/i.test(String(map.get(k) || ''))) map.set(k, q(v));
          }
        }
      }
      // Transforms are printed as a matrix: `matrix(1.001, 0, 0, 1.001, 0, 0)`.
      {
        const tr = map.get('transform');
        if (tr && tr !== 'none') {
          const M = __parseTransform(tr);
          if (M) map.set('transform', 'matrix(' + M.map(__cssNum1).join(', ') + ')');
        }
      }
      // A family list substituted from a variable prints like a written one.
      { const ff = map.get('font-family'); if (ff && /["']/.test(ff)) map.set('font-family', __cssFontFamily(ff)); }
      // Any sRGB colour is normalised to `rgb(…)`.
      for (const k of __CS_COLOUR_KEYS) {
        if (!map.has(k)) continue;
        const norm = __colourMemo(map.get(k));
        if (norm) map.set(k, norm);
      }
      // `currentColor` is the initial value of several properties; Chrome
      // prints the element's own colour there.
      const own = map.get('color');
      if (own) {
        for (const k of CS_CURRENT_COLOUR) {
          if (!map.has(k)) continue;
          const cur = map.get(k);
          if (!written.has(k) || /^currentcolor$/i.test(String(cur))) map.set(k, own);
        }
      }
      // Logical names mirror physical ones.
      for (const [logical, physical] of CS_LOGICAL) {
        if (map.has(logical) && map.has(physical) && !written.has(logical)) {
          map.set(logical, map.get(physical));
        }
      }
      // A flex item is blockified and its initial min size becomes `auto`.
      try {
        const parent = el.__ptParent;
        const pd = parent && parent.__ptType === ELEMENT_NODE
          ? String(__cascadeFor(parent).get('display') || CS_DISPLAY[parent.__ptLocal] || '')
          : '';
        if (/^(flex|inline-flex|grid|inline-grid)$/.test(pd)) {
          if (!written.has('display') && /^(inline|inline-block)$/.test(String(map.get('display')))) {
            map.set('display', 'block');
          }
          for (const k of ['min-width', 'min-height', 'min-inline-size', 'min-block-size']) {
            if (!written.has(k) && map.has(k)) map.set(k, 'auto');
          }
        }
      } catch (e) {}
      // Shadow format: colour first, then four lengths, `inset` last.
      {
        const sh = String(map.get('box-shadow') || '');
        // All four lengths are printed; Chrome fills blur and spread with 0.
        if (sh && sh !== 'none') {
          const parts = __ptCssParts(sh);
          let colour = null, inset = false;
          const lens = [];
          for (const t of parts) {
            if (/^inset$/i.test(t)) { inset = true; continue; }
            if (/^[-\d.]/.test(t)) { lens.push(t); continue; }
            const norm = globalThis.__pt_cssColour && globalThis.__pt_cssColour(t);
            if (norm) colour = norm;
          }
          while (lens.length < 4) lens.push('0px');
          const px = (x) => (/^[-\d.]+$/.test(x) ? x + 'px' : x);
          map.set('box-shadow', [colour || map.get('color'), px(lens[0]), px(lens[1]), px(lens[2]), px(lens[3])]
            .join(' ') + (inset ? ' inset' : ''));
        }
      }
      // A line-height multiplier is printed in pixels, of the used font size
      // (the map's is still a percentage resolved against the width here).
      const lh = String(map.get('line-height') || '');
      if (/^[\d.]+$/.test(lh)) {
        const px = parseFloat(lh) * fs || 0;
        map.set('line-height', (Math.round(px * 1e4) / 1e4) + 'px');
      }
      // Links have a UA default style, visible in computed style.
      if (el.__ptLocal === 'a' && __ptHasA(el, 'href')) {
        if (!written.has('cursor')) map.set('cursor', 'pointer');
        if (!written.has('text-decoration-line')) map.set('text-decoration-line', 'underline');
      }
      // Shorthands Chrome does print are built from longhands.
      {
        const line = map.get('text-decoration-line');
        if (map.has('text-decoration')) {
          let td = line || 'none';
          const st = map.get('text-decoration-style');
          if (st && st !== 'solid') td += ' ' + st;
          const col = map.get('text-decoration-color');
          if (col && col !== own && written.has('text-decoration-color')) td += ' ' + col;
          map.set('text-decoration', td);
        }
        if (map.has('-webkit-text-decorations-in-effect')) {
          map.set('-webkit-text-decorations-in-effect', line && line !== 'none' ? line : 'none');
        }
        if (map.has('font-variant')) {
          const caps = map.get('font-variant-caps');
          map.set('font-variant', caps && caps !== 'normal' ? caps : 'normal');
        }
      }
      if (el) map.set('font-size', __usedFontSize(el) + 'px');
    } catch (e) {}
    try {
      if (el && el.__ptType === ELEMENT_NODE) {
        if (__isUnboxed(el)) map.set('display', 'none');
        const b = withLayout ? __boxOf(el) : null;
        if (b) {
          // `width` is the content box (CSS `width`), not the outer size,
          // printed with four decimals: `72.2656px`, not `72.265625px`.
          const q = (v) => {
            const r = Math.round(v * 1e4) / 1e4;
            return (Number.isInteger(r) ? r : parseFloat(r.toFixed(4))) + 'px';
          };
          // With `border-box`, padding and border included.
          const outer = map.get('box-sizing') === 'border-box';
          const w = outer ? b.w : b.cw, h = outer ? b.h : b.ch;
          map.set('width', q(w)); map.set('height', q(h));
          map.set('inline-size', q(w)); map.set('block-size', q(h));
          map.set('perspective-origin', q(b.w / 2) + ' ' + q(b.h / 2));
          map.set('transform-origin', q(b.w / 2) + ' ' + q(b.h / 2));
        }
      }
    } catch (e) {}
    // Only longhands are enumerated; shorthands are readable but not in
    // `length` or indexed names. Flex/grid items, out-of-flow boxes
    // (`absolute`, `fixed`, `float`) and the root are blockified: Chrome
    // prints `grid` where `inline-grid` was written.
    if (el && el.__ptType === ELEMENT_NODE) {
      const BLOCKIFY = { inline: 'block', 'inline-block': 'block', 'inline-flex': 'flex', 'inline-grid': 'grid', 'inline-table': 'table', 'inline-flow-root': 'flow-root', 'list-item': null };
      const d = map.get('display');
      const to = BLOCKIFY[d];
      if (to) {
        let why = el.ownerDocument && el === el.ownerDocument.documentElement;
        const pos = map.get('position');
        if (pos === 'absolute' || pos === 'fixed') why = true;
        if (map.get('float') && map.get('float') !== 'none') why = true;
        let p = el.__ptParent;
        while (!why && p && p.__ptType === ELEMENT_NODE) {
          const pd = __s_toLowerCase(__s_trim(String(__cascadeFor(p).get('display') || CS_DISPLAY[p.__ptLocal] || '')));
          if (pd === 'contents') { p = p.__ptParent; continue; }
          if (/^(inline-)?(flex|grid)$/.test(pd)) why = true;
          break;
        }
        if (why) map.set('display', to);
      }
    }
    // Numbers print with six significant digits: `138.828125px` -> `138.828px`.
    for (const [k, v] of map) {
      if (typeof v === 'string' && v && !(__s_charCodeAt(k, 0) === 45 && __s_charCodeAt(k, 1) === 45)) {
        const n = __numbersMemo(v);
        if (n !== v) map.set(k, n);
      }
    }
    const names = [...map.keys()];
    // Shorthands are assembled when one is asked for (`__computedValue`).
    if (flags.pct) flags.pct = __geoClosure(flags.pct);
    return { map, names, flags, sh: false };
  }
  // Strings repeat across elements (`0px`, `rgb(0, 0, 0)`): formatting is
  // remembered per string.
  const __CS_COLOUR_KEYS = [];
  const __memoOf = (f) => {
    const m = new Map();
    return (v) => {
      let hit = m.get(v);
      if (hit !== undefined) return hit;
      try { hit = f(v); } catch (e) { hit = v; }
      if (m.size > 8192) m.clear();
      m.set(v, hit);
      return hit;
    };
  };
  // Shorthand expansion by property and value; the pairs are shared, read only.
  const __expandMemoMap = new Map();
  const __expandMemo = (prop, v) => {
    const key = prop + '\u0000' + v;
    let hit = __expandMemoMap.get(key);
    if (hit !== undefined) return hit;
    hit = __ptExpand(prop, v) || null;
    if (__expandMemoMap.size > 8192) __expandMemoMap.clear();
    __expandMemoMap.set(key, hit);
    return hit;
  };
  const __numbersMemo = __memoOf((v) => (/\d/.test(v) ? __cssNumbers(v) : v));
  const __colourMemo = __memoOf((v) => (globalThis.__pt_cssColour ? globalThis.__pt_cssColour(v) || null : null));
  let __CS_BASE_MAP = null;
  const __csBaseMap = () => {
    if (__CS_BASE_MAP) return __CS_BASE_MAP;
    __CS_BASE_MAP = new Map();
    for (const k of CS_ORDER) {
      __CS_BASE_MAP.set(k, CS_BASE[k]);
      if (k === 'color' || __s_endsWith(k, '-color')) __CS_COLOUR_KEYS.push(k);
    }
    return __CS_BASE_MAP;
  };
  // Every name whose answer follows from these longhands: logical mirrors,
  // shorthands, `-webkit-` aliases.
  function __geoClosure(keys) {
    const out = new Set(keys);
    for (const [logical, physical] of CS_LOGICAL) if (out.has(physical)) out.add(logical);
    for (const sh in CSS_LONGHANDS) if (CSS_LONGHANDS[sh].some((k) => out.has(k))) out.add(sh);
    for (const alias in SH_ALIAS) if (out.has(SH_ALIAS[alias])) out.add(alias);
    for (const k of [...out]) {
      if (/^(padding|margin)-/.test(k) || /-(inline|block)-size$/.test(k)) {
        for (const w of ['webkit-padding-before', 'webkit-padding-after', 'webkit-padding-start', 'webkit-padding-end',
          'webkit-margin-before', 'webkit-margin-after', 'webkit-margin-start', 'webkit-margin-end',
          'webkit-logical-width', 'webkit-logical-height', 'webkit-min-logical-width', 'webkit-min-logical-height',
          'webkit-max-logical-width', 'webkit-max-logical-height']) out.add(w);
        break;
      }
    }
    return out;
  }

  // Computed style is live, as in Chrome: a new declaration per call whose
  // values follow the element (`el.style.color = 'red'` shows in a style read
  // before it). Values are worked out on first read, from the style pass
  // alone; only sizes, auto margins and percentages lay the page out. Per
  // element the result is kept while its cascade is the same object (a
  // mutation drops the cascades it can reach, see `__styleTouch`) and, for
  // the layout part, while the layout is.
  const __GEO_ALWAYS = new Set(['width', 'height', 'inline-size', 'block-size', 'perspective-origin',
    'transform-origin', 'webkit-perspective-origin', 'webkit-transform-origin', 'webkit-logical-width',
    'webkit-logical-height']);
  const __GEO_MARGIN = new Set(['margin-top', 'margin-right', 'margin-bottom', 'margin-left', 'margin-block-start',
    'margin-block-end', 'margin-inline-start', 'margin-inline-end', 'margin', 'margin-block', 'margin-inline',
    'webkit-margin-before', 'webkit-margin-after', 'webkit-margin-start', 'webkit-margin-end']);
  const __computedState = new WeakMap();
  // Per element: the stamp of the tree state the answer below was checked
  // at; reads between two changes go straight to it.
  const __computedStamp = () => __layoutSeq * 1e7 + LAYOUT.W * 1e3 + LAYOUT.H;
  function __computedNow(el) {
    let st = __computedState.get(el);
    if (!st) { st = { cs: null, style: null, geoAt: -1, geo: null, at: -1, names: null }; __computedState.set(el, st); }
    const stamp = __computedStamp();
    if (st.at === stamp && st.style) return st;
    st.at = stamp;
    st.names = null;
    const rendered = el.isConnected && __inFlatTree(el)
      && (!el.ownerDocument || el.ownerDocument === document || !!el.ownerDocument.defaultView);
    // Not rendered: empty answers, rebuilt only after the tree changed.
    if (!rendered) {
      if (st.cs !== null || st.seq !== __layoutSeq || !st.style) { st.cs = null; st.seq = __layoutSeq; st.style = __computedBuild(el, false); }
      return st;
    }
    __styleBegin();
    const cs = __cascadeFor(el);
    if (st.cs !== cs || !st.style || st.gen !== __styleGen) { st.cs = cs; st.gen = __styleGen; st.style = __computedBuild(el, false); st.geoAt = -1; st.geo = null; }
    return st;
  }
  function __computedValue(el, key) {
    const st = __computedNow(el), style = st.style;
    if (!st.cs) return style.map.get(key);
    // Custom properties are readable via `getPropertyValue('--name')` but not
    // enumerated; read straight from the element's variables.
    if (__s_charCodeAt(key, 0) === 45 && __s_charCodeAt(key, 1) === 45) {
      const v = st.cs.__ptVars && st.cs.__ptVars[key];
      return typeof v === 'string' ? v : undefined;
    }
    const f = style.flags;
    const read = (r) => {
      const v = r.map.get(key);
      if (v !== undefined || r.sh) return v;
      r.sh = true;
      __addShorthands(r.map);
      return r.map.get(key);
    };
    if (__GEO_ALWAYS.has(key) || (f.auto && __GEO_MARGIN.has(key)) || (f.pct && f.pct.has(key))) {
      __relayout();
      if (st.geoAt !== __layoutBuilt || !st.geo) { st.geo = __computedBuild(el, true); st.geoAt = __layoutBuilt; }
      return read(st.geo);
    }
    return read(style);
  }
  function __computedNames(el) {
    if (!el || el.__ptType !== ELEMENT_NODE) return [];
    const st = __computedState.get(el);
    if (st && st.names && st.at === __computedStamp()) return st.names;
    let names = CS_ORDER;
    if (!el.isConnected || (el.ownerDocument && el.ownerDocument !== document && !el.ownerDocument.defaultView)) names = [];
    if (st && st.at === __computedStamp()) st.names = names;
    return names;
  }
  // A map's face over the live values, for the prototype's methods.
  const __computedView = (el) => ({
    get: (k) => __computedValue(el, k),
    has: (k) => { const v = __computedValue(el, k); return v !== undefined; },
  });
  const __camelKeys = new Map();
  const __computedKeysOf = (name) => {
    let keys = __camelKeys.get(name);
    if (keys) return keys;
    // `webkitBorderAfter` is `-webkit-border-after` (leading dash for vendor
    // names), while `webkitAlignItems` is just another name for `align-items`.
    const plain = __s_toLowerCase(__s_replace(name, /[A-Z]/g, (c) => '-' + __s_toLowerCase(c)));
    keys = /^(webkit|moz|ms|o)-/.test(plain)
      ? ['-' + plain, plain, __s_replace(plain, /^(webkit|moz|ms|o)-/, '')]
      : [plain];
    __camelKeys.set(name, keys);
    return keys;
  };
  const __computedOf = (el, name) => {
    for (const k of __computedKeysOf(name)) { const v = __computedValue(el, k); if (v) return v; }
    return '';
  };
  // A dashed name as a property (`cs['background-color']`): Chrome answers it
  // as an own property too, though it is not listed.
  let __DASH_NAMES = null;
  const __dashNames = () => {
    if (__DASH_NAMES) return __DASH_NAMES;
    __DASH_NAMES = new Map();
    for (const name of CSS_PROPS) {
      const keys = __computedKeysOf(name);
      for (const k of keys) if (!__DASH_NAMES.has(k)) __DASH_NAMES.set(k, name);
    }
    return __DASH_NAMES;
  };
  let __COMPUTED_KEYS = null, __INDEX_KEYS = [];
  const __computedOwnKeys = (n) => {
    if (!__COMPUTED_KEYS) __COMPUTED_KEYS = __withEpub(CSS_PROPS.slice());
    if (__INDEX_KEYS.length !== n) { __INDEX_KEYS = []; for (let i = 0; i < n; i++) __INDEX_KEYS.push(String(i)); }
    return __INDEX_KEYS.concat(__COMPUTED_KEYS);
  };
  const __readOnly = (what) => __pt_mkErr(globalThis.DOMException || Error, what, 'NoModificationAllowedError');
  const __isIndex = (p) => typeof p === 'string' && p.length > 0 && p.length < 8 && /^(0|[1-9]\d*)$/.test(p);

  globalThis.getComputedStyle = (el, pseudo) => {
    const proto = __inlineStyleProto();
    const target = Object.create(proto);
    const view = __computedView(el);
    const reader = {
      computed: true, el,
      get names() { return __computedNames(el); },
      get map() { return view; },
      read: () => view,
      write: () => { throw __readOnly("Failed to set the 'cssFloat' property on 'CSSStyleDeclaration': These styles are computed, and therefore read-only."); },
    };
    __cssReaders.set(target, reader);
    const props = __cssPropSet();
    const valueOf = (p) => {
      if (props.has(p)) return __computedOf(el, p);
      const camel = __dashNames().get(p);
      return camel !== undefined ? (__computedValue(el, p) || __computedOf(el, camel)) : undefined;
    };
    const px = __ptProxy(target, {
      ownKeys: () => __computedOwnKeys(__computedNames(el).length),
      getOwnPropertyDescriptor: (t, p) => {
        if (typeof p === 'string') {
          if (EPUB_SET.has(p)) return undefined;
          if (__isIndex(p)) {
            const names = __computedNames(el);
            return +p < names.length ? { value: names[+p], writable: false, enumerable: true, configurable: true } : undefined;
          }
          const v = valueOf(p);
          if (v !== undefined) return { value: v, writable: true, enumerable: true, configurable: true };
        }
        return Reflect.getOwnPropertyDescriptor(t, p);
      },
      has: (t, p) => {
        if (typeof p === 'string') {
          if (EPUB_SET.has(p)) return false;
          if (__isIndex(p)) return +p < __computedNames(el).length;
          if (props.has(p) || __dashNames().has(p)) return true;
        }
        return Reflect.has(t, p);
      },
      get: (t, p, recv) => {
        if (typeof p === 'string') {
          if (EPUB_SET.has(p)) return undefined;
          if (__isIndex(p)) return __computedNames(el)[+p];
          const v = valueOf(p);
          if (v !== undefined) return v;
        }
        return Reflect.get(t, p, recv);
      },
      set: (t, p, v, recv) => {
        if (typeof p === 'string') {
          if (p === 'cssText') throw __readOnly("Failed to set the 'cssText' property on 'CSSStyleDeclaration': These styles are computed, and therefore read-only.");
          if (props.has(p) || __dashNames().has(p)) {
            throw __readOnly("Failed to set a named property '" + p + "' on 'CSSStyleDeclaration': These styles are computed, and therefore the '" + p + "' property is read-only.");
          }
          if (__isIndex(p)) return true;
        }
        return Reflect.set(t, p, v, recv);
      },
    });
    __cssReaders.set(px, reader);
    return px;
  };

  // Computed shorthands: Chrome returns the assembled value; pages that
  // enumerate the whole style read them. Built from longhands by CSS
  // serialization rules; `-webkit-*` aliases mirror the plain property; the
  // rest are initial values taken from Chrome (shorthands with no longhands we
  // track).
  const SH_ALIAS = {"webkit-align-content": "align-content", "webkit-align-items": "align-items", "webkit-align-self": "align-self", "webkit-animation": "animation", "webkit-animation-delay": "animation-delay", "webkit-animation-direction": "animation-direction", "webkit-animation-duration": "animation-duration", "webkit-animation-fill-mode": "animation-fill-mode", "webkit-animation-iteration-count": "animation-iteration-count", "webkit-animation-name": "animation-name", "webkit-animation-play-state": "animation-play-state", "webkit-animation-timing-function": "animation-timing-function", "webkit-app-region": "app-region", "webkit-appearance": "appearance", "webkit-backface-visibility": "backface-visibility", "webkit-background-clip": "background-clip", "webkit-background-origin": "background-origin", "webkit-background-size": "background-size", "webkit-border-bottom-left-radius": "border-bottom-left-radius", "webkit-border-bottom-right-radius": "border-bottom-right-radius", "webkit-border-image": "border-image", "webkit-border-radius": "border-radius", "webkit-border-top-left-radius": "border-top-left-radius", "webkit-border-top-right-radius": "border-top-right-radius", "webkit-box-decoration-break": "box-decoration-break", "webkit-box-shadow": "box-shadow", "webkit-box-sizing": "box-sizing", "webkit-clip-path": "clip-path", "webkit-column-count": "column-count", "webkit-column-gap": "column-gap", "webkit-column-rule": "column-rule", "webkit-column-rule-color": "column-rule-color", "webkit-column-rule-style": "column-rule-style", "webkit-column-rule-width": "column-rule-width", "webkit-column-span": "column-span", "webkit-column-width": "column-width", "webkit-columns": "columns", "webkit-filter": "filter", "webkit-flex": "flex", "webkit-flex-basis": "flex-basis", "webkit-flex-direction": "flex-direction", "webkit-flex-flow": "flex-flow", "webkit-flex-grow": "flex-grow", "webkit-flex-shrink": "flex-shrink", "webkit-flex-wrap": "flex-wrap", "webkit-font-feature-settings": "font-feature-settings", "webkit-hyphenate-character": "hyphenate-character", "webkit-justify-content": "justify-content", "webkit-line-break": "line-break", "webkit-mask": "mask", "webkit-mask-clip": "mask-clip", "webkit-mask-composite": "mask-composite", "webkit-mask-image": "mask-image", "webkit-mask-origin": "mask-origin", "webkit-mask-position": "mask-position", "webkit-mask-repeat": "mask-repeat", "webkit-mask-size": "mask-size", "webkit-opacity": "opacity", "webkit-order": "order", "webkit-perspective": "perspective", "webkit-perspective-origin": "perspective-origin", "webkit-print-color-adjust": "print-color-adjust", "webkit-shape-image-threshold": "shape-image-threshold", "webkit-shape-margin": "shape-margin", "webkit-shape-outside": "shape-outside", "webkit-text-emphasis": "text-emphasis", "webkit-text-emphasis-color": "text-emphasis-color", "webkit-text-emphasis-position": "text-emphasis-position", "webkit-text-emphasis-style": "text-emphasis-style", "webkit-text-size-adjust": "text-size-adjust", "webkit-transform": "transform", "webkit-transform-origin": "transform-origin", "webkit-transform-style": "transform-style", "webkit-transition": "transition", "webkit-transition-delay": "transition-delay", "webkit-transition-duration": "transition-duration", "webkit-transition-property": "transition-property", "webkit-transition-timing-function": "transition-timing-function", "webkit-user-select": "user-select", "webkit-writing-mode": "writing-mode"};
  const SH_CONST = {"animation-range": "normal", "border-image": "none", "border-spacing": "0px", "column-rule-inset": "0px", "column-rule-inset-cap": "0px", "column-rule-inset-end": "0px", "column-rule-inset-junction": "0px", "column-rule-inset-start": "0px", "columns": "auto", "container": "none", "corner-block-end-shape": "round", "corner-block-start-shape": "round", "corner-bottom-shape": "round", "corner-inline-end-shape": "round", "corner-inline-start-shape": "round", "corner-left-shape": "round", "corner-right-shape": "round", "corner-shape": "round", "corner-top-shape": "round", "interest-delay": "normal", "marker": "none", "mask": "none", "offset": "none 0px auto 0deg", "page": "auto", "position-try": "none", "row-rule": "3px rgb(0, 0, 0)", "row-rule-inset": "0px", "row-rule-inset-cap": "0px", "row-rule-inset-end": "0px", "row-rule-inset-junction": "0px", "row-rule-inset-start": "0px", "rule": "3px rgb(0, 0, 0)", "rule-break": "normal", "rule-color": "rgb(0, 0, 0)", "rule-inset": "0px", "rule-inset-cap": "0px", "rule-inset-end": "0px", "rule-inset-junction": "0px", "rule-inset-start": "0px", "rule-style": "none", "rule-visibility-items": "normal", "rule-width": "3px", "scroll-timeline": "none", "text-box": "normal", "timeline-trigger": "none", "timeline-trigger-activation-range": "normal", "timeline-trigger-active-range": "auto", "view-timeline": "none", "webkit-border-after": "0px none rgb(0, 0, 0)", "webkit-border-after-color": "rgb(0, 0, 0)", "webkit-border-after-style": "none", "webkit-border-after-width": "0px", "webkit-border-before": "0px none rgb(0, 0, 0)", "webkit-border-before-color": "rgb(0, 0, 0)", "webkit-border-before-style": "none", "webkit-border-before-width": "0px", "webkit-border-end": "0px none rgb(0, 0, 0)", "webkit-border-end-color": "rgb(0, 0, 0)", "webkit-border-end-style": "none", "webkit-border-end-width": "0px", "webkit-border-horizontal-spacing": "0px", "webkit-border-start": "0px none rgb(0, 0, 0)", "webkit-border-start-color": "rgb(0, 0, 0)", "webkit-border-start-style": "none", "webkit-border-start-width": "0px", "webkit-border-vertical-spacing": "0px", "webkit-box-align": "stretch", "webkit-box-direction": "normal", "webkit-box-flex": "0", "webkit-box-ordinal-group": "1", "webkit-box-orient": "horizontal", "webkit-box-pack": "start", "webkit-box-reflect": "none", "webkit-column-break-after": "auto", "webkit-column-break-before": "auto", "webkit-column-break-inside": "auto", "webkit-font-smoothing": "auto", "webkit-line-clamp": "none", "webkit-locale": "\"en\"", "webkit-logical-height": "0px", "webkit-logical-width": "925px", "webkit-margin-after": "0px", "webkit-margin-before": "0px", "webkit-margin-end": "0px", "webkit-margin-start": "0px", "webkit-mask-box-image": "none", "webkit-mask-box-image-outset": "0", "webkit-mask-box-image-repeat": "stretch", "webkit-mask-box-image-slice": "0 fill", "webkit-mask-box-image-source": "none", "webkit-mask-box-image-width": "auto", "webkit-mask-position-x": "0%", "webkit-mask-position-y": "0%", "webkit-max-logical-height": "none", "webkit-max-logical-width": "none", "webkit-min-logical-height": "0px", "webkit-min-logical-width": "0px", "webkit-padding-after": "0px", "webkit-padding-before": "0px", "webkit-padding-end": "0px", "webkit-padding-start": "0px", "webkit-rtl-ordering": "logical", "webkit-ruby-position": "before", "webkit-tap-highlight-color": "rgba(0, 0, 0, 0.18)", "webkit-text-combine": "none", "webkit-text-decorations-in-effect": "none", "webkit-text-fill-color": "rgb(0, 0, 0)", "webkit-text-orientation": "vertical-right", "webkit-text-security": "none", "webkit-text-stroke": "0px rgb(0, 0, 0)", "webkit-text-stroke-color": "rgb(0, 0, 0)", "webkit-text-stroke-width": "0px", "webkit-user-drag": "auto", "webkit-user-modify": "read-only"};
  const __addShorthands = (map) => {
    const g = (k) => map.get(k) || '';
    const set = (k, v) => { if (v !== '' && v != null) map.set(k, v); };
    // Four sides collapse while values match.
    const four = (t, r, b, l) => {
      if (!t) return '';
      if (t === r && r === b && b === l) return t;
      if (t === b && r === l) return t + ' ' + r;
      if (r === l) return t + ' ' + r + ' ' + b;
      return t + ' ' + r + ' ' + b + ' ' + l;
    };
    const two = (a, b) => (a === b ? a : (a && b ? a + ' ' + b : a || b));
    const box = (name, suffix) => four(g(name + '-top' + suffix), g(name + '-right' + suffix),
      g(name + '-bottom' + suffix), g(name + '-left' + suffix));
    set('margin', box('margin', ''));
    set('padding', box('padding', ''));
    set('scroll-margin', box('scroll-margin', ''));
    set('scroll-padding', box('scroll-padding', ''));
    set('inset', four(g('top'), g('right'), g('bottom'), g('left')));
    set('border-width', box('border', '-width'));
    set('border-style', box('border', '-style'));
    set('border-color', box('border', '-color'));
    set('border-radius', four(g('border-top-left-radius'), g('border-top-right-radius'),
      g('border-bottom-right-radius'), g('border-bottom-left-radius')));
    for (const [sh, base] of [['margin-block', 'margin-block'], ['margin-inline', 'margin-inline'],
      ['padding-block', 'padding-block'], ['padding-inline', 'padding-inline'],
      ['inset-block', 'inset-block'], ['inset-inline', 'inset-inline'],
      ['scroll-margin-block', 'scroll-margin-block'], ['scroll-margin-inline', 'scroll-margin-inline'],
      ['scroll-padding-block', 'scroll-padding-block'], ['scroll-padding-inline', 'scroll-padding-inline'],
      ['border-block-width', 'border-block'], ['border-inline-width', 'border-inline'],
      ['border-block-style', 'border-block'], ['border-inline-style', 'border-inline'],
      ['border-block-color', 'border-block'], ['border-inline-color', 'border-inline']]) {
      const tail = __s_slice(sh, base.length);
      set(sh, two(g(base + '-start' + tail), g(base + '-end' + tail)));
    }
    // Border: width, style, colour, only when all sides agree.
    const edge = (p) => {
      const w = g(p + '-width'), s = g(p + '-style'), c = g(p + '-color');
      return w && s && c ? w + ' ' + s + ' ' + c : '';
    };
    for (const p of ['border-top', 'border-right', 'border-bottom', 'border-left',
      'border-block-start', 'border-block-end', 'border-inline-start', 'border-inline-end']) set(p, edge(p));
    set('border-block', edge('border-block-start') === edge('border-block-end') ? edge('border-block-start') : '');
    set('border-inline', edge('border-inline-start') === edge('border-inline-end') ? edge('border-inline-start') : '');
    const bt = edge('border-top');
    set('border', (bt && bt === edge('border-right') && bt === edge('border-bottom') && bt === edge('border-left')) ? bt : '');
    set('column-rule', g('column-rule-width') + ' ' + g('column-rule-color'));
    set('row-rule', g('row-rule-width') + ' ' + g('row-rule-color'));
    // Shared column/row rule, printed only when both match.
    set('rule-width', two(g('row-rule-width'), g('column-rule-width')));
    set('rule-style', two(g('row-rule-style'), g('column-rule-style')));
    set('rule-color', two(g('row-rule-color'), g('column-rule-color')));
    set('rule', g('rule-width') + ' ' + g('rule-color'));
    // Old webkit logical-side names carry the same values.
    for (const [old_, now] of [['webkit-border-before', 'border-block-start'],
      ['webkit-border-after', 'border-block-end'],
      ['webkit-border-start', 'border-inline-start'],
      ['webkit-border-end', 'border-inline-end'],
      ['webkit-margin-before', 'margin-block-start'], ['webkit-margin-after', 'margin-block-end'],
      ['webkit-margin-start', 'margin-inline-start'], ['webkit-margin-end', 'margin-inline-end'],
      ['webkit-padding-before', 'padding-block-start'], ['webkit-padding-after', 'padding-block-end'],
      ['webkit-padding-start', 'padding-inline-start'], ['webkit-padding-end', 'padding-inline-end'],
      ['webkit-logical-width', 'inline-size'], ['webkit-logical-height', 'block-size'],
      ['webkit-min-logical-width', 'min-inline-size'], ['webkit-min-logical-height', 'min-block-size'],
      ['webkit-max-logical-width', 'max-inline-size'], ['webkit-max-logical-height', 'max-block-size'],
      ['webkit-perspective-origin', 'perspective-origin'],
      ['webkit-transform-origin', 'transform-origin']]) {
      map.set(old_, g(now));
      for (const tail of ['-width', '-style', '-color']) if (g(now + tail)) map.set(old_ + tail, g(now + tail));
    }
    // Text stroke: width and colour together.
    map.set('webkit-text-stroke-color', g('-webkit-text-stroke-color'));
    map.set('webkit-text-stroke-width', g('-webkit-text-stroke-width'));
    map.set('webkit-text-stroke', g('-webkit-text-stroke-width') + ' ' + g('-webkit-text-stroke-color'));
    // Outline order: colour, style, width.
    set('outline', g('outline-color') + ' ' + g('outline-style') + ' ' + g('outline-width'));
    set('background', g('background-color') + ' ' + g('background-image') + ' ' + g('background-repeat') +
      ' ' + g('background-attachment') + ' ' + g('background-position') + ' / ' + g('background-size') +
      ' ' + g('background-origin') + ' ' + g('background-clip'));
    const bp = __s_split(g('background-position'), /\s+/);
    set('background-position-x', bp[0] || '');
    set('background-position-y', bp[1] || bp[0] || '');
    set('flex', g('flex-grow') + ' ' + g('flex-shrink') + ' ' + g('flex-basis'));
    set('flex-flow', g('flex-direction') + ' ' + g('flex-wrap'));
    // Font: style, variant, weight, size/line-height, family.
    {
      const bits = [];
      if (g('font-style') && g('font-style') !== 'normal') bits.push(g('font-style'));
      if (g('font-variant-caps') && g('font-variant-caps') !== 'normal') bits.push(g('font-variant-caps'));
      if (g('font-weight') && g('font-weight') !== '400') bits.push(g('font-weight'));
      const lh = g('line-height');
      bits.push(lh && lh !== 'normal' ? g('font-size') + ' / ' + lh : g('font-size'));
      bits.push(g('font-family'));
      set('font', bits.filter(Boolean).join(' '));
    }
    set('font-synthesis', ['weight', 'style', 'small-caps']
      .filter((p) => g('font-synthesis-' + p) === 'auto').join(' ') || 'none');
    set('list-style', g('list-style-position') + ' ' + g('list-style-image') + ' ' + g('list-style-type'));
    set('text-emphasis', g('text-emphasis-style') + ' ' + g('text-emphasis-color'));
    set('gap', two(g('row-gap'), g('column-gap')));
    set('grid-gap', two(g('row-gap'), g('column-gap')));
    set('grid-row-gap', g('row-gap'));
    set('grid-column-gap', g('column-gap'));
    set('place-content', two(g('align-content'), g('justify-content')));
    set('place-items', two(g('align-items'), g('justify-items')));
    set('place-self', two(g('align-self'), g('justify-self')));
    // Grid parts are slash-separated; an empty end is omitted.
    for (const axis of ['row', 'column']) {
      const a = g('grid-' + axis + '-start'), b = g('grid-' + axis + '-end');
      set('grid-' + axis, !b || b === 'auto' || b === a ? a : a + ' / ' + b);
    }
    {
      const quad = [g('grid-row-start'), g('grid-column-start'), g('grid-row-end'), g('grid-column-end')];
      set('grid-area', quad.every((x) => x === 'auto') ? 'auto' : quad.join(' / '));
    }
    set('grid-template', g('grid-template-rows') === 'none' && g('grid-template-columns') === 'none' &&
      g('grid-template-areas') === 'none' ? 'none' : '');
    set('grid', g('grid-template') === 'none'
      ? 'none / none / none / ' + g('grid-auto-flow') + ' / ' + g('grid-auto-rows') + ' / ' + g('grid-auto-columns')
      : '');
    set('overflow', two(g('overflow-x'), g('overflow-y')));
    set('overscroll-behavior', two(g('overscroll-behavior-x'), g('overscroll-behavior-y')));
    set('columns', two(g('column-width'), g('column-count')) === 'auto auto' ? 'auto'
      : two(g('column-width'), g('column-count')));
    set('animation', g('animation-name') === 'none' && g('animation-duration') === '0s' ? 'none' : '');
    // Transition: parts at their initial value are omitted.
    {
      const dur = g('transition-duration'), ease = g('transition-timing-function');
      const delay = g('transition-delay'), prop = g('transition-property');
      set('transition', dur === '0s' && delay === '0s' ? prop
        : [prop && prop !== 'all' ? prop : '', dur,
           ease && ease !== 'ease' ? ease : '', delay && delay !== '0s' ? delay : '']
          .filter(Boolean).join(' '));
    }
    // White-space: known combinations collapse to one keyword.
    const wsc = g('white-space-collapse'), twm = g('text-wrap-mode');
    set('white-space', wsc === 'collapse' && twm === 'wrap' ? 'normal'
      : (wsc === 'preserve' && twm === 'nowrap' ? 'pre'
      : (wsc === 'preserve' && twm === 'wrap' ? 'pre-wrap'
      : (wsc === 'preserve-breaks' && twm === 'wrap' ? 'pre-line'
      : (wsc === 'collapse' && twm === 'nowrap' ? 'nowrap' : wsc + ' ' + twm)))));
    set('text-wrap', two(g('text-wrap-mode'), g('text-wrap-style')) === 'wrap auto' ? 'wrap'
      : two(g('text-wrap-mode'), g('text-wrap-style')));
    set('word-wrap', g('overflow-wrap'));
    set('page-break-after', g('break-after'));
    set('page-break-before', g('break-before'));
    set('page-break-inside', g('break-inside'));
    // Constants before aliases, or an alias mirrors nothing.
    for (const k of Object.keys(SH_CONST)) if (!map.has(k)) map.set(k, SH_CONST[k]);
    for (const k of Object.keys(SH_ALIAS)) set(k, g(SH_ALIAS[k]));
  };

  /// Font size in effect on an element (inherited; `em` resolves against it).
  function __usedFontSize(el) {
    if (el && el.__ptType === ELEMENT_NODE) {
      const hit = __passFont.get(el);
      if (hit !== undefined) return hit;
      const v = __usedFontSizeRaw(el);
      __passFont.set(el, v);
      return v;
    }
    return __usedFontSizeRaw(el);
  }

  const FONT_KEYWORDS = {
    'xx-small': 9, 'x-small': 10, small: 13, medium: 16, large: 18,
    'x-large': 24, 'xx-large': 32, 'xxx-large': 48,
  };

  // One element's `font-size` applied to the size it inherits.
  function __fontSizeStep(e, size) {
    __lstats.fontSteps++;
    const raw = __cascadeFor(e).get('font-size');
    if (raw == null) {
      const f = UA_FONT_SIZE[__s_toLowerCase(e.__ptLocal || '')];
      return f ? size * f : size;
    }
    let v = __s_toLowerCase(__s_trim(String(raw)));
    // `rem` on the root means the initial font size, not its own.
    if (e.ownerDocument && e === e.ownerDocument.documentElement) v = __s_replace(v, /(\d)rem\b/g, '$1em');
    if (FONT_KEYWORDS[v]) return FONT_KEYWORDS[v];
    if (v === 'smaller') return size / 1.2;
    if (v === 'larger') return size * 1.2;
    // `em`, percentages, `calc()` and `clamp()` resolve against the parent's size.
    const px = __lengthPx(v, size, size);
    return px != null && px >= 0 ? px : size;
  }
  // Every `font-size` from the root down applied to 16px, unrounded: the
  // parent's, kept for the pass, with the element's own on top. Walking the
  // whole chain per element was a sixth of a Wikipedia layout.
  function __fontFold(el) {
    const chain = [];
    let size = 16;
    for (let e = el; e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) {
      const hit = __passFold.get(e);
      if (hit !== undefined) { size = hit; break; }
      chain.push(e);
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      size = __fontSizeStep(chain[i], size);
      __passFold.set(chain[i], size);
    }
    return size;
  }

  function __usedFontSizeRaw(el) {
    // Form controls do not inherit the page font size; the UA gives their own.
    const own = (el && el.__ptLocal) || '';
    let start = 16;
    if (own === 'input' || own === 'button' || own === 'select' || own === 'textarea') {
      start = UA_FORM_FONT;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return start;
    }
    // Monospace text uses 13px, not 16px, so `pre` without its own rule gets
    // 13px margins.
    if (own !== 'textarea' && UA_MONO.has(own)) {
      start = 13;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return start;
    }
    let size;
    if (start === 16 && el && el.__ptType === ELEMENT_NODE) size = __fontFold(el);
    else {
      // A control with its own size starts from the UA's and folds the
      // whole chain over it.
      const chain = [];
      for (let e = el; e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) chain.push(e);
      size = start;
      for (let i = chain.length - 1; i >= 0; i--) size = __fontSizeStep(chain[i], size);
    }
    return Math.round(size * 1e4) / 1e4;
  }

  /// Length in pixels as Chrome reports it: `em` from the font size,
  /// percentages from the parent width, the rest as is.
  const __LENGTH_PROPS = /^(width|height|min-|max-|margin|padding|border-.*-width|top|right|bottom|left|inset|gap|font-size|line-height|text-indent|letter-spacing|word-spacing|outline-width|border-spacing|column-gap|row-gap)/;
  function __resolveLength(raw, prop, fontSize, el) {
    let v = String(raw);
    if (!__LENGTH_PROPS.test(prop)) return v;
    // Chrome prints an expression as a number when everything is known.
    if (__CALC_FN.test(v)) v = __ptCalcOut(v, fontSize, el);
    if (!/[\d.](?:em|rem|pt|%|[dsl]?v(?:h|w|min|max))/.test(v)) return v;
    return __s_replace(v, /(-?[\d.]+)(em|rem|pt|[dsl]?vmin|[dsl]?vmax|[dsl]?vh|[dsl]?vw|%)(?![\w-])/g, (m, n, unit) => {
      const x = parseFloat(n);
      if (unit === 'pt') return (x * 4 / 3) + 'px';
      if (unit === 'em') return (x * fontSize) + 'px';
      if (unit === 'rem') return (x * __rootFontSize()) + 'px';
      if (unit.length > 2 && /^[dsl]v/.test(unit)) unit = __s_slice(unit, 1);
      // Viewport units are printed in pixels too (`margin: 15vh auto`).
      if (unit === 'vh' || unit === 'vw' || unit === 'vmin' || unit === 'vmax') {
        const base = unit === 'vh' ? LAYOUT.H : unit === 'vw' ? LAYOUT.W
          : unit === 'vmin' ? Math.min(LAYOUT.W, LAYOUT.H) : Math.max(LAYOUT.W, LAYOUT.H);
        return (Math.round(x / 100 * base * 64) / 64) + 'px';
      }
      // Percent line-height is relative to the font size, not the width.
      if (prop === 'line-height') return (Math.round(x / 100 * fontSize * 64) / 64) + 'px';
      // Vertical percentages are relative to the width too, per spec.
      const base = __containingWidth(el);
      return base != null ? (Math.round(x / 100 * base * 64) / 64) + 'px' : m;
    });
  }

  /// Resolve each top-level `calc()`/`min()`/`max()`/`clamp()` to pixels when
  /// possible; otherwise leave it as written.
  function __ptCalcOut(v, fontSize, el) {
    let out = '', i = 0;
    const re = /(?:-webkit-)?(?:calc|min|max|clamp)\(/gi;
    for (;;) {
      re.lastIndex = i;
      const m = re.exec(v);
      if (!m) { out += __s_slice(v, i); break; }
      if (m.index > 0 && /[\w-]/.test(v[m.index - 1])) { out += __s_slice(v, i, re.lastIndex); i = re.lastIndex; continue; }
      let depth = 1, j = re.lastIndex;
      for (; j < v.length && depth; j++) {
        if (v[j] === '(') depth++;
        else if (v[j] === ')') depth--;
      }
      const part = __s_slice(v, m.index, j);
      const needsBase = __s_indexOf(part, '%') >= 0;
      const px = __ptCalcPx(part, fontSize, needsBase ? __containingWidth(el) : null);
      out += __s_slice(v, i, m.index) + (px == null ? part : (Math.round(px * 64) / 64) + 'px');
      i = j;
    }
    return out;
  }

  /// Content width of the element's containing block.
  function __containingWidth(el) {
    const parent = el && el.__ptParent;
    if (!parent || parent.__ptType !== ELEMENT_NODE) return LAYOUT.W;
    const b = parent.__ptBoxV === __layoutBuilt ? parent.__ptBox : null;
    return b ? b.cw : LAYOUT.W;
  }

  function __boxOf(el) {
    if (!el || el.__ptType !== ELEMENT_NODE) return null;
    const doc = el.ownerDocument;
    if (doc && doc !== globalThis.document) {
      // A node of another document is laid out by its own realm; ask its
      // document for the layout stamp.
      try {
        const win = doc.defaultView;
        if (win && typeof win.__pt_relayout === 'function') win.__pt_relayout();
      } catch (e) {}
      return doc.__ptLayoutV != null && el.__ptBoxV === doc.__ptLayoutV ? el.__ptBox : null;
    }
    __relayout();
    return el.__ptBoxV === __layoutBuilt ? el.__ptBox : null; // detached/hidden → no box
  }

  /// Rect list: Chrome returns a `DOMRectList`, not an array, and pages read
  /// the name.
  function __ptRectList(items) {
    const list = __s_slice(items);
    list.item = function item(i) { return this[i] || null; };
    try { Object.defineProperty(list, Symbol.toStringTag, { value: 'DOMRectList', configurable: true }); } catch (e) {}
    return list;
  }

  // Rects and text metrics are named objects, not literals:
  // `Object.prototype.toString.call(el.getBoundingClientRect())` must be
  // `[object DOMRect]`. Prototype members taken from Chrome 151: 10 on
  // `DOMRectReadOnly`, 5 more on `DOMRect`, 11 on `TextMetrics`.
  const __rectVals = new WeakMap();
  class DOMRectReadOnly {
    constructor(x, y, w, h) {
      __rectVals.set(this, { x: +x || 0, y: +y || 0, w: +w || 0, h: +h || 0 });
    }
    get x() { return __rectVals.get(this).x; }
    get y() { return __rectVals.get(this).y; }
    get width() { return __rectVals.get(this).w; }
    get height() { return __rectVals.get(this).h; }
    get top() { const v = __rectVals.get(this); return Math.min(v.y, v.y + v.h); }
    get right() { const v = __rectVals.get(this); return Math.max(v.x, v.x + v.w); }
    get bottom() { const v = __rectVals.get(this); return Math.max(v.y, v.y + v.h); }
    get left() { const v = __rectVals.get(this); return Math.min(v.x, v.x + v.w); }
    toJSON() {
      return { x: this.x, y: this.y, width: this.width, height: this.height,
               top: this.top, right: this.right, bottom: this.bottom, left: this.left };
    }
  }
  class DOMRect extends DOMRectReadOnly {
    get x() { return __rectVals.get(this).x; }
    set x(v) { __rectVals.get(this).x = +v || 0; }
    get y() { return __rectVals.get(this).y; }
    set y(v) { __rectVals.get(this).y = +v || 0; }
    get width() { return __rectVals.get(this).w; }
    set width(v) { __rectVals.get(this).w = +v || 0; }
    get height() { return __rectVals.get(this).h; }
    set height(v) { __rectVals.get(this).h = +v || 0; }
  }
  for (const [C, n] of [[DOMRectReadOnly, 'DOMRectReadOnly'], [DOMRect, 'DOMRect']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }
  globalThis.__pt_makeRect = (x, y, w, h) => new DOMRect(x, y, w, h);

  // Point: Chrome's DOMPointReadOnly (x, y, z, w, matrixTransform, toJSON,
  // fromPoint) and DOMPoint on top with setters.
  const __ptVals = new WeakMap();
  const __ptNum = (v) => { const n = +v; return Number.isNaN(n) ? NaN : n; };
  class DOMPointReadOnly {
    constructor(x = 0, y = 0, z = 0, w = 1) {
      __ptVals.set(this, { x: __ptNum(x), y: __ptNum(y), z: __ptNum(z), w: __ptNum(w) });
    }
    get x() { return __ptVals.get(this).x; }
    get y() { return __ptVals.get(this).y; }
    get z() { return __ptVals.get(this).z; }
    get w() { return __ptVals.get(this).w; }
    matrixTransform(m) {
      const v = __ptVals.get(this);
      const M = (m && typeof m === 'object') ? m : {};
      const g = (k, d) => (M[k] === undefined ? d : +M[k]);
      const m11 = g('m11', g('a', 1)), m12 = g('m12', g('b', 0)), m13 = g('m13', 0), m14 = g('m14', 0);
      const m21 = g('m21', g('c', 0)), m22 = g('m22', g('d', 1)), m23 = g('m23', 0), m24 = g('m24', 0);
      const m31 = g('m31', 0), m32 = g('m32', 0), m33 = g('m33', 1), m34 = g('m34', 0);
      const m41 = g('m41', g('e', 0)), m42 = g('m42', g('f', 0)), m43 = g('m43', 0), m44 = g('m44', 1);
      return new DOMPoint(m11 * v.x + m21 * v.y + m31 * v.z + m41 * v.w,
                          m12 * v.x + m22 * v.y + m32 * v.z + m42 * v.w,
                          m13 * v.x + m23 * v.y + m33 * v.z + m43 * v.w,
                          m14 * v.x + m24 * v.y + m34 * v.z + m44 * v.w);
    }
    toJSON() { const v = __ptVals.get(this); return { x: v.x, y: v.y, z: v.z, w: v.w }; }
    static fromPoint(o) { const M = (o && typeof o === 'object') ? o : {}; return new this(M.x === undefined ? 0 : M.x, M.y === undefined ? 0 : M.y, M.z === undefined ? 0 : M.z, M.w === undefined ? 1 : M.w); }
  }
  class DOMPoint extends DOMPointReadOnly {
    get x() { return __ptVals.get(this).x; }
    set x(v) { __ptVals.get(this).x = __ptNum(v); }
    get y() { return __ptVals.get(this).y; }
    set y(v) { __ptVals.get(this).y = __ptNum(v); }
    get z() { return __ptVals.get(this).z; }
    set z(v) { __ptVals.get(this).z = __ptNum(v); }
    get w() { return __ptVals.get(this).w; }
    set w(v) { __ptVals.get(this).w = __ptNum(v); }
    static fromPoint(o) { return DOMPointReadOnly.fromPoint.call(DOMPoint, o); }
  }
  for (const [C, n] of [[DOMPointReadOnly, 'DOMPointReadOnly'], [DOMPoint, 'DOMPoint']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }

  // `TextMetrics`: values on the prototype, no own properties. Baselines come
  // from font metrics: hanging = 0.8 * ascent, ideographic = -descent.
  const __tmVals = new WeakMap();
  const TM_KEYS = ['width', 'actualBoundingBoxLeft', 'actualBoundingBoxRight',
                   'actualBoundingBoxAscent', 'actualBoundingBoxDescent',
                   'fontBoundingBoxAscent', 'fontBoundingBoxDescent',
                   'alphabeticBaseline', 'hangingBaseline', 'ideographicBaseline'];
  class TextMetrics {}
  for (const k of TM_KEYS) {
    Object.defineProperty(TextMetrics.prototype, k, {
      get() { return (__tmVals.get(this) || {})[k] || 0; },
      enumerable: false, configurable: true,
    });
  }
  try { Object.defineProperty(TextMetrics.prototype, Symbol.toStringTag, { value: 'TextMetrics', configurable: true }); } catch (e) {}
  globalThis.TextMetrics = globalThis.__pt_native ? __pt_native(TextMetrics) : TextMetrics;
  globalThis.__pt_makeMetrics = (v) => {
    const m = Object.create(TextMetrics.prototype);
    __tmVals.set(m, {
      width: v.width || 0,
      actualBoundingBoxLeft: v.left || 0, actualBoundingBoxRight: v.right || 0,
      actualBoundingBoxAscent: v.ascent || 0, actualBoundingBoxDescent: v.descent || 0,
      fontBoundingBoxAscent: v.fontAscent || 0, fontBoundingBoxDescent: v.fontDescent || 0,
      alphabeticBaseline: 0,
      // Chrome keeps the hanging baseline in float32 (10.399999618530273).
      hangingBaseline: Math.fround((v.fontAscent || 0) * 0.8),
      ideographicBaseline: -(v.fontDescent || 0),
    });
    return m;
  };

  // Gradient, pattern and selection are named objects too, with no own
  // marker property a browser object would not have.
  const __gradVals = new WeakMap();
  class CanvasGradient {
    addColorStop(pos, color) {
      const g = __gradVals.get(this);
      if (g) g.add(pos, color);
    }
  }
  const __patVals = new WeakMap();
  class CanvasPattern {
    setTransform(m) { const p = __patVals.get(this); if (p) p.transform = m || null; }
  }
  class Selection {
    getRangeAt() { throw __pt_mkErr(globalThis.DOMException || Error, "Failed to execute 'getRangeAt' on 'Selection': 0 is not a valid index.", 'IndexSizeError'); }
    removeAllRanges() {} addRange() {} removeRange() {} empty() {} collapse() {}
    collapseToStart() {} collapseToEnd() {} extend() {} modify() {}
    selectAllChildren() {} setBaseAndExtent() {} setPosition() {}
    deleteFromDocument() {} containsNode() { return false; }
    getComposedRanges() { return []; }
    toString() { return ''; }
  }
  for (const [k, v] of Object.entries({
    anchorNode: null, anchorOffset: 0, focusNode: null, focusOffset: 0,
    baseNode: null, baseOffset: 0, extentNode: null, extentOffset: 0,
    isCollapsed: true, rangeCount: 0, type: 'None', direction: 'none',
  })) Object.defineProperty(Selection.prototype, k, { get: () => v, configurable: true });
  for (const [C, n] of [[CanvasGradient, 'CanvasGradient'], [CanvasPattern, 'CanvasPattern'],
                        [Selection, 'Selection']]) {
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: n, configurable: true }); } catch (e) {}
    globalThis[n] = globalThis.__pt_native ? __pt_native(C) : C;
  }
  globalThis.__pt_makeGradient = (state) => {
    const g = Object.create(CanvasGradient.prototype);
    __gradVals.set(g, state);
    return g;
  };
  globalThis.__pt_makePattern = (state) => {
    const p = Object.create(CanvasPattern.prototype);
    __patVals.set(p, state || {});
    return p;
  };
  {
    const sel = Object.create(Selection.prototype);
    globalThis.getSelection = globalThis.__pt_native
      ? __pt_native(function getSelection() { return sel; })
      : function getSelection() { return sel; };
    // On the prototype: a document has exactly one own property, `location`.
    const D = globalThis.document && Object.getPrototypeOf(globalThis.document);
    if (D) {
      try {
        const docSel = globalThis.__pt_native ? __pt_native(function getSelection() { return this === globalThis.document ? sel : null; }) : function getSelection() { return this === globalThis.document ? sel : null; };
        Object.defineProperty(D, 'getSelection', {
          value: docSel, writable: true, enumerable: true, configurable: true,
        });
      } catch (e) {}
    }
  }

  // The window's scroll offset. Boxes are laid out in document coordinates; what
  // a page reads (rects, quads, hit tests) is relative to the window.
  const __scrollPos = [0, 0];
  function __scrollWindowTo(x, y) {
    const doc = globalThis.document, de = doc && doc.documentElement;
    const vw = globalThis.innerWidth || LAYOUT.W, vh = globalThis.innerHeight || LAYOUT.H;
    const maxX = Math.max(0, (de ? de.scrollWidth : 0) - vw), maxY = Math.max(0, (de ? de.scrollHeight : 0) - vh);
    const nx = Math.min(maxX, Math.max(0, Math.round(+x || 0))), ny = Math.min(maxY, Math.max(0, Math.round(+y || 0)));
    if (nx === __scrollPos[0] && ny === __scrollPos[1]) return;
    __scrollPos[0] = nx; __scrollPos[1] = ny;
    for (const [k, v] of [['scrollX', nx], ['pageXOffset', nx], ['scrollY', ny], ['pageYOffset', ny]]) {
      try { const d = Object.getOwnPropertyDescriptor(globalThis, k); if (d && 'value' in d) Object.defineProperty(globalThis, k, Object.assign({}, d, { value: v })); } catch (e) {}
    }
    // `scroll` fires on the document after the move and bubbles to the window.
    setTimeout(() => { try { doc.dispatchEvent(__ptTrust(new Event('scroll', { bubbles: true }))); } catch (e) {} }, 0);
  }
  globalThis.__pt_scrollWindowTo = __scrollWindowTo;
  // window.scrollTo / scroll / scrollBy, made like the shape stubs they replace
  // (a method without a prototype, native-looking, length 0) and kept on the
  // window with the same property attributes.
  const __scrollArgs = (a, base) => {
    if (a.length && a[0] && typeof a[0] === 'object') {
      const o = a[0];
      return [o.left !== undefined ? +o.left + base[0] : (base === __scrollZero ? __scrollPos[0] : base[0]),
              o.top !== undefined ? +o.top + base[1] : (base === __scrollZero ? __scrollPos[1] : base[1])];
    }
    return [(+a[0] || 0) + base[0], (+a[1] || 0) + base[1]];
  };
  const __scrollZero = [0, 0];
  for (const [name, rel] of [['scrollTo', false], ['scroll', false], ['scrollBy', true]]) {
    const f = ({ [name](...a) { const [x, y] = __scrollArgs(a, rel ? __s_slice(__scrollPos) : __scrollZero); __scrollWindowTo(x, y); } })[name];
    try {
      const d = Object.getOwnPropertyDescriptor(globalThis, name) || { writable: true, enumerable: true, configurable: true };
      Object.defineProperty(globalThis, name, { value: globalThis.__pt_native ? __pt_native(f) : f,
        writable: d.writable !== false, enumerable: d.enumerable !== false, configurable: d.configurable !== false });
    } catch (e) {}
  }
  function __rectFromBox(b) {
    return b ? new DOMRect(b.x - __scrollPos[0], b.y - __scrollPos[1], b.w, b.h) : new DOMRect(0, 0, 0, 0);
  }

  function __elementFromPoint(x, y) {
    __relayout();
    if (x == null || y == null || x < 0 || y < 0) return null;
    x += __scrollPos[0]; y += __scrollPos[1];
    // The deepest, latest element whose box covers the point.
    for (let i = __boxes.length - 1; i >= 0; i--) {
      const el = __boxes[i], b = el.__ptBox;
      if (!b || b.w <= 0 || b.h <= 0) continue;
      if (x >= b.x && x < b.x + b.w && y >= b.y && y < b.y + b.h) return el;
    }
    return null;
  }

  function __focusableAncestor(el) {
    for (let e = el; e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) {
      const t = e.tagName;
      if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || t === 'BUTTON') return e;
      if (t === 'A' && __ptHasA(e, 'href')) return e;
      if (__ptHasA(e, 'tabindex')) return e;
      if (e.isContentEditable) return e;
    }
    return null;
  }

  const __quad = (b) => {
    const x = b.x - __scrollPos[0], y = b.y - __scrollPos[1];
    return [x, y, x + b.w, y, x + b.w, y + b.h, x, y + b.h];
  };

  // Visible text of an element: skip hidden subtrees, gather text nodes, collapse
  // runs of whitespace. Not a full innerText (no per-block newlines) but enough
  // for reading rendered text.
  const __INNERTEXT_SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'TITLE']);
  function __innerText(el) {
    if (!el || el.__ptType !== ELEMENT_NODE) return '';
    // A non-rendered element returns its `textContent`, styles and scripts
    // included: in Chrome `d.style.display='none'; d.innerText` gives
    // ".z{color:red}text".
    if (__isHiddenEl(el)) return __descText(el);
    // `innerText` renders only visible content — the text inside <script>/<style>
    // etc. is not rendered, so it must not leak into it (`textContent` includes it).
    if (__INNERTEXT_SKIP.has(el.__ptTag)) return '';
    // Each element's text collapsed, then added to its parent's after a
    // space; frames of (element, text so far, next child index), no stack
    // frame per level.
    const st = [el, '', 0];
    for (;;) {
      const top = st.length - 3;
      const e = st[top], i = st[top + 2], kids = e.__ptKids;
      if (i < kids.length) {
        st[top + 2] = i + 1;
        const c = kids[i];
        if (c.__ptType === TEXT_NODE) st[top + 1] += c.__ptData;
        else if (c.__ptType === ELEMENT_NODE && !__isHiddenEl(c)) {
          if (__INNERTEXT_SKIP.has(c.__ptTag)) st[top + 1] += ' ';
          else st.push(c, '', 0);
        }
        continue;
      }
      const out = __s_trim(__s_replace(st[top + 1], /\s+/g, ' '));
      st.length = top;
      if (!st.length) return out;
      st[st.length - 2] += ' ' + out;
    }
  }

  // Called from the CDP layer (server.rs). Nodes are resolved there and passed in.
  globalThis.__pt_layoutMetrics = () => ({ w: LAYOUT.W, h: LAYOUT.H });
  globalThis.__pt_boxModel = (n) => {
    const b = __boxOf(n); if (!b) return null;
    const q = __quad(b);
    return { content: q, padding: q, border: q, margin: q, width: b.w, height: b.h };
  };
  globalThis.__pt_contentQuads = (n) => { const b = __boxOf(n); return b ? [__quad(b)] : []; };
  globalThis.__pt_focusNode = (n) => { if (n && n.focus) { n.focus(); return true; } return false; };

  // A mouse action at (x,y): resolve the topmost element there and fire the
  // matching pointer + mouse events, synthesizing `click` on release over the
  // same element that received the press (as a real browser does).
  // A point inside a frame belongs to the frame: the engine descends into its
  // context and re-hits in frame coordinates (the Turnstile widget is an
  // iframe in a closed shadow root).
  // First visible control of the document (checkbox, radio or button) with the
  // point to click, searching shadow trees too, where widgets keep their UI.
  // No captcha-specific knowledge here. `widgetOnly` searches only inside
  // shadow trees: the page's own form must never be submitted. In the
  // widget's frame the restriction is lifted.
  globalThis.__pt_findControl = (widgetOnly) => {
    __relayout();
    const seen = [];
    const scan = (root, shadowed) => {
      for (const n of (root.__ptKids || [])) {
        if (n.__ptType !== ELEMENT_NODE) continue;
        if (!__isHiddenEl(n)) {
          const role = (n.getAttribute && __ptGetA(n, 'role')) || '';
          const type = (n.getAttribute && __ptGetA(n, 'type')) || '';
          const control = (n.tagName === 'INPUT' && /^(checkbox|radio|submit|button)$/i.test(type))
            || n.tagName === 'BUTTON'
            || role === 'checkbox' || role === 'button' || role === 'switch';
          if (control && (shadowed || !widgetOnly)) {
            // The real widget checkbox is hidden (zero size, transparent
            // overlay); a human clicks the nearest wrapper with a real box.
            let r = n.getBoundingClientRect();
            if (!(r.width > 0 && r.height > 0)) {
              for (let a = n.__ptParent; a && a.__ptType === ELEMENT_NODE; a = a.__ptParent) {
                const ar = a.getBoundingClientRect();
                if (ar.width > 0 && ar.height > 0 && ar.width <= 400 && ar.height <= 200) { r = ar; break; }
              }
            }
            if (r.width > 0 && r.height > 0) {
              seen.push({ tag: n.tagName, type: type || role,
                          x: r.x + Math.min(r.width, 24) / 2,
                          y: r.y + Math.min(r.height, 24) / 2,
                          at: Math.round(r.y),
                          label: (n.getAttribute && __ptGetA(n, 'aria-label')) || '' });
            }
          }
          if (n.__ptShadow) scan(n.__ptShadow, true);
          scan(n, shadowed);
        }
      }
    };
    const de = globalThis.document && globalThis.document.documentElement;
    if (de) scan(de, false);
    return __ptJSON.stringify(__s_slice(seen, 0, 8));
  };

  // Solver debugging: every input and label (shadow trees included) with
  // its rect and visibility.
  globalThis.__pt_ctlDebug = () => {
    const out = [];
    const walk = (n, depth) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.__ptType !== ELEMENT_NODE) continue;
        const t = c.tagName;
        if (t === 'INPUT' || t === 'LABEL' || t === 'BUTTON' || (c.getAttribute && __ptGetA(c, 'role'))) {
          let r = null; try { r = c.getBoundingClientRect(); } catch (e) {}
          let cs = null; try { cs = getComputedStyle(c); } catch (e) {}
          out.push([t, (c.getAttribute && (__ptGetA(c, 'type') || __ptGetA(c, 'role'))) || '', depth,
            r ? [Math.round(r.x), Math.round(r.y), Math.round(r.width), Math.round(r.height)] : null,
            cs ? cs.display + '/' + cs.visibility + '/' + cs.opacity : '', c.isConnected]);
        }
        if (c.__ptShadow) walk(c.__ptShadow, depth + 1);
        walk(c, depth);
      }
    };
    if (globalThis.document) walk(globalThis.document, 0);
    return __ptJSON.stringify({ ctl: __s_slice(out, 0, 20), body: globalThis.document && document.body ? __s_slice(document.body.innerText || '', 0, 120) : '' });
  };

  // Rect of a frame element by its id, wherever it is, shadow trees included
  // (the widget frame lives in a closed shadow root).
  // Token of the widget (`cf-turnstile-response`) found by walking the tree
  // internally, not via the page's `querySelector`: the challenge records
  // which selectors were queried and reports them.
  globalThis.__pt_widgetToken = () => {
    let out = '';
    try {
      __walkTree(globalThis.document, (n) => {
        if (out || !n || n.__ptType !== ELEMENT_NODE) return;
        if ((n.__ptLocal === 'input' || n.__ptLocal === 'textarea') && /^(cf-turnstile-response|g-recaptcha-response)$/.test(__ptGetA(n, 'name') || '')) { const v = n.value; if (v) out = String(v); }
      });
    } catch (e) {}
    return out;
  };
  // What the page shows in front of the site, for the driver; walks the tree
  // internally so no page API call shows up in the challenge's report.
  globalThis.__pt_gateInfo = () => {
    const out = { title: '', url: '', inter: false, widget: false, recaptcha: false, token: false, datadome: false, orchestrator: false, awswaf: false };
    try {
      out.title = String((globalThis.document && document.title) || '');
      out.url = String((globalThis.location && location.href) || '');
      out.inter = /Just a moment/.test(out.title);
      __walkTree(globalThis.document, (n) => {
        if (!n || n.__ptType !== ELEMENT_NODE) return;
        const t = n.__ptLocal;
        if (t === 'iframe' && /challenges\.cloudflare\.com/.test(__ptGetA(n, 'src') || '')) out.widget = true;
        // A checkbox widget (Google's /sorry/ page among others); the invisible
        // kind asks nothing of a user.
        if (t === 'iframe' && /\/recaptcha\/(api2|enterprise)\/anchor/.test(__ptGetA(n, 'src') || '') && !/size=invisible/.test(__ptGetA(n, 'src') || '')) out.recaptcha = true;
        if (t === 'script') {
          const src = __ptGetA(n, 'src') || '';
          if (/\/cdn-cgi\/challenge-platform\//.test(src)) out.orchestrator = true;
          if (/captcha-delivery\.com|datadome/.test(src)) out.datadome = true;
        }
        if ((t === 'input' || t === 'textarea') && /^(cf-turnstile-response|g-recaptcha-response)$/.test(__ptGetA(n, 'name') || '') && n.value) out.token = true;
      });
      if (!out.inter && out.orchestrator && typeof globalThis._cf_chl_opt === 'object') out.inter = true;
      // AWS WAF's challenge page: its config object and the container it
      // renders into. A real page that only loads the integration has neither.
      if (globalThis.gokuProps && typeof globalThis.gokuProps === 'object' && document.getElementById('challenge-container')) out.awswaf = true;
    } catch (e) {}
    return __ptJSON.stringify(out);
  };
  // The node id of the <iframe> a frame lives in (0 if not in this document).
  globalThis.__pt_frameOwner = (id) => {
    const walk = (n) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.__ptType !== ELEMENT_NODE) continue;
        if (c.__ptLocal === 'iframe' && c.__ptFrameId === id) return c;
        const found = (c.__ptShadow && walk(c.__ptShadow)) || walk(c);
        if (found) return found;
      }
      return null;
    };
    const el = globalThis.document && walk(globalThis.document);
    return el ? globalThis.__pt_nodeId(el) : 0;
  };
  globalThis.__pt_frameRectById = (id) => {
    const walk = (n) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.__ptType !== ELEMENT_NODE) continue;
        if (c.__ptLocal === 'iframe' && c.__ptFrameId === id) return c;
        const inShadow = c.__ptShadow ? walk(c.__ptShadow) : null;
        if (inShadow) return inShadow;
        const deeper = walk(c);
        if (deeper) return deeper;
      }
      return null;
    };
    const el = globalThis.document && walk(globalThis.document);
    if (!el) return '';
    const r = el.getBoundingClientRect();
    return __ptJSON.stringify({ x: r.x, y: r.y, w: r.width, h: r.height });
  };

  globalThis.__pt_hitFrame = (x, y) => {
    for (let el = __elementFromPoint(x, y); el && el.__ptType === ELEMENT_NODE; el = el.__ptParent) {
      if (el.__ptLocal === 'iframe' && el.__ptFrameId) {
        const r = el.getBoundingClientRect();
        // One to one, as in a real window: a frame does not scale its content,
        // it clips it. A point in the frame box is the same point in frame
        // coordinates.
        return __ptJSON.stringify({ frame: el.__ptFrameId, x: x - r.x, y: y - r.y });
      }
    }
    return '';
  };


  /// The control a label activates: the one named by `for`, or the first
  /// control inside the label; null if none.
  function __labelFor(el) {
    for (let e = el; e && e.__ptType === ELEMENT_NODE; e = e.__ptParent) {
      if (e.tagName !== 'LABEL') continue;
      const id = e.getAttribute && __ptGetA(e, 'for');
      if (id) {
        const root = e.getRootNode ? e.getRootNode() : (globalThis.document || null);
        const found = root && root.getElementById ? root.getElementById(id)
                    : (globalThis.document && globalThis.document.getElementById(id));
        if (found) return found;
      }
      const inner = e.querySelector && e.querySelector('input, select, textarea, button');
      if (inner) return inner;
    }
    return null;
  }

  // Engine mouse input as a page sees it in Chrome (checked against a real
  // click recorded in the widget frame): pointer events have fractional
  // coordinates, mouse events integer ones; screen coordinates include the
  // window and frame position; movement deltas; on move button -1 (mouse
  // event 0) and which 0; on press which 1; click is a PointerEvent; mouse
  // events have sourceCapabilities, pointer events null. `ox`/`oy` are the
  // frame origin on screen (passed by the core; default: own window origin).
  let __lastSX = null, __lastSY = null, __idc = null, __winFocused = false;
  const __devCaps = () => {
    if (__idc) return __idc;
    try { __idc = new InputDeviceCapabilities({ firesTouchEvents: false }); if (globalThis.__pt_idcSet) __pt_idcSet(__idc, false); } catch (e) { __idc = null; }
    return __idc;
  };
  const __q = (v) => Math.round(v * 256) / 256;
  globalThis.__pt_screenOrigin = () => {
    const w = globalThis;
    const ox = (w.screenX || 0) + Math.max(0, ((w.outerWidth || 0) - (w.innerWidth || 0)) / 2);
    const oy = (w.screenY || 0) + Math.max(0, (w.outerHeight || 0) - (w.innerHeight || 0));
    return __ptJSON.stringify([ox, oy]);
  };
  // A press aimed at a known element goes to it: our layout can put another element
  // under its centre (a widget's footer buttons can land below the frame's window).
  let __pressTarget = null;
  globalThis.__pt_setPressTarget = (sel) => {
    __pressTarget = sel ? (globalThis.document && globalThis.document.querySelector(sel)) || null : null;
    return !!__pressTarget;
  };
  globalThis.__pt_mouse = (type, x, y, button, clickCount, ox, oy) => {
    x = __q(+x || 0); y = __q(+y || 0);
    const el = __pressTarget || __elementFromPoint(x, y) || (globalThis.document && globalThis.document.body);
    if (!el) return false;
    if (ox === undefined || oy === undefined) {
      try { const o = __ptJSON.parse(globalThis.__pt_screenOrigin()); ox = o[0]; oy = o[1]; } catch (e) { ox = 0; oy = 0; }
    }
    const sx = __q(x + ox), sy = __q(y + oy);
    const mx = __lastSX === null ? 0 : Math.round(sx - __lastSX), my = __lastSY === null ? 0 : Math.round(sy - __lastSY);
    let r = null; try { r = el.getBoundingClientRect(); } catch (e) {}
    const rl = r ? r.left : 0, rt = r ? r.top : 0;
    const scX = globalThis.scrollX || 0, scY = globalThis.scrollY || 0;
    const b = button === 'right' ? 2 : button === 'middle' ? 1 : (button | 0);
    const down = type === 'mousePressed', up = type === 'mouseReleased', move = type === 'mouseMoved';
    const clicks = clickCount || 1;
    // Fields not in the constructor dictionary are set after creation.
    const finish = (ev, mouse, extra) => {
      const cx = mouse ? Math.trunc(x) : x, cy = mouse ? Math.trunc(y) : y;
      const E = ev.__ptE;
      if (E) Object.assign(E, {
        clientX: cx, clientY: cy, x: cx, y: cy,
        screenX: mouse ? Math.trunc(sx) : sx, screenY: mouse ? Math.trunc(sy) : sy,
        pageX: mouse ? Math.trunc(x + scX) : x + scX, pageY: mouse ? Math.trunc(y + scY) : y + scY,
        offsetX: mouse ? Math.round(x - rl) : x - rl, offsetY: mouse ? Math.round(y - rt) : y - rt,
        layerX: Math.trunc(x + scX), layerY: Math.trunc(y + scY),
        movementX: move ? mx : 0, movementY: move ? my : 0,
        sourceCapabilities: mouse ? __devCaps() : null,
      }, extra || {});
      return __ptTrust(ev);
    };
    const base = { bubbles: true, cancelable: true, composed: true, view: globalThis, clientX: x, clientY: y, screenX: sx, screenY: sy };
    const ptrInit = (extra) => Object.assign({}, base, { pointerId: 1, pointerType: 'mouse', isPrimary: true, width: 1, height: 1 }, extra || {});
    const P = (t, extra, fields) => { const ev = new PointerEvent(t, ptrInit(extra)); finish(ev, false, fields); return ev; };
    const M = (t, init, fields) => { const ev = new MouseEvent(t, Object.assign({}, base, init)); finish(ev, true, fields); return ev; };
    const send = (target, ev) => target.dispatchEvent(ev);
    const hoverTo = (next) => {
      const prev = __hoverEl;
      if (prev === next) return;
      const nb = () => { const o = { ...base }; o.bubbles = false; o.cancelable = false; return o; };
      if (prev && prev.isConnected !== false) {
        send(prev, P('pointerout', { button: -1, relatedTarget: next }, { button: -1, which: 0, detail: 0 }));
        send(prev, P('pointerleave', { button: -1, bubbles: false, cancelable: false, relatedTarget: next }, { button: -1, which: 0, detail: 0 }));
        send(prev, M('mouseout', { relatedTarget: next }, { which: 0, detail: 0 }));
        send(prev, M('mouseleave', { ...nb(), relatedTarget: next }, { which: 0, detail: 0 }));
      }
      __hoverEl = next;
      send(next, P('pointerover', { button: -1, relatedTarget: prev || null }, { button: -1, which: 0, detail: 0 }));
      send(next, P('pointerenter', { button: -1, bubbles: false, cancelable: false, relatedTarget: prev || null }, { button: -1, which: 0, detail: 0 }));
      send(next, M('mouseover', { relatedTarget: prev || null }, { which: 0, detail: 0 }));
      send(next, M('mouseenter', { ...nb(), relatedTarget: prev || null }, { which: 0, detail: 0 }));
    };
    const held = __mouseDownEl ? 1 : 0;
    if (down) {
      hoverTo(el);
      send(el, P('pointerdown', { button: b, buttons: 1, pressure: 0.5 }, { which: b + 1, detail: 0 }));
      send(el, M('mousedown', { button: b, buttons: 1, detail: clicks }, { which: b + 1 }));
      // A window that receives its first press gets focus before the element.
      if (!__winFocused) {
        __winFocused = true;
        try { const wf = new FocusEvent('focus', { bubbles: false, cancelable: false, composed: false }); globalThis.dispatchEvent(__ptTrust(wf)); } catch (e) {}
      }
      const f = __focusableAncestor(el);
      try { Object.defineProperty(globalThis, '__ptFocusCaps', { value: __devCaps(), writable: true, configurable: true }); } catch (e) {}
      try {
        if (f) f.focus(); else if (globalThis.document) { const a = globalThis.document.activeElement; if (a && a.blur) a.blur(); }
      } finally { try { globalThis.__ptFocusCaps = null; } catch (e) {} }
      __mouseDownEl = el;
    } else if (up) {
      send(el, P('pointerup', { button: b, buttons: 0, pressure: 0 }, { which: b + 1, detail: 0 }));
      send(el, M('mouseup', { button: b, buttons: 0, detail: clicks }, { which: b + 1 }));
      if (__mouseDownEl === el) {
        const isBox = (n) => n && n.tagName === 'INPUT' && /^(checkbox|radio)$/i.test(__ptGetA(n, 'type') || '');
        // A checkbox toggles before click (its handler reads the new state),
        // input/change fire after click; preventDefault on click reverts it.
        const clickOn = (target) => {
          const box = isBox(target) ? target : null;
          const was = box ? box.checked : null;
          if (box) box.checked = __s_toLowerCase(String(__ptGetA(box, 'type'))) === 'radio' ? true : !box.checked;
          // Chrome's click is a PointerEvent with integer mouse coordinates
          // and isPrimary false.
          const ev = new PointerEvent('click', ptrInit({ button: b, buttons: 0, pressure: 0, detail: clicks, isPrimary: false }));
          finish(ev, true, { which: b + 1, detail: clicks, isPrimary: false });
          const ok = send(target, ev);
          if (ok && !box) __ptActivate(target);
          if (box) {
            if (!ok) box.checked = was;
            else if (box.checked !== was) {
              box.dispatchEvent(__ptTrust(new Event('input', { bubbles: true, composed: true })));
              box.dispatchEvent(__ptTrust(new Event('change', { bubbles: true })));
            }
          }
        };
        clickOn(el);
        // A click on a label is a click on its control: the widget hides its
        // checkbox at zero size under a visible wrapper inside `<label>`.
        const lbl = __labelFor(el);
        if (lbl && lbl !== el) {
          clickOn(lbl);
          if (lbl.focus) lbl.focus();
        }
      }
      __mouseDownEl = null;
    } else if (move) {
      hoverTo(el);
      send(el, P('pointermove', { button: -1, buttons: held, pressure: held ? 0.5 : 0 }, { button: -1, which: 0, detail: 0 }));
      send(el, M('mousemove', { button: 0, buttons: held }, { which: 0, detail: 0 }));
    }
    __lastSX = sx; __lastSY = sy;
    return true;
  };

  const __editable = (el) => el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
  function __insertInto(el, text) {
    if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
      el.value = (el.value || '') + text;
    } else if (el.isContentEditable) {
      el.textContent = (el.textContent || '') + text;
    } else return false;
    el.dispatchEvent(__ptTrust(new InputEvent('input', { bubbles: true, data: text, inputType: 'insertText' })));
    return true;
  }
  // The parent document's side of focus moving into this frame: its focused
  // element blurs and the <iframe> becomes active, up through every ancestor.
  function __ptFocusHost() {
    let fe = null;
    try { fe = globalThis.frameElement; } catch (e) {}
    const pdoc = fe && fe.ownerDocument;
    if (!pdoc || pdoc.__ptActive === fe) return;
    const pprev = pdoc.__ptActive;
    if (pprev && pprev !== pdoc.body && pprev.dispatchEvent) {
      pprev.dispatchEvent(__ptFocusEvent('blur', null));
      pprev.dispatchEvent(__ptFocusEvent('focusout', null, true));
    }
    pdoc.__ptActive = fe;
    try { const up = pdoc.defaultView && pdoc.defaultView.__pt_focusHost; if (typeof up === 'function') up(); } catch (e) {}
  }
  globalThis.__pt_focusHost = __ptFocusHost;
  // When this document last took focus (0: nothing focused). The engine sends
  // keyboard input to the page or frame that did so last.
  globalThis.__pt_focusAt = () => {
    const d = globalThis.document, a = d && d.__ptActive;
    return a && a !== d.body ? (d.__ptFocusAt || 0) : 0;
  };
  globalThis.__pt_insertText = (text) => {
    const el = globalThis.document && globalThis.document.activeElement;
    return __editable(el) ? __insertInto(el, String(text)) : false;
  };

  // A key action on the focused element. Fires keydown/keyup (+ keypress for a
  // printable key), and mirrors real editing side effects: printable `text`
  // is inserted, Backspace deletes the last char, both raising `input`.
  globalThis.__pt_key = (type, init) => {
    init = init || {};
    const doc = globalThis.document;
    const el = (doc && doc.activeElement) || (doc && doc.body);
    if (!el) return false;
    const name = { keyDown: 'keydown', rawKeyDown: 'keydown', keyUp: 'keyup', char: 'keypress' }[type] || type;
    const ev = { bubbles: true, cancelable: true, key: init.key || '', code: init.code || '', keyCode: init.keyCode || 0 };
    el.dispatchEvent(__ptTrust(new KeyboardEvent(name, ev)));
    if (name === 'keydown') {
      if (init.text) { if (__editable(el)) __insertInto(el, init.text); }
      else if (init.key === 'Backspace' && __editable(el)) {
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.value = __s_slice(String(el.value || ''), 0, -1);
        else el.textContent = __s_slice(String(el.textContent || ''), 0, -1);
        el.dispatchEvent(__ptTrust(new InputEvent('input', { bubbles: true, inputType: 'deleteContentBackward' })));
      }
    }
    return true;
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
