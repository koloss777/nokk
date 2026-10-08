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
  const __sm = (f, m) => {
    const call = Function.prototype.call.bind(f);
    return function (s, a, b) {
      const n = arguments.length;
      if (typeof s === 'string') return n === 1 ? call(s) : n === 2 ? call(s, a) : call(s, a, b);
      return n === 1 ? s[m]() : n === 2 ? s[m](a) : s[m](a, b);
    };
  };
  const __s_slice = __sm(String.prototype.slice, 'slice'),
    __s_toLowerCase = __sm(String.prototype.toLowerCase, 'toLowerCase'),
    __s_replace = __sm(String.prototype.replace, 'replace'),
    __s_trim = __sm(String.prototype.trim, 'trim'),
    __s_indexOf = __sm(String.prototype.indexOf, 'indexOf'),
    __s_split = __sm(String.prototype.split, 'split'),
    __s_charCodeAt = __sm(String.prototype.charCodeAt, 'charCodeAt'),
    __s_endsWith = __sm(String.prototype.endsWith, 'endsWith'),
    __s_toUpperCase = __sm(String.prototype.toUpperCase, 'toUpperCase'),
    __s_lastIndexOf = __sm(String.prototype.lastIndexOf, 'lastIndexOf'),
    __s_match = __sm(String.prototype.match, 'match'),
    __s_includes = __sm(String.prototype.includes, 'includes'),
    __s_charAt = __sm(String.prototype.charAt, 'charAt'),
    __s_startsWith = __sm(String.prototype.startsWith, 'startsWith'),
    __s_normalize = __sm(String.prototype.normalize, 'normalize'),
    __s_search = __sm(String.prototype.search, 'search'),
    __s_padStart = __sm(String.prototype.padStart, 'padStart');
  // JSON captured before any page code runs. The engine serializes its own
  // queues; using the page's `JSON.stringify` would let a page that wraps it
  // see the emulator's internals.
  const __ptJSON = globalThis.__ptJSON || { stringify: JSON.stringify, parse: JSON.parse };
  const ELEMENT_NODE = 1, TEXT_NODE = 3, COMMENT_NODE = 8,
        DOCUMENT_NODE = 9, DOCUMENT_FRAGMENT_NODE = 11;

  const __pt_soon = (f) => { try { queueMicrotask(f); } catch (e) { setTimeout(f, 0); } };
  // An engine task (load on readiness, CSP violation, script error) is not a
  // page timer: it must not consume a setTimeout id.
  const __ptLater = (f, d) => (typeof globalThis.__pt_addTask === 'function' ? __pt_addTask(f, d || 0) : setTimeout(f, d || 0));
  const VOID = new Set(['area','base','br','col','embed','hr','img','input',
    'link','meta','param','source','track','wbr']);

  // Every node in a subtree, shadow trees included. Frames and scripts come to
  // life as part of whatever tree they are inserted with — a widget hands the DOM
  // a finished tree, not a bare element.
  function __attrName(el, n) {
    const s = String(n);
    return el.__ptNS === undefined || el.__ptNS === 'http://www.w3.org/1999/xhtml' ? __s_toLowerCase(s) : s;
  }
  function __walkTree(node, fn) {
    if (!node) return;
    fn(node);
    const kids = node.__ptKids;
    if (kids) for (const c of __s_slice(kids)) __walkTree(c, fn);
    if (node.__ptShadow) __walkTree(node.__ptShadow, fn);
  }

  // What connecting a subtree means for the elements that *do* something: a frame
  // opens a browsing context, a script runs. Both were inert before — a page that
  // builds `<script src=…>` and appends it (which is how every tag loader, widget
  // bootstrap and anti-bot orchestrator works, Cloudflare's interstitial included)
  // got a DOM node and nothing else: no fetch, no execution, no `onload`.
  const __connectSubtree = (node) => __walkTree(node, (n) => {
    if (n.__ptLocal === 'iframe') n.__ptConnectFrame();
    else if (n.__ptLocal === 'script') n.__ptRunScript();
    // Stylesheets and preloads start loading on insertion, not on `href`
    // assignment: the order can be either.
    else if (n.__ptLocal === 'link' && n.__ptLoadLink) n.__ptLoadLink();
    else if (n.__ptLocal === 'img' && n.__ptLoadImage) n.__ptLoadImage();
    if (n.nodeType === ELEMENT_NODE && __customs.has(n.__ptLocal)) {
      if (!n.__ptUpgraded) __customUpgrade(n, __customs.get(n.__ptLocal));
      else __customCallback(n, 'connectedCallback');
    }
  });

  // An array wrapped as HTMLCollection: length/item/namedItem/iterator, not an
  // Array (`Array.isArray` is false on a real collection).
  function __collection(arr) {
    const list = Object.create(__link('HTMLCollection', __collectionProto));
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
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
    const kids = node.__ptKids, prev = list.__ptLen | 0;
    for (let i = 0; i < kids.length; i++) list[i] = kids[i];
    for (let i = kids.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptLen', { value: kids.length, enumerable: false, configurable: true });
    return list;
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
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    forEach(fn, thisArg) { for (let i = 0; i < this.length; i++) fn.call(thisArg, this[i], i, this); },
    *entries() { for (let i = 0; i < this.length; i++) yield [i, this[i]]; },
    *keys() { for (let i = 0; i < this.length; i++) yield i; },
    *values() { for (let i = 0; i < this.length; i++) yield this[i]; },
    [Symbol.iterator]() { return this.values(); },
  };

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
    get localName() { return this.__ptName; },
    get name() { return this.__ptName; },
    get nodeName() { return this.__ptName; },
    get value() { return this.__ptValue; },
    get nodeValue() { return this.__ptValue; },
    get textContent() { return this.__ptValue; },
    get namespaceURI() { return null; },
    get prefix() { return null; },
    get specified() { return true; },
    get ownerElement() { return this.__ptOwner; },
  };
  function __attr(el, name, value) {
    const a = Object.create(__link('Attr', __attrProto));
    Object.defineProperty(a, '__ptName', { value: name });
    Object.defineProperty(a, '__ptValue', { value: value });
    Object.defineProperty(a, '__ptOwner', { value: el });
    return a;
  }
  const __namedNodeMapProto = {
    get [Symbol.toStringTag]() { return 'NamedNodeMap'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    getNamedItem(n) { const k = __s_toLowerCase(String(n));
      for (let i = 0; i < this.length; i++) if (this[i].name === k) return this[i];
      return null; },
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
  function __namedNodeMap(el) {
    const map = Object.create(__link('NamedNodeMap', __namedNodeMapProto));
    let i = 0;
    for (const [name, value] of el.__ptAttrs) map[i++] = __attr(el, name, value);
    Object.defineProperty(map, '__ptLen', { value: i, enumerable: false, configurable: true });
    Object.defineProperty(map, '__ptOwner', { value: el });
    return map;
  }

  // `classList` is a live DOMTokenList that writes back to the attribute; an
  // interface, not a literal with methods.
  const __tokenListProto = {
    get [Symbol.toStringTag]() { return 'DOMTokenList'; },
    get value() { return __ptGetA(this.__ptEl, 'class') || ''; },
    set value(v) { __ptSetA(this.__ptEl, 'class', String(v)); },
    get length() { return this.__ptTokens().length; },
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
    forEach(fn, thisArg) { this.__ptTokens().forEach((v, i) => fn.call(thisArg, v, i, this)); },
    *entries() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield [i, t[i]]; },
    *keys() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield i; },
    *values() { yield* this.__ptTokens(); },
    [Symbol.iterator]() { return this.values(); },
    toString() { return this.value; },
  };
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
    const t = list.__ptTokens(), prev = list.__ptCount | 0;
    for (let i = 0; i < t.length; i++) list[i] = t[i];
    for (let i = t.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptCount', { value: t.length, configurable: true });
    return list;
  }

  // ---- Node -----------------------------------------------------------------
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
      const p = this.parentNode; if (!p) return null;
      const i = __s_indexOf(p.__ptKids, this); return p.__ptKids[i + 1] || null;
    }
    get previousSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = __s_indexOf(p.__ptKids, this); return p.__ptKids[i - 1] || null;
    }
    hasChildNodes() { return this.__ptKids.length > 0; }
    contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }
    // Walks out through a shadow host too: a node inside an attached shadow tree
    // is connected, even though the root itself has no parent.
    // The base URL is the document's; for `about:blank` it is the creator's.
    get baseURI() {
      const d = this.nodeType === 9 ? this : (this.ownerDocument || null);
      if (d && typeof d.__ptBaseURI === 'function') return d.__ptBaseURI();
      const href = (globalThis.location && globalThis.location.href) || 'about:blank';
      return href === 'about:blank' && typeof globalThis.__pt_inheritedBase === 'string' ? globalThis.__pt_inheritedBase : href;
    }
    get isConnected() {
      for (let n = this; n; n = n.parentNode || n.__ptHost) {
        if (n.nodeType === DOCUMENT_NODE) return true;
      }
      return false;
    }
    getRootNode(opts) {
      let n = this;
      while (n.parentNode || (n.__ptHost && opts && opts.composed)) n = n.parentNode || n.__ptHost;
      return n;
    }

    appendChild(child) {
      __needArgs(arguments.length, 1, 'appendChild', 'Node');
      __needNode(child, 1, 'appendChild');
      // A node cannot contain itself or its ancestor.
      for (let p = this; p; p = p.parentNode) {
        if (p === child) {
          throw __pt_mkErr(globalThis.DOMException || Error, 
            "Failed to execute 'appendChild' on 'Node': The new child element contains the parent.",
            'HierarchyRequestError');
        }
      }
      return __ptInsert.call(this, child, null);
    }
    insertBefore(child, ref) {
      __needArgs(arguments.length, 2, 'insertBefore', 'Node');
      __needNode(child, 1, 'insertBefore');
      // The second parameter is `Node?`: `undefined` is the same as `null`,
      // meaning "append".
      if (ref !== null && ref !== undefined) {
        __needNode(ref, 2, 'insertBefore');
        __needChild(this, ref, 'insertBefore',
          'The node before which the new node is to be inserted is not a child of this node.');
      }
      if (child.nodeType === DOCUMENT_FRAGMENT_NODE) {
        for (const c of __s_slice(child.__ptKids)) this.insertBefore(c, ref);
        return child;
      }
      if (child.parentNode) __ptDrop.call(child.parentNode, child);
      // A node from another document is adopted: it and its subtree get the
      // new parent's ownerDocument, as in Chrome.
      try {
        const doc = this.nodeType === 9 ? this : this.__ptDoc;
        if (doc && child.__ptDoc !== doc) __walkTree(child, (n) => { if (n.__ptDoc !== doc) n.__ptDoc = doc; });
      } catch (e) {}
      const i = (ref === null || ref === undefined) ? -1 : __s_indexOf(this.__ptKids, ref);
      if (i < 0) this.__ptKids.push(child); else this.__ptKids.splice(i, 0, child);
      child.__ptParent = this;
      __markDirty();
      __styleTouch(this);
      __mutation(__childListRecord(this, [child], [], child.previousSibling, child.nextSibling));
      // A frame only becomes a browsing context once it is in the document — and
      // the frame is rarely the node being inserted. A widget builds its tree
      // detached and inserts the root of it: Turnstile puts its iframe in a closed
      // shadow root and then connects the host, so checking only `child` left the
      // iframe sitting there, connected and inert, and the widget waiting forever
      // for a frame that never opened.
      if (child.isConnected) __connectSubtree(child);
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
      this.__ptKids.splice(i, 1); child.__ptParent = null; __markDirty(); __styleTouch(this);
      __mutation(__childListRecord(this, [], [child], prev, next));
      // A removed frame is a closed browsing context. Without this its V8 context
      // outlives the element forever — a widget that replaces its iframe on a
      // retry (Turnstile does, repeatedly) would pile them up until the cap. The
      // whole subtree goes, for the same reason it connects as a whole.
      __walkTree(child, (f) => {
        if (f.__ptFrameId) __ptDisconnectFrame(f);
        // A sandboxed frame: the page keeps its window, but the context is
        // closed (zero sizes, `closed`, no `frameElement`).
        if (f.__ptRealm) { try { if (typeof f.__ptRealm.__pt_detach === 'function') f.__ptRealm.__pt_detach(); } catch (e) {} try { __realmFrames.delete(f); } catch (e) {} }
        if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
      });
      return child;
    }
    replaceChild(nw, old) {
      __needArgs(arguments.length, 2, 'replaceChild', 'Node');
      __needNode(nw, 1, 'replaceChild');
      __needNode(old, 2, 'replaceChild');
      __needChild(this, old, 'replaceChild',
        'The node to be replaced is not a child of this node.');
      // Replacing a node with itself leaves it in place (Turnstile probes the
      // root this way); insert-then-remove would drop it.
      if (nw === old) return old;
      this.insertBefore(nw, old);
      return this.removeChild(old);
    }
    cloneNode(deep) {
      const c = this.__ptShallowClone();
      // A clone carries the exact inline style numbers, not the six-digit
      // printed ones: Chrome clones the parsed declaration, so
      // `scale(1.000998)` stays 1.000998 though the attribute says 1.001.
      try {
        if (this.__ptStyle && c.style) {
          const sr = __declRaw.get(this.__ptStyle), sm = sr && sr();
          if (sm && sm.__ptPrecise && sm.__ptPrecise.size) {
            const dr = __declRaw.get(c.style), dm = dr && dr();
            if (dm) { const pm = __cssPrecise(dm); for (const [k, v] of sm.__ptPrecise) if (dm.has(k)) pm.set(k, v); }
          }
        }
      } catch (e) {}
      if (deep) for (const ch of this.__ptKids) c.appendChild(ch.cloneNode(true));
      if (deep && this.__ptLocal === 'template' && this.__ptContent) {
        const into = __templateContent(c);
        for (const ch of this.__ptContent.__ptKids) into.appendChild(ch.cloneNode(true));
      }
      return c;
    }

    get textContent() {
      // A document and doctype have none: null, not the page's joined text.
      if (this.nodeType === 9 || this.nodeType === 10) return null;
      // Text, comment, processing instruction: their data (Chrome's Node.textContent).
      if (this.nodeType === 3 || this.nodeType === 4 || this.nodeType === 7) return this.data;
      if (this.nodeType === 8) return this.data;
      let s = ''; for (const c of this.__ptKids) s += c.textContent; return s;
    }
    set textContent(v) {
      if (this.nodeType === 9 || this.nodeType === 10) return;
      if (this.nodeType === 3 || this.nodeType === 4 || this.nodeType === 7 || this.nodeType === 8) { this.data = String(v); return; }
      if (this.__ptLocal === 'script') v = __pt_ttSink('TrustedScript', 'HTMLScriptElement textContent', v, "Failed to set the 'textContent' property on 'HTMLScriptElement'");
      __ptDropKids(this);
      if (v !== '') __ptAdd.call(this, new Text(String(v)));
    }

    // EventTarget
    addEventListener(type, fn, opts) {
      __needArgs(arguments.length, 2, 'addEventListener', 'EventTarget');
      if (!fn) return;
      const cap = !!(opts && (opts === true || opts.capture));
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
      (this.__ptLis[type] || (this.__ptLis[type] = [])).push({ fn, cap });
    }
    removeEventListener(type, fn, opts) {
      const cap = !!(opts && (opts === true || opts.capture));
      const l = this.__ptLis[type]; if (!l) return;
      this.__ptLis[type] = l.filter(e => !(e.fn === fn && e.cap === cap));
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
        if (n.nodeType === 11 && n.host) {
          if (!event.composed) break;
          n = n.host; tgt = n; continue;
        }
        if (n.nodeType === 9) {
          const w = n.defaultView;
          if (w && event.type !== 'load') { path.push(w); targets.push(tgt); }
          break;
        }
        n = n.parentNode;
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
            __ptEvSet(event, 'currentTarget', node);
            try { e.fn.call(node, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
          }
        }
        // An ancestor's handler property (`document.onmousemove`,
        // `window.onclick`) is a bubbling listener too.
        if (phase === 3 && !event.__ptStopImm) {
          let on; try { on = node['on' + event.type]; } catch (x) {}
          if (typeof on === 'function') {
            __ptEvSet(event, 'currentTarget', node);
            try { on.call(node, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
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
          try { on.call(this, event); } catch (e) { __pt_reportError(e, 'listener ' + event.type); }
        }
      };
      // At the target, capture listeners first, then the rest (Chrome >= 89).
      const atTarget = (capture) => {
        const l = this.__ptLis && this.__ptLis[event.type]; if (!l) return;
        for (const e of __s_slice(l)) {
          if (event.__ptStopImm) break;
          if (!!e.cap !== capture) continue;
          __ptEvSet(event, 'currentTarget', this);
          try { e.fn.call(this, event); } catch (x) { __pt_reportError(x, 'listener ' + event.type); }
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
  globalThis.__pt_reportError = (e, where) => {
    const msg = 'Uncaught ' + String((e && e.name ? e.name + ': ' + e.message : e));
    try {
      const on = globalThis.onerror;
      if (typeof on === 'function') {
        on.call(globalThis, msg, (e && e.fileName) || (globalThis.location && location.href) || '',
                (e && e.lineNumber) || 0, (e && e.columnNumber) || 0, e);
      }
    } catch (x) {}
    try {
      if (globalThis.ErrorEvent && globalThis.dispatchEvent) {
        const ev = new ErrorEvent('error', { message: msg, error: e });
        globalThis.dispatchEvent(ev);
      }
    } catch (x) {}
    try { console.error(msg + (where ? ' (' + where + ')' : ''), (e && e.stack) || ''); } catch (x) {}
  };

  function fireCapture(node, event) {
    const l = node.__ptLis && node.__ptLis[event.type]; if (!l) return;
    for (const e of __s_slice(l)) { if (!e.cap) continue; if (event.__ptStopImm) break; __ptEvSet(event, 'currentTarget', node); try { e.fn.call(node, event); } catch (x) { __pt_reportError(x, 'capture ' + event.type); } }
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
          const cap = !!(opts && (opts === true || opts.capture));
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
          const l = store(t); (l[type] = l[type] || []).push({ fn, cap, once: !!(opts && opts.once) });
        }],
        ['removeEventListener', function removeEventListener(type, fn, opts) {
          __needArgs(arguments.length, 2, 'removeEventListener', 'EventTarget');
          const t = self_(this);
          const cap = !!(opts && (opts === true || opts.capture));
          const l = t.__ptLis && t.__ptLis[type]; if (!l) return;
          t.__ptLis[type] = l.filter((e) => !(e.fn === fn && e.cap === cap));
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

  const __removeSelf = function remove() { if (this.parentNode) this.parentNode.removeChild(this); };

  Object.defineProperties(Node.prototype, {
    nodeType: accessor('nodeType', function () { return this.__ptType; }, function (v) { this.__ptType = v; }),
    childNodes: accessor('childNodes',
      function () { return __nodeList(this); },
      function (v) { this.__ptKids = Array.from(v); }),
    parentNode: accessor('parentNode', function () { return this.__ptParent; }, function (v) { this.__ptParent = v; }),
    ownerDocument: accessor('ownerDocument', function () { return this.__ptDoc; }, function (v) { this.__ptDoc = v; }),
  });

  // ---- CharacterData: Text / Comment ---------------------------------------
  class Text extends Node {
    constructor(data) { super(TEXT_NODE); this.__ptData = String(data); }
    get data() { return this.__ptData; }
    // New text means new layout, and `:empty` sees it in the parent's style.
    set data(v) { this.__ptData = String(v); if (this.__ptParent) { __markDirty(); __styleTouch(this.__ptParent); } }
    get nodeName() { return '#text'; }
    get nodeValue() { return this.data; }
    set nodeValue(v) { this.data = String(v); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
    get length() { return this.data.length; }
    __ptShallowClone() { return new Text(this.data); }
  }
  class Comment extends Node {
    constructor(data) { super(COMMENT_NODE); this.__ptData = String(data); }
    get data() { return this.__ptData; }
    set data(v) { this.__ptData = String(v); }
    get nodeName() { return '#comment'; }
    get nodeValue() { return this.data; }
    get textContent() { return this.data; }
    get length() { return this.data.length; }
    __ptShallowClone() { return new Comment(this.data); }
  }

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
    get children() { return __collection(this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.nodeType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    getElementById(id) { return firstMatch(this, (e) => __ptGetA(e, 'id') === String(id)); }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...nodes) {
      const first = this.__ptKids[0] || null;
      for (const n of nodes) this.insertBefore(typeof n === 'string' ? new Text(n) : n, first);
    }
    replaceChildren(...nodes) {
      __ptDropKids(this);
      for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    moveBefore(node, child) { return this.insertBefore(node, child); }
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
    get textContent() { return this.__ptKids.map(n => n.textContent).join(''); }
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
      for (const n of parseFragment(String(html))) __ptAdd.call(host, n);
    }
    // A collection, not an array: `document.children` is an HTMLCollection,
    // and `Object.prototype.toString` says so.
    get children() { return __collection(this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE)); }
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
    getElementById(id) { return firstMatch(this, (e) => __ptGetA(e, 'id') === String(id)); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = __s_split(String(c), /\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = __s_split(e.__ptAttrs.get('class') || '', /\s+/);
        return cs.every((x) => __s_indexOf(own, x) >= 0);
      }));
    }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }
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
    // A constructor body cannot be rerun on an existing node, so the element
    // gets the class prototype: methods and callbacks are in place.
    try { Object.setPrototypeOf(el, Ctor.prototype); } catch (e) { return; }
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
        if (el.nodeType !== ELEMENT_NODE) return;
        const C = __customs.get(el.__ptLocal);
        if (C) __customUpgrade(el, C);
      });
    }
  }

  class Element extends Node {
    constructor(tag) {
      super(ELEMENT_NODE);
      // `new MyElement()` passes no tag name; the registry knows it by the
      // class. Real HTMLElement works the same way.
      if (tag === undefined && new.target) tag = __customName(new.target) || 'unknown';
      this.__ptTag = __s_toUpperCase(String(tag));
      this.__ptLocal = __s_toLowerCase(String(tag));
      this.__ptAttrs = new Map();
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
      __styleTouch(this);
      if (this.__ptUpgraded) {
        const watched = this.constructor && this.constructor.observedAttributes;
        if (Array.isArray(watched) && __s_indexOf(watched, name) >= 0) {
          __customCallback(this, 'attributeChangedCallback',
            [name, old === undefined ? null : old, String(v), null]);
        }
      }
      __markDirty();
      __mutation({ type: 'attributes', target: this, attributeName: name, attributeNamespace: null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    removeAttribute(n) {
      const name = __attrName(this, n), old = this.__ptAttrs.get(name);
      this.__ptAttrs.delete(name);
      __markDirty();
      __styleTouch(this);
      __mutation({ type: 'attributes', target: this, attributeName: name, attributeNamespace: null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    hasAttribute(n) { return this.__ptAttrs.has(__attrName(this, n)); }
    getAttributeNames() { return [...this.__ptAttrs.keys()]; }
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
      if (this.__ptLocal === 'img') { this.__ptLoadImage(); return; }
      if (!this.isConnected) return;
      // The src can arrive after the element is in the document, in either order:
      // `el.src = …; head.appendChild(el)` or `head.appendChild(el); el.src = …`.
      if (this.__ptConnectFrame) this.__ptConnectFrame();
      if (this.__ptRunScript) this.__ptRunScript();
    }

    __ptLoadImage() {
      const raw = __ptGetA(this, 'src');
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptImgAt === url) return;                 // same URL: do not load twice
      Object.defineProperty(this, '__ptImgAt', { value: url, configurable: true, enumerable: false });
      Object.defineProperty(this, '__ptImgDone', { value: false, writable: true, configurable: true, enumerable: false });
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
      __pt_subresource(url, 'img').then(
        () => { this.__ptImgDone = true; this.__ptFireLoad(true); },
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
      // Kinds that load; others (`alternate`, `canonical`, `dns-prefetch`)
      // make no request.
      if (!/^(stylesheet|preload|prefetch|modulepreload|icon|shortcut icon|apple-touch-icon|manifest|prerender)$/.test(rel)) return;
      const raw = __ptGetA(this, 'href');
      if (!raw) return;
      let url = raw;
      try { url = new URL(raw, document.baseURI || location.href).href; } catch (e) {}
      if (this.__ptLinkAt === url) return;
      Object.defineProperty(this, '__ptLinkAt', { value: url, configurable: true, enumerable: false });
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
      // Resource timing names everything loaded via `<link>` as `link`:
      // preload, icon, stylesheet.
      const kind = rel === 'stylesheet' ? 'stylesheet' : 'link';
      // A markup stylesheet blocks the scripts after it until parsed; otherwise
      // they measure an unstyled page (Turnstile's api.js reported the
      // wrapper at the right edge instead of centred).
      const blocking = rel === 'stylesheet' && !document.__ptCurScript
        && this.ownerDocument === document && document.__ptReady === 'loading';
      if (blocking) {
        globalThis.__ptBlockingSheets = (globalThis.__ptBlockingSheets | 0) + 1;
        (globalThis.__ptBlockingSheetUrls || (globalThis.__ptBlockingSheetUrls = new Set())).add(url);
      }
      let released = false;
      const release = () => {
        if (!blocking || released) return;
        released = true;
        globalThis.__ptBlockingSheets = Math.max(0, (globalThis.__ptBlockingSheets | 0) - 1);
        try { globalThis.__ptBlockingSheetUrls.delete(url); } catch (e) {}
      };
      __pt_subresource(url, kind).then(
        (res) => {
          // An external stylesheet is rules, not just a request: they go into
          // `document.styleSheets[i].cssRules` and the cascade.
          const wanted = rel === 'stylesheet';
          const take = (text) => {
            if (wanted && typeof text === 'string') {
              Object.defineProperty(this, '__ptSheetText',
                { value: text, writable: true, enumerable: false, configurable: true });
              __markDirty();
            }
            release();
            if (this.__ptFireLoad) this.__ptFireLoad(true);
          };
          if (wanted && res && typeof res.text === 'function') {
            res.text().then(take, () => take(null));
          } else take(null);
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
    get action() { return this.__ptUrlAttr('action') || ((this.ownerDocument || document).URL || ''); }
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
      __walkTree(this, (n) => { if (n && n.nodeType === ELEMENT_NODE && /^(input|select|textarea|button|fieldset|object|output)$/.test(n.__ptLocal || '') && !(n.__ptLocal === 'input' && __inputType(n) === 'image')) out.push(n); });
      return __collection(out);
    }
    get length() { return this.__ptLocal === 'form' ? this.elements.length : undefined; }
    __ptFormData(submitter) {
      const pairs = [];
      for (const el of this.elements) {
        const tag = el.__ptLocal, name = __ptGetA(el, 'name');
        if (!name || __ptHasA(el, 'disabled') || tag === 'fieldset' || tag === 'object' || tag === 'output') continue;
        if (tag === 'input') {
          const type = __inputType(el);
          if (type === 'submit' || type === 'button' || type === 'reset' || type === 'image') { if (el === submitter) pairs.push([name, el.value || '']); continue; }
          if ((type === 'checkbox' || type === 'radio') && !el.checked) continue;
          if (type === 'file') continue;
          pairs.push([name, String(el.value == null ? '' : el.value)]);
        } else if (tag === 'button') { if (el === submitter) pairs.push([name, el.value || '']); }
        else if (tag === 'select') { for (const o of el.options || []) if (o.selected) pairs.push([name, o.value]); }
        else pairs.push([name, String(el.value == null ? '' : el.value)]);
      }
      return pairs;
    }
    __ptSubmit(submitter) {
      if (this.__ptLocal !== 'form' || !this.isConnected) return;
      const method = this.method;
      if (method === 'dialog') return;
      let action = this.action;
      try { if (submitter && __ptHasA(submitter, 'formaction')) action = new URL(__ptGetA(submitter, 'formaction'), (this.ownerDocument || document).baseURI).href; } catch (e) {}
      const pairs = this.__ptFormData(submitter);
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
        const base = __docTags(this.ownerDocument || document, 'base').find((b) => __ptHasA(b, 'target'));
        target = base ? __ptGetA(base, 'target') : '';
      }
      const kw = __s_toLowerCase(target || '');
      if (kw && kw !== '_self' && kw !== '_top' && kw !== '_parent') {
        // A frame of that name loads the response; the page stays. A new window
        // (`_blank`, an unknown name) without a user's click is a blocked popup.
        const frame = kw === '_blank' ? null : __docTags(this.ownerDocument || document, 'iframe').find((f) => __ptGetA(f, 'name') === target);
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
      if (submitter !== undefined && submitter !== null && !(submitter && submitter.nodeType === ELEMENT_NODE)) throw __pt_mkErr(TypeError, "Failed to execute 'requestSubmit' on 'HTMLFormElement': parameter 1 is not of type 'HTMLElement'.");
      // The browser sends `submit`, so it is trusted even when a script asked
      // for submission (`isTrusted` true in Chrome).
      const ev = __ptTrust(new (globalThis.SubmitEvent || Event)('submit', { bubbles: true, cancelable: true, submitter: submitter || null }));
      if (!this.dispatchEvent(ev)) return;
      this.__ptSubmit(submitter || null);
    }
    __ptUrlAttr(n) {
      const raw = __ptGetA(this, n);
      if (raw == null) return '';
      // An empty frame takes its base URL from the creator: `s.src = 'x.js'`
      // resolves against the parent, not `about://x.js`.
      const base = (this.ownerDocument || document).baseURI || (globalThis.location && location.href) || 'about:blank';
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

    get children() { return __collection(this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() { let n = this.nextSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.previousSibling; return n; }

    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }
    replaceChildren(...ns) {
      const nodes = ns.map((n) => (typeof n === 'string' ? new Text(n) : n));
      for (const n of nodes) if (n && n.__ptParent === this) this.removeChild(n);
      __ptDropKids(this);
      for (const n of nodes) this.appendChild(n);
    }

    // Queries (scoped to this subtree)
    // Element has no getElementById; only document and fragment do.
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    getElementsByClassName(c) {
      const cs = __s_split(String(c), /\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = __s_split(e.__ptAttrs.get('class') || '', /\s+/);
        return cs.length > 0 && cs.every((x) => __s_indexOf(own, x) >= 0);
      }));
    }
    querySelector(sel) {
      __needArgs(arguments.length, 1, 'querySelector', this.constructor && this.constructor.name || 'Element');
      return query(this, __checkSelector(sel, 'querySelector', this.constructor && this.constructor.name || 'Element'))[0] || null;
    }
    querySelectorAll(sel) {
      const who = this.constructor && this.constructor.name || 'Element';
      __needArgs(arguments.length, 1, 'querySelectorAll', who);
      return __staticNodeList(query(this, __checkSelector(sel, 'querySelectorAll', who)));
    }
    closest(sel) {
      __needArgs(arguments.length, 1, 'closest', 'Element');
      __checkSelector(sel, 'closest', 'Element');
      for (let e = this; e; e = e.parentNode) if (e.nodeType === ELEMENT_NODE && matchesSelector(e, sel, this)) return e;
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
        for (let p = this; p && p.nodeType === ELEMENT_NODE; p = p.parentNode && p.parentNode.nodeType === 11 && p.parentNode.__ptHost ? p.parentNode.__ptHost : p.parentNode) {
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
            for (let p = this; p; p = p.parentNode && p.parentNode.nodeType === 11 && p.parentNode.__ptHost ? (chain.push('#shadow'), p.parentNode.__ptHost) : p.parentNode) {
              if (p.nodeType !== 1) { chain.push('#' + p.nodeType); break; }
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
      if (globalThis.__pt_cspActive && __pt_cspActive()) {
        if (!src && __pt_cspBlocksInline(this)) return;
        if (src && __pt_cspBlocksScriptUrl(this, String(src))) return;
      }
      // A module has its own parsing, `import` and scope; the engine runs it,
      // both external and inline.
      const isModule = type === 'module';
      if (src) {
        const id = __nextScriptId++;
        __scriptEls.set(id, this);
        __scriptOps.push({ op: 'load', id, src: String(src), module: isModule });
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
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      // The element size travels with the request: the frame context must know
      // its viewport before its first line runs. Layout cannot be queried here
      // (mid-parse it would freeze half-built); use the declared size.
      const box = __ptJSON.parse(globalThis.__pt_frameBoxOf ? __pt_frameBoxOf(this) : '[300,150]');
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      __frameOps.push({ op: 'open', id, src, name: __ptGetA(this, 'name') || '', w: box[0] || 300, h: box[1] || 150 });
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
      __markDirty();
      __styleTouch(this);
      return sr;
    }
    getAnimations() { return []; }
    getHTML(opts) {
      const kids = (this.__ptLocal === 'template' ? __templateContent(this) : this).__ptKids;
      const withShadow = !!(opts && opts.serializableShadowRoots);
      return kids.map((n) => serializeNode(n, withShadow)).join('');
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
      const nodes = parseFragment(String(html));
      // With an <html> element as the context the parser starts "before head":
      // the result is always a <head> and a <body>, head-only elements up front
      // in the first. Pages build a whole template this way
      // (`createElement('html').innerHTML = page`) and then look for its body.
      if (this.__ptLocal === 'html') {
        const O = globalThis.__pt_orig || {};
        const mk = (t) => (O.createElement ? O.createElement.call(document, t) : document.createElement(t));
        const head = mk('head'), body = mk('body');
        const HEADISH = new Set(['title', 'meta', 'link', 'style', 'script', 'base', 'noscript', 'template', 'basefont', 'bgsound']);
        let inHead = true;
        for (const n of nodes) {
          if (inHead) {
            if (n.nodeType === 3 && !/\S/.test(n.data)) continue;
            if (n.nodeType === 8 || (n.nodeType === 1 && HEADISH.has(n.localName))) { __ptAdd.call(head, n); continue; }
            inHead = false;
          }
          __ptAdd.call(body, n);
        }
        __ptAdd.call(host, head);
        __ptAdd.call(host, body);
        return;
      }
      for (const n of nodes) __ptAdd.call(host, n);
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
      const nodes = parseFragment(String(html));
      if (pos === 'beforeend') for (const n of nodes) __ptAdd.call(this, n);
      else if (pos === 'afterbegin') for (const n of nodes.reverse()) __ptInsert.call(this, n, this.firstChild);
      else if (pos === 'beforebegin') for (const n of nodes) __ptInsert.call(this.parentNode, n, this);
      else if (pos === 'afterend') for (const n of nodes.reverse()) __ptInsert.call(this.parentNode, n, this.nextSibling);
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
      for (let e = this; e && e.nodeType === ELEMENT_NODE; e = e.parentElement) {
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
    get parentElement() { const p = this.parentNode; return p && p.nodeType === ELEMENT_NODE ? p : null; }
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
      // Body means "nothing focused": `relatedTarget` is then null, not `<body>`.
      const relatedFrom = prev && prev !== doc.body ? prev : null;
      this.dispatchEvent(__ptFocusEvent('focus', relatedFrom));
      this.dispatchEvent(__ptFocusEvent('focusin', relatedFrom, true));
    }
    blur() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement !== this) return;
      doc.__ptActive = doc.body || null;
      this.dispatchEvent(__ptFocusEvent('blur', null));
      this.dispatchEvent(__ptFocusEvent('focusout', null, true));
    }
    // Form-field value (reflects the `value` attribute until edited). Generic so
    // input/textarea typing works; harmless on other elements.
    get value() { return this.__ptValue !== undefined ? this.__ptValue : (__ptGetA(this, 'value') || ''); }
    // Form state is styled (`:checked ~ x`, `:placeholder-shown`): new layout.
    set value(v) { this.__ptValue = String(v); __markDirty(); }
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
    set checked(v) { this.__ptChecked = !!v; __markDirty(); }
    get selectionStart() { return String(this.value || '').length; }
    get selectionEnd() { return String(this.value || '').length; }
    select() {}
    setSelectionRange() {}
    setRangeText() {}
    get isContentEditable() { const v = __s_toLowerCase(__ptGetA(this, 'contenteditable') || ''); return v === '' || v === 'true'; }
    click() {
      const ok = this.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
      if (ok) __ptActivate(this);
    }

    __ptShallowClone() {
      const e = new Element(this.localName);
      e.__ptAttrs = new Map(this.__ptAttrs);
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
      for (let i = 0; i < kids.length; i++) if (kids[i].nodeType === ELEMENT_NODE) return kids[i];
      return null;
    }
    // The document's ParentNode members are its own: `children` lives on
    // `Document.prototype` (otherwise the surface installs an empty stub).
    get children() { return __collection(this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.nodeType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE);
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
      for (let e = __elementFromPoint(x, y); e && e.nodeType === ELEMENT_NODE; e = e.parentNode) out.push(e);
      // A point inside the viewport always hits at least <html>.
      if (!out.length && this.documentElement && x >= 0 && y >= 0 && x < (globalThis.innerWidth || 0) && y < (globalThis.innerHeight || 0)) out.push(this.documentElement);
      return out;
    }
    get nodeName() { return '#document'; }
    get head() { return this.documentElement && __tags(this.documentElement, 'head')[0] || null; }
    get body() { return this.documentElement && __tags(this.documentElement, 'body')[0] || null; }
    get title() { const t = this.documentElement ? __tags(this.documentElement, 'title')[0] : null; return t ? __s_trim(t.textContent) : ''; }
    set title(v) {
      let t = this.documentElement ? __tags(this.documentElement, 'title')[0] : null;
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
    get scripts() { return __collection(__docTags(this, 'script')); }
    get forms() { return __collection(__docTags(this, 'form')); }
    get images() { return __collection(__docTags(this, 'img')); }
    get embeds() { return __collection(__docTags(this, 'embed')); }
    get plugins() { return __collection(__docTags(this, 'embed')); }
    // `links` is `<a>`/`<area>` *with an href*, and `anchors` is `<a>` with a name.
    get links() {
      return __collection(__docTags(this, 'a').concat(__docTags(this, 'area'))
        .filter(e => __ptHasA(e, 'href')));
    }
    get anchors() { return __collection(__docTags(this, 'a').filter(e => __ptHasA(e, 'name'))); }
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
    get compatMode() { return this.__ptDoctype || this.__ptXml ? 'CSS1Compat' : 'BackCompat'; }
    get doctype() { return this.__ptDoctype || null; }
    get designMode() { return 'off'; }
    set designMode(v) {}
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
    __ptBaseURI() { return (this.URL === 'about:blank' || this.URL === 'about:srcdoc') && globalThis.__pt_creatorURL ? globalThis.__pt_creatorURL : this.URL; }
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
    createDocumentFragment() { const f = new DocumentFragment(); f.__ptDoc = this; return f; }
    createEvent() { return new Event(''); }
    // A copy of a foreign node for this document. The Cloudflare challenge
    // puts template content into the body this way and then calls
    // `replaceChild` with the result.
    importNode(node, deep) {
      __needArgs(arguments.length, 1, 'importNode', 'Document');
      __needNode(node, 1, 'importNode', 'Document');
      if (node.nodeType === DOCUMENT_NODE) {
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
      if (node.nodeType === DOCUMENT_NODE) {
        throw __pt_mkErr(globalThis.DOMException || Error, 
          "Failed to execute 'adoptNode' on 'Document': The node provided is a document, " +
          "which may not be adopted.", 'NotSupportedError');
      }
      if (node.parentNode) node.parentNode.removeChild(node);
      __walkTree(node, (n) => { n.__ptDoc = this; });
      return node;
    }

    // Walk from the document itself: <html> is a descendant too (otherwise
    // getElementsByTagName('*') was one short and an id on <html> was not found).
    getElementById(id) { return firstMatch(this, (e) => __ptGetA(e, 'id') === String(id)); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = __s_split(String(c), /\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = __s_split((e.__ptAttrs && e.__ptAttrs.get('class')) || '', /\s+/);
        return cs.length > 0 && cs.every((x) => __s_indexOf(own, x) >= 0);
      }));
    }
    getElementsByName(n) {
      const want = String(n);
      return __staticNodeList(collect(this, (e) => e.__ptAttrs && e.__ptAttrs.get('name') === want));
    }
    getElementsByTagNameNS(ns, local) { return __collection(__tagsNS(this, ns, local)); }
    querySelector(s) {
      __needArgs(arguments.length, 1, 'querySelector', 'Document');
      __checkSelector(s, 'querySelector', 'Document');
      return query(this, s)[0] || null;
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
      const nodes = parseFragment(args.map((a) => String(__pt_ttSink('TrustedHTML', 'Document write', a, "Failed to execute 'write' on 'Document'"))).join(''));
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
    preventDefault() { if (this.cancelable) this.__ptE.defaultPrevented = true; }
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
        if (n.nodeType === 11 && n.mode === 'closed' && cur && cur !== n && !(n.contains && n.contains(cur))) hidden = true;
        if (hidden && n.nodeType === 11) { out.length = 0; hidden = false; }
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
      __workerOps.push({ op: 'open', id, src, body, name: (options && options.name) || '' });
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

  class SharedWorker {
    constructor(scriptURL, options) {
      const port = {
        onmessage: null, onmessageerror: null,
        postMessage() {}, start() {}, close() {},
        addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
      };
      Object.defineProperty(this, '__ptW', { value: { onerror: null, port } });
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
  const __ptAdd = Node.prototype.appendChild;
  const __ptDrop = Node.prototype.removeChild;
  const __ptSetAttr = Element.prototype.setAttribute;
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
    if (h.length === 4 || h.length === 8) {
      const a = at(3) / 255;
      return 'rgba(' + r + ', ' + g + ', ' + b + ', ' + (Math.round(a * 100) / 100) + ')';
    }
    return 'rgb(' + r + ', ' + g + ', ' + b + ')';
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
  const __cssValueRaw = (prop, value) => {
    // Custom property values are stored as written.
    if (__s_charCodeAt(prop, 0) === 45 && __s_charCodeAt(prop, 1) === 45) return __s_trim(String(value));
    let v = __cssZero(__cssHex(__s_replace(__s_trim(String(value)), /\s+/g, ' ')));
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
    return out;
  };
  const __cssSelector = (sel) => __s_replace(__s_replace(__s_replace(__s_trim(String(sel)), /\s+/g, ' '), /\s*([>+~])\s*/g, ' $1 '), /\s*,\s*/g, ', ');
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
      // and re-appends on overwrite.
      if (prop) {
        map.delete(prop);
        map.set(prop, __cssValue(prop, __s_slice(decl, colon + 1)));
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

  // A declaration built on first read: thousands of rules, few ever asked.
  const __lazyStyle = (r, decls) => {
    Object.defineProperty(r, 'style', {
      get() {
        const d = __cssDeclaration(decls);
        Object.defineProperty(this, 'style', { value: d, enumerable: true, configurable: true });
        return d;
      },
      enumerable: true, configurable: true,
    });
    return r;
  };

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
  // A rule with children prints on several lines, one per child, indented two
  // spaces. `@keyframes` keeps a space after the opening brace, `@media` does
  // not, as in Chrome.
  const __cssGroup = (prelude, kids, pad) => prelude + ' {' + (pad ? ' ' : '') + '\n'
    + kids.map((k) => '  ' + __s_replace(String(k.cssText), /\n/g, '\n  ')).join('\n')
    + '\n}';

  function __makeRule(parsed, sheet, parent) {
    const prelude = parsed.prelude || '';
    const at = __s_charCodeAt(prelude, 0) === 64 ? __s_toLowerCase(__s_split(prelude, /[\s({]/)[0]) : '';
    const own = (r, props) => { for (const k of Object.keys(props)) Object.defineProperty(r, k, { value: props[k], enumerable: true, configurable: true }); return r; };
    const common = (r, type) => own(r, {
      type, parentStyleSheet: sheet, parentRule: parent || null,
    });

    if (at === '@import') {
      const href = __s_slice(/url\(\s*["']?([^"')]*)["']?\s*\)|["']([^"']*)["']/.exec(prelude) || [], 1).find((x) => x !== undefined) || '';
      const r = common(Object.create(__ruleProto('CSSImportRule')), RULE_TYPE.import);
      return own(r, { href, layerName: null, supportsText: null, styleSheet: null,
                      media: __mediaList(''), cssText: '@import url("' + href + '");' });
    }
    if (at === '@media' || at === '@supports') {
      const name = at === '@media' ? 'CSSMediaRule' : 'CSSSupportsRule';
      const r = common(Object.create(__ruleProto(name)), at === '@media' ? RULE_TYPE.media : RULE_TYPE.supports);
      const cond = __cssPrelude(__s_trim(__s_slice(prelude, at.length)));
      const kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r)).filter(Boolean);
      own(r, { cssRules: __cssRuleList(kids), conditionText: cond });
      if (at === '@media') own(r, { media: __mediaList(cond) });
      return own(r, { cssText: __cssGroup(at + ' ' + cond, kids, false) });
    }
    if (at === '@keyframes' || at === '@-webkit-keyframes') {
      const r = common(Object.create(__ruleProto('CSSKeyframesRule')), RULE_TYPE.keyframes);
      const kids = __cssParse(parsed.body || '').map((p) => {
        const k = common(Object.create(__ruleProto('CSSKeyframeRule')), RULE_TYPE.keyframe);
        const decls = __cssDecls(p.body || '');
        return own(__lazyStyle(k, decls), { keyText: __cssPrelude(p.prelude),
                        cssText: __cssPrelude(p.prelude) + ' { '
                          + __styleEntries(decls).map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
      });
      const name = __s_trim(__s_slice(prelude, at.length));
      return own(r, { name, length: kids.length, cssRules: __cssRuleList(kids),
                      appendRule() {}, deleteRule() {}, findRule() { return null; },
                      cssText: __cssGroup('@keyframes ' + name, kids, true) });
    }
    if (at === '@font-face') {
      const r = common(Object.create(__ruleProto('CSSFontFaceRule')), RULE_TYPE['font-face']);
      const decls = __cssDecls(parsed.body || '');
      return own(__lazyStyle(r, decls), {
                      cssText: '@font-face { '
                        + __styleEntries(decls).map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
    }
    if (at) {
      // Chrome reads `@charset` and drops it; it is not in the rule list.
      if (/^@charset\b/i.test(prelude)) return null;
      const r = common(Object.create(__ruleProto('CSSRule')), RULE_TYPE.charset);
      return own(r, { cssText: prelude + (parsed.statement ? ';' : ' { }') });
    }
    const r = common(Object.create(__ruleProto('CSSStyleRule')), RULE_TYPE.style);
    const decls = __cssDecls(parsed.body || '');
    const sel = __cssSelector(prelude);
    const body = __styleEntries(decls).map(([k, v]) => k + ': ' + v + ';').join(' ');
    own(r, { selectorText: sel });
    // A rule's declaration (~700 properties) is built lazily: building it for
    // thousands of rules cost ~800 ms per stylesheet. The cascade reads the
    // declaration map directly.
    Object.defineProperty(r, 'style', {
      get() {
        const d = __cssDeclaration(decls);
        Object.defineProperty(this, 'style', { value: d, enumerable: true, configurable: true });
        return d;
      },
      enumerable: true, configurable: true,
    });
    Object.defineProperty(r, '__ptDecls', { value: decls, enumerable: false, configurable: true });
    return own(r, { cssRules: __cssRuleList([]), insertRule() { return 0; }, deleteRule() {},
                    cssText: sel + ' { ' + (body ? body + ' ' : '') + '}' });
  }

  const __sheetProto = {
    get [Symbol.toStringTag]() { return 'CSSStyleSheet'; },
    get rules() { return this.cssRules; },
    insertRule(text, index) {
      const parsed = __cssParse(String(text))[0];
      if (!parsed) return 0;
      const arr = [...this.cssRules];
      const at = index === undefined ? 0 : Math.min(index | 0, arr.length);
      arr.splice(at, 0, __makeRule(parsed, this, null));
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(arr), enumerable: true, configurable: true });
      return at;
    },
    deleteRule(index) {
      const arr = [...this.cssRules];
      arr.splice(index | 0, 1);
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(arr), enumerable: true, configurable: true });
    },
    addRule(sel, decl, index) { return this.insertRule(sel + ' { ' + (decl || '') + ' }', index), -1; },
    removeRule(index) { this.deleteRule(index); },
    replaceSync(text) {
      const rules = __cssParse(String(text)).map((p) => __makeRule(p, this, null)).filter(Boolean);
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(rules), enumerable: true, configurable: true });
    },
    replace(text) { this.replaceSync(text); return Promise.resolve(this); },
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
    const proto = __link('CSSStyleSheet', __sheetProto);
    const text = owner.__ptLocal === 'style'
      ? String(owner.textContent || '')
      : String(owner.__ptSheetText || '');
    let sheet = owner.__ptSheet;
    if (!sheet) {
      sheet = Object.create(proto);
      Object.defineProperty(owner, '__ptSheet', { value: sheet, writable: true, enumerable: false });
      const href = owner.__ptLocal === 'link' ? (owner.href || null) : null;
      Object.defineProperty(sheet, 'ownerNode', { value: owner, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'href', { value: href, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'type', { value: 'text/css', enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'disabled', { value: false, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'title', { value: __ptGetA(owner, 'title'), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'media', { value: __mediaList(__ptGetA(owner, 'media') || ''), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'parentStyleSheet', { value: null, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'ownerRule', { value: null, enumerable: true, configurable: true });
    }
    if (sheet.__ptText !== text) {
      Object.defineProperty(sheet, '__ptText', { value: text, writable: true, enumerable: false, configurable: true });
      const rules = __cssParse(text).map((p) => __makeRule(p, sheet, null)).filter(Boolean);
      Object.defineProperty(sheet, 'cssRules', { value: __cssRuleList(rules), enumerable: true, configurable: true });
    }
    return sheet;
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
      if (s.computed) throw __pt_mkErr(TypeError, 'Cannot modify computed style');
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
      if (s.computed) throw __pt_mkErr(TypeError, 'Cannot modify computed style');
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
        if (s.el && s.el.setAttribute) __ptSetA(s.el, 'style', String(v));
        __markDirty();
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

  function makeStyle(el) {
    let cachedText = null, cachedMap = new Map();
    const read = () => {
      const text = String((el && el.getAttribute && __ptGetA(el, 'style')) || '');
      if (text === cachedText) return cachedMap;
      const m = new Map();
      for (const part of __s_split(text, ';')) {
        const i = __s_indexOf(part, ':');
        if (i < 0) continue;
        const k = __cssKey(__s_slice(part, 0, i));
        let v = __s_trim(__s_slice(part, i + 1));
        // Priority is stored beside the value: `getPropertyValue` answers
        // without `!important`, `getPropertyPriority` with it.
        const im = /!\s*important\s*$/i.exec(v);
        if (im) v = __s_trim(__s_slice(v, 0, im.index));
        if (k) { m.set(k, v); if (im) __cssImp(m).add(k); }
      }
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
      __markDirty();
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
  function __tags(root, t) {
    // By internal name, not `tagName`: internal walks must not use
    // page-visible accessors, which a page can wrap and log.
    const local = __s_toLowerCase(String(t));
    return collect(root, (e) => t === '*' || e.__ptLocal === local);
  }
  function __tagsNS(root, ns, local) {
    const L = String(local), N = ns === null ? null : String(ns);
    return collect(root, (e) => (L === '*' || e.__ptLocal === L || e.localName === L)
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
    const visit = (n) => {
      for (const c of (n.__ptKids || [])) {
        if (c.nodeType !== ELEMENT_NODE) continue;
        if (__ptHasSheet(c)) own.push(c);
        visit(c);
      }
    };
    visit(root);
    return own;
  }

  function firstMatch(root, pred) {
    let found = null; walk(root, e => { if (!found && pred(e)) found = e; }); return found;
  }
  function walk(node, visit) {
    for (const c of node.__ptKids) {
      if (c.nodeType === ELEMENT_NODE) { visit(c); walk(c, visit); }
    }
  }

  // ---- selector engine ------------------------------------------------------
  // Full selector parsing: simple, compound, all four combinators and
  // pseudo-classes (chess.com puts all its variables in `:root { … }`).
  const __selCache = new Map();
  const __SEL_NEVER = () => false;

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

  function __selParse(src) {
    let i = 0;
    const s = String(src);
    const ws = () => { const a = i; while (i < s.length && /\s/.test(s[i])) i++; return i > a; };
    const identStart = (c) => c != null && (/[A-Za-z_ -￿-]/.test(c) || c === '\\');
    const ident = () => {
      let out = '';
      while (i < s.length) {
        const c = s[i];
        if (c === '\\') {
          const hex = /^[0-9a-fA-F]{1,6}\s?/.exec(__s_slice(s, i + 1, i + 8));
          if (hex) { out += String.fromCodePoint(parseInt(hex[0], 16) || 0xfffd); i += 1 + hex[0].length; }
          else { out += s[i + 1] || ''; i += 2; }
        } else if (/[\w -￿-]/.test(c)) { out += c; i++; }
        else break;
      }
      return out;
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
          if (s[i] === '|') { i++; if (s[i] === '*') i++; else { const n = __s_toLowerCase(ident()); spec[2]++; tests.push((e) => e.localName === n); } }
          continue;
        }
        if (c === '|') { i++; continue; }
        if (identStart(c)) {
          if (any || tests.length) break;
          let n = ident();
          if (s[i] === '|' && s[i + 1] !== '=') { i++; if (s[i] === '*') { i++; any = true; continue; } n = ident(); }
          const low = __s_toLowerCase(n);
          spec[2]++; any = true;
          tests.push((e) => e.localName === low || (e.__ptNS && e.__ptNS !== 'http://www.w3.org/1999/xhtml' && e.localName === n));
          continue;
        }
        if (c === '#') { i++; const n = ident(); if (!n) fail(); spec[0]++; toks.push('i' + n); tests.push((e) => e.id === n); any = true; continue; }
        if (c === '.') {
          i++; const n = ident(); if (!n) fail(); spec[1]++; toks.push('c' + n);
          tests.push((e) => { const set = __ptClassSet(e); return set !== null && set.has(n); });
          any = true; continue;
        }
        if (c === '[') {
          i++; ws();
          let name = ident();
          if (s[i] === '|' && s[i + 1] !== '=') { i++; name = ident(); }
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
          tests.push((e) => {
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
          });
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
        if (c === '&') { i++; any = true; spec[1]++; tests.push((e, ctx) => !!(ctx && ctx.scope) && e === ctx.scope); continue; }
        break;
      }
      if (!any) fail();
      const n = tests.length;
      const test = n === 0 ? () => true : n === 1 ? tests[0]
        : (e, ctx) => { for (let k = 0; k < n; k++) if (!tests[k](e, ctx)) return false; return true; };
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
      // Tokens every match needs among the subject's ancestors: compounds
      // reached from it through descendant and child combinators only.
      const need = [];
      for (let k = comps.length - 2; k >= 0 && (combs[k] === ' ' || combs[k] === '>'); k--) need.push(...toks[k]);
      return { comps, combs, spec, lead, needH: need.length ? need.map(__bloomHash) : null };
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
      return out;
    };
    return list(false);
  }

  const __parentEl = (e) => { const p = e.parentNode; return p && p.nodeType === ELEMENT_NODE ? p : null; };

  // Ancestor filter, as browsers do it: a 256-bit set of the id and class
  // tokens on an element's ancestors. A rule whose ancestor compounds need a
  // token the set lacks cannot match and is not tested. Must agree with the
  // matcher: ancestors by `__parentEl`, classes by `__ptClassSet`.
  function __bloomHash(t) {
    let x = 2166136261;
    for (let i = 0; i < t.length; i++) { x ^= __s_charCodeAt(t, i); x = Math.imul(x, 16777619); }
    return x >>> 0;
  }
  const __BLOOM_NONE = new Int32Array(8);
  let __passBloom = new WeakMap();
  function __bloomAdd(b, t) { const h = __bloomHash(t); b[(h >>> 5) & 7] |= 1 << (h & 31); }
  function __ancBloom(el) {
    const p = __parentEl(el);
    if (!p) return __BLOOM_NONE;
    let b = __passBloom.get(p);
    if (b) return b;
    b = Int32Array.from(__ancBloom(p));
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
        if (!(b[(h >>> 5) & 7] & (1 << (h & 31)))) { ok = false; break; }
      }
      if (ok) return true;
    }
    return false;
  }
  const __prevEl = (e) => { let p = e.previousSibling; while (p && p.nodeType !== ELEMENT_NODE) p = p.previousSibling; return p; };
  const __nextEl = (e) => { let p = e.nextSibling; while (p && p.nodeType !== ELEMENT_NODE) p = p.nextSibling; return p; };

  function __selMatchComplex(el, cx, idx, ctx) {
    if (!cx.comps[idx](el, ctx)) return false;
    if (idx === 0) {
      if (!cx.lead && !cx.anchored) return true;
      // `:has(> a)`: the anchor itself is on the left.
      const a = ctx.hasAnchor;
      const comb = cx.lead || ' ';
      if (comb === '>') return __parentEl(el) === a;
      if (comb === ' ') { for (let p = __parentEl(el); p; p = __parentEl(p)) if (p === a) return true; return false; }
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
    if (!__FORM_CTL.has(e.localName)) return false;
    if (__ptHasA(e, 'disabled')) return true;
    for (let p = __parentEl(e); p; p = __parentEl(p)) {
      if (p.localName === 'fieldset' && __ptHasA(p, 'disabled')) {
        // Except what is inside the first legend.
        const legend = [...p.children].find((k) => k.localName === 'legend');
        if (!(legend && legend.contains(e))) return true;
      }
    }
    return false;
  };
  const __valueOf = (e) => { try { return String(e.value == null ? '' : e.value); } catch (x) { return ''; } };
  const __isInvalid = (e) => {
    const t = e.localName;
    if (t === 'form' || t === 'fieldset') {
      let bad = false;
      walk(e, (k) => { if (!bad && __isInvalid(k)) bad = true; });
      return bad;
    }
    if (!(t === 'input' || t === 'select' || t === 'textarea') || __isDisabled(e)) return false;
    if (t === 'input' && /^(hidden|submit|reset|button|image)$/.test(__inputType(e))) return false;
    if (__ptHasA(e, 'required')) {
      if (t === 'input' && /^(checkbox|radio)$/.test(__inputType(e))) return !e.checked;
      if (__valueOf(e) === '') return true;
    }
    return false;
  };

  function __selPseudo(name, arg) {
    const B = [0, 1, 0];
    const doc = () => globalThis.document;
    const sib = (e, dir, same) => {
      let n = 1;
      for (let p = dir < 0 ? __prevEl(e) : __nextEl(e); p; p = dir < 0 ? __prevEl(p) : __nextEl(p)) {
        if (!same || p.localName === e.localName) n++;
      }
      return n;
    };
    switch (name) {
      case 'root': return { spec: B, test: (e) => !!e.ownerDocument && e === e.ownerDocument.documentElement };
      case 'scope': return { spec: B, test: (e, ctx) => (ctx && ctx.scope && ctx.scope.nodeType === ELEMENT_NODE ? e === ctx.scope : !!e.ownerDocument && e === e.ownerDocument.documentElement) };
      case 'is': case 'matches': case '-webkit-any': case 'where': {
        const list = __selForgiving(arg || '');
        return { spec: name === 'where' ? [0, 0, 0] : __maxSpec(list),
          test: (e, ctx) => __selAny(list, e, ctx) };
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
              walk(scope, (k) => { if (!found && __selMatchComplex(k, cx, cx.comps.length - 1, ctx)) found = true; });
              if (found) return true;
            }
            return false;
          },
        };
      }
      case 'first-child': return { spec: B, test: (e) => !__prevEl(e) && !!e.parentNode };
      case 'last-child': return { spec: B, test: (e) => !__nextEl(e) && !!e.parentNode };
      case 'only-child': return { spec: B, test: (e) => !__prevEl(e) && !__nextEl(e) && !!e.parentNode };
      case 'first-of-type': return { spec: B, test: (e) => sib(e, -1, true) === 1 };
      case 'last-of-type': return { spec: B, test: (e) => sib(e, 1, true) === 1 };
      case 'only-of-type': return { spec: B, test: (e) => sib(e, -1, true) === 1 && sib(e, 1, true) === 1 };
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
            if (!e.parentNode) return false;
            if (of && !__selAny(of, e, ctx)) return false;
            let n = 1;
            for (let p = last ? __nextEl(e) : __prevEl(e); p; p = last ? __nextEl(p) : __prevEl(p)) {
              if (type ? p.localName === e.localName : !of || __selAny(of, p, ctx)) n++;
            }
            return __nthOk(ab, n);
          },
        };
      }
      case 'empty': return { spec: B, test: (e) => !(e.__ptKids || []).some((k) => k.nodeType === ELEMENT_NODE || ((k.nodeType === TEXT_NODE || k.nodeType === 4) && k.data !== '')) };
      case 'checked': return { spec: B, test: (e) => (e.localName === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && !!e.checked) || (e.localName === 'option' && !!e.selected) };
      case 'indeterminate': return { spec: B, test: (e) => e.localName === 'input' && __inputType(e) === 'checkbox' && !!e.indeterminate };
      case 'default': return { spec: B, test: (e) => (e.localName === 'input' && /^(checkbox|radio)$/.test(__inputType(e)) && __ptHasA(e, 'checked')) || (e.localName === 'option' && __ptHasA(e, 'selected')) };
      case 'disabled': return { spec: B, test: (e) => __isDisabled(e) };
      case 'enabled': return { spec: B, test: (e) => __FORM_CTL.has(e.localName) && !__isDisabled(e) };
      case 'required': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.localName) && __ptHasA(e, 'required') };
      case 'optional': return { spec: B, test: (e) => /^(input|select|textarea)$/.test(e.localName) && !__ptHasA(e, 'required') };
      case 'read-write': case 'read-only': {
        const rw = (e) => {
          if (e.localName === 'textarea') return !__ptHasA(e, 'readonly') && !__isDisabled(e);
          if (e.localName === 'input') return __TEXTISH.test(__inputType(e)) && !__ptHasA(e, 'readonly') && !__isDisabled(e);
          for (let p = e; p; p = __parentEl(p)) {
            const v = __ptGetA(p, 'contenteditable');
            if (v != null) return v !== 'false';
          }
          return false;
        };
        return { spec: B, test: name === 'read-write' ? rw : (e) => !rw(e) };
      }
      case 'placeholder-shown': return { spec: B, test: (e) => (e.localName === 'input' || e.localName === 'textarea') && __ptHasA(e, 'placeholder') && __valueOf(e) === '' };
      case 'valid': return { spec: B, test: (e) => /^(input|select|textarea|form|fieldset)$/.test(e.localName) && !__isInvalid(e) };
      case 'invalid': return { spec: B, test: (e) => __isInvalid(e) };
      case 'link': case 'any-link': case '-webkit-any-link': return { spec: B, test: (e) => (e.localName === 'a' || e.localName === 'area') && __ptHasA(e, 'href') };
      case 'focus': return { spec: B, test: (e) => { const d = e.ownerDocument; return !!d && d.__ptActive === e; } };
      case 'focus-within': return { spec: B, test: (e) => { const d = e.ownerDocument; const a = d && d.__ptActive; return !!a && (a === e || e.contains(a)); } };
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
      case 'open': return { spec: B, test: (e) => (e.localName === 'details' || e.localName === 'dialog') && __ptHasA(e, 'open') };
      case 'defined': return { spec: B, test: (e) => __s_indexOf(e.localName, '-') < 0 || !!(globalThis.customElements && globalThis.customElements.get && globalThis.customElements.get(e.localName)) };
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
  const __SEL_IDENT = /^(?:-?(?:[_a-zA-Z\u00A0-\uFFFF]|\\[^\n]|\\$)(?:[-_a-zA-Z0-9\u00A0-\uFFFF]|\\[^\n]|\\$)*|--(?:[-_a-zA-Z0-9\u00A0-\uFFFF]|\\[^\n]|\\$)*)/;
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
    if (v !== null && typeof v === 'object' && typeof v.nodeType === 'number') return;
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
    if (!el || el.nodeType !== ELEMENT_NODE) return false;
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

  // ---- HTML serialization (innerHTML getter) --------------------------------
  const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' };
  const esc = (s, attr) => __s_replace(s, attr ? /[&<>"]/g : /[&<>]/g, c => ESC[c]);
  function serializeNode(n, withShadow) {
    if (n.nodeType === TEXT_NODE) return esc(n.data, false);
    if (n.nodeType === COMMENT_NODE) return `<!--${n.data}-->`;
    if (n.nodeType !== ELEMENT_NODE) return n.__ptKids.map((c) => serializeNode(c, withShadow)).join('');
    const tag = n.localName;
    let attrs = '';
    for (const { name, value } of n.attributes) attrs += ` ${name}="${esc(value, true)}"`;
    if (VOID.has(tag)) return `<${tag}${attrs}>`;
    // `<template>` serializes its content; a serializable shadow root
    // (getHTML with serializableShadowRoots) as <template shadowrootmode>.
    let inner = '';
    if (withShadow && n.__ptShadow && n.__ptShadow.__ptSerializable) {
      const sr = n.__ptShadow;
      inner += `<template shadowrootmode="${sr.mode}"${sr.__ptDelegatesFocus ? ' shadowrootdelegatesfocus=""' : ''}${sr.__ptSerializable ? ' shadowrootserializable=""' : ''}${sr.__ptClonable ? ' shadowrootclonable=""' : ''}>${sr.__ptKids.map((c) => serializeNode(c, withShadow)).join('')}</template>`;
    }
    const kids = tag === 'template' ? __templateContent(n).__ptKids : n.__ptKids;
    inner += kids.map((c) => serializeNode(c, withShadow)).join('');
    return `<${tag}${attrs}>${inner}</${tag}>`;
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
    for (const c of old) c.__ptParent = null;
    __markDirty();
    __styleTouch(node);
    __mutation(__childListRecord(node, [], old, null, null));
    for (const c of old) __walkTree(c, (f) => {
      if (f.__ptFrameId) __ptDisconnectFrame(f);
      if (f.__ptRealm) { try { if (typeof f.__ptRealm.__pt_detach === 'function') f.__ptRealm.__pt_detach(); } catch (e) {} try { __realmFrames.delete(f); } catch (e) {} }
      if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
    });
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
    for (let el = target; el && el.nodeType === 1; el = el.parentNode) {
      const tag = el.__ptLocal;
      if ((tag === 'button' || tag === 'input') && __ptHasA(el, 'disabled')) return;
      const btype = tag === 'button' ? __s_toLowerCase(String(__ptGetA(el, 'type') || 'submit'))
        : tag === 'input' ? __inputType(el) : null;
      if (btype === 'submit' || btype === 'image' || btype === 'reset') {
        if (tag === 'button' && btype !== 'submit' && btype !== 'reset') return;
        let f = el.parentNode; while (f && f.__ptLocal !== 'form') f = f.parentNode;
        const formId = __ptGetA(el, 'form');
        if (formId && globalThis.document) f = document.getElementById(formId) || f;
        if (!f) return;
        if (btype === 'reset') { if (typeof f.reset === 'function') f.reset(); }
        else if (typeof f.requestSubmit === 'function') f.requestSubmit(el);
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

  // ---- HTML fragment parser (innerHTML setter) ------------------------------
  // A forgiving tokenizer: handles tags, attributes (quoted/unquoted/bare),
  // text, comments, and void/self-closing elements. Not spec-perfect, but
  // covers the markup scripts typically inject.
  const __SVG_NS = 'http://www.w3.org/2000/svg', __MATH_NS = 'http://www.w3.org/1998/Math/MathML';
  // Case tables from the HTML spec (adjust SVG tag/attribute names).
  const __SVG_CASE = {};
  for (const n of ['altGlyph', 'altGlyphDef', 'altGlyphItem', 'animateColor', 'animateMotion', 'animateTransform', 'clipPath', 'feBlend', 'feColorMatrix', 'feComponentTransfer', 'feComposite', 'feConvolveMatrix', 'feDiffuseLighting', 'feDisplacementMap', 'feDistantLight', 'feDropShadow', 'feFlood', 'feFuncA', 'feFuncB', 'feFuncG', 'feFuncR', 'feGaussianBlur', 'feImage', 'feMerge', 'feMergeNode', 'feMorphology', 'feOffset', 'fePointLight', 'feSpecularLighting', 'feSpotLight', 'feTile', 'feTurbulence', 'foreignObject', 'glyphRef', 'linearGradient', 'radialGradient', 'textPath']) __SVG_CASE[__s_toLowerCase(n)] = n;
  const __SVG_ATTR_CASE = {};
  for (const n of ['attributeName', 'attributeType', 'baseFrequency', 'baseProfile', 'calcMode', 'clipPathUnits', 'diffuseConstant', 'edgeMode', 'filterUnits', 'glyphRef', 'gradientTransform', 'gradientUnits', 'kernelMatrix', 'kernelUnitLength', 'keyPoints', 'keySplines', 'keyTimes', 'lengthAdjust', 'limitingConeAngle', 'markerHeight', 'markerUnits', 'markerWidth', 'maskContentUnits', 'maskUnits', 'numOctaves', 'pathLength', 'patternContentUnits', 'patternTransform', 'patternUnits', 'pointsAtX', 'pointsAtY', 'pointsAtZ', 'preserveAlpha', 'preserveAspectRatio', 'primitiveUnits', 'refX', 'refY', 'repeatCount', 'repeatDur', 'requiredExtensions', 'requiredFeatures', 'specularConstant', 'specularExponent', 'spreadMethod', 'startOffset', 'stdDeviation', 'stitchTiles', 'surfaceScale', 'systemLanguage', 'tableValues', 'targetX', 'targetY', 'textLength', 'viewBox', 'viewTarget', 'xChannelSelector', 'yChannelSelector', 'zoomAndPan']) __SVG_ATTR_CASE[__s_toLowerCase(n)] = n;
  const __foreignElem = (doc, ns, name) => {
    const O = globalThis.__pt_orig || {};
    const f = O.createElementNS || Document.prototype.createElementNS;
    return f.call(doc, ns, name);
  };
  function parseFragment(html) {
    const doc = globalThis.document;
    // Parsing bypasses page-visible names: in Chrome `innerHTML` does not call
    // `createElement`, `appendChild` or `setAttribute`, and anyone wrapping
    // them would see the calls.
    const O = globalThis.__pt_orig || {};
    const mk = (name, self, args) => (O[name] ? O[name].apply(self, args) : self[name].apply(self, args));
    const frag = () => mk('createDocumentFragment', doc, []);
    const text = (t) => mk('createTextNode', doc, [t]);
    const note = (t) => mk('createComment', doc, [t]);
    const elem = (t) => mk('createElement', doc, [t]);
    const put = (parent, child) => __ptAdd.call(parent, child);
    const attr = (el, n, v) => __ptSetAttr.call(el, n, v);
    const root = frag();
    const stack = [root];
    const top = () => stack[stack.length - 1];
    let i = 0;
    while (i < html.length) {
      if (html[i] === '<') {
        if (__s_startsWith(html, '<!--', i)) {
          const end = __s_indexOf(html, '-->', i + 4);
          const stop = end < 0 ? html.length : end;
          put(top(), note(__s_slice(html, i + 4, stop)));
          i = end < 0 ? html.length : end + 3; continue;
        }
        // A DOCTYPE inside a fragment is a parse error the parser ignores —
        // it never becomes text.
        if (/^<!doctype/i.test(__s_slice(html, i, i + 9))) {
          const end = __s_indexOf(html, '>', i);
          i = end < 0 ? html.length : end + 1; continue;
        }
        const close = html[i + 1] === '/';
        const m = /^<\/?([a-zA-Z][\w-]*)((?:[^>"']|"[^"]*"|'[^']*')*)\/?>/.exec(__s_slice(html, i));
        if (!m) { put(top(), text('<')); i++; continue; }
        const tag = __s_toLowerCase(m[1]);
        if (close) {
          for (let s = stack.length - 1; s > 0; s--) if (__s_toLowerCase(String(stack[s].localName)) === tag) { stack.length = s; break; }
        } else if (tag === 'html' || tag === 'head' || tag === 'body') {
          // Fragment parsing: Chrome does not insert these tags, their content
          // moves into the current parent (`div.innerHTML =
          // '<html><body></body></html>'` leaves it empty).
        } else {
          // Implied end tags as in HTML parsing: a new block tag closes an open
          // <p>, `<li>` closes an open <li>, etc. (`<p>a<p>b` gives two siblings).
          const CLOSES_P = new Set(['address', 'article', 'aside', 'blockquote', 'details', 'dialog', 'div', 'dl', 'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hgroup', 'hr', 'main', 'menu', 'nav', 'ol', 'p', 'pre', 'section', 'table', 'ul']);
          const SELF_CLOSES = { li: ['li'], dt: ['dt', 'dd'], dd: ['dt', 'dd'], option: ['option', 'optgroup'], optgroup: ['optgroup'], tr: ['tr', 'td', 'th'], td: ['td', 'th'], th: ['td', 'th'], thead: ['tbody', 'tfoot', 'thead'], tbody: ['tbody', 'tfoot', 'thead'], tfoot: ['tbody', 'tfoot', 'thead'] };
          if (CLOSES_P.has(tag)) { for (let s = stack.length - 1; s > 0; s--) { if (stack[s].localName === 'p') { stack.length = s; break; } if (CLOSES_P.has(stack[s].localName) && stack[s].localName !== 'p') break; } }
          const closes = SELF_CLOSES[tag];
          if (closes) { for (let s = stack.length - 1; s > 0; s--) { const ln = stack[s].localName; if (__s_indexOf(closes, ln) >= 0) { stack.length = s; break; } if (ln === 'table' || ln === 'ul' || ln === 'ol' || ln === 'select' || ln === 'dl') break; } }
          // Implied table wrappers: `<table><tr>` gets a `<tbody>`, a `<td>`
          // without a row gets a `<tr>`; `table.tBodies[0].rows` always exists.
          if (tag === 'tr' || tag === 'td' || tag === 'th') {
            const tl = top().localName;
            if (tag === 'tr' && tl === 'table') { const tb = elem('tbody'); put(top(), tb); stack.push(tb); }
            else if ((tag === 'td' || tag === 'th') && (tl === 'table' || tl === 'tbody' || tl === 'thead' || tl === 'tfoot')) {
              if (tl === 'table') { const tb = elem('tbody'); put(top(), tb); stack.push(tb); }
              const row = elem('tr'); put(top(), row); stack.push(row);
            }
          }
          // Foreign content as in HTML parsing: SVG elements inside <svg> (name
          // case per the spec table), MathML inside <math>, HTML again inside
          // SVG foreignObject/desc/title.
          const parentNS = (() => {
            const t = top(); const pns = t && t.__ptNS;
            if (pns === __SVG_NS && (t.__ptLocal === 'foreignObject' || t.__ptLocal === 'desc' || t.__ptLocal === 'title')) return null;
            if (pns === __MATH_NS && t.__ptLocal === 'annotation-xml') return null;
            return pns === __SVG_NS || pns === __MATH_NS ? pns : null;
          })();
          const ns = parentNS || (tag === 'svg' ? __SVG_NS : tag === 'math' ? __MATH_NS : null);
          const el = ns ? __foreignElem(doc, ns, ns === __SVG_NS ? (__SVG_CASE[tag] || tag) : tag) : elem(tag);
          for (const am of m[2].matchAll(/([\w:-]+)(?:\s*=\s*("[^"]*"|'[^']*'|[^\s>]+))?/g)) {
            let v = am[2] || '';
            if (v && (v[0] === '"' || v[0] === "'")) v = __s_slice(v, 1, -1);
            // Character references in attribute values are decoded like text:
            // `&quot;` becomes a quote and serializes back as `&quot;`.
            const an = __s_toLowerCase(am[1]);
            attr(el, ns === __SVG_NS ? (__SVG_ATTR_CASE[an] || an) : an, unescapeEntities(v));
          }
          put(top(), el);
          const selfClose = __s_endsWith(m[0], '/>') && (ns || VOID.has(tag)) || VOID.has(tag) && !ns;
          if (!selfClose) stack.push(el);
        }
        i += m[0].length;
      } else {
        const next = __s_indexOf(html, '<', i);
        const stop = next < 0 ? html.length : next;
        const chunk = __s_slice(html, i, stop);
        if (chunk) put(top(), text(unescapeEntities(chunk)));
        i = stop;
      }
    }
    return __s_slice(root.__ptKids);
  }
  const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '\u00a9', reg: '\u00ae', trade: '\u2122', hellip: '\u2026', mdash: '\u2014', ndash: '\u2013', laquo: '\u00ab', raquo: '\u00bb', times: '\u00d7', middot: '\u00b7', bull: '\u2022', lsquo: '\u2018', rsquo: '\u2019', ldquo: '\u201c', rdquo: '\u201d', euro: '\u20ac', pound: '\u00a3', yen: '\u00a5', cent: '\u00a2', sect: '\u00a7', deg: '\u00b0', plusmn: '\u00b1', para: '\u00b6', shy: '\u00ad', iexcl: '\u00a1', iquest: '\u00bf', larr: '\u2190', rarr: '\u2192', uarr: '\u2191', darr: '\u2193', ensp: '\u2002', emsp: '\u2003', thinsp: '\u2009', zwnj: '\u200c', zwj: '\u200d' };
  function unescapeEntities(s) {
    if (__s_indexOf(s, '&') < 0) return s;
    return __s_replace(s, /&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g, (m, e) => {
      if (e[0] === '#') {
        const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(__s_slice(e, 2), 16) : parseInt(__s_slice(e, 1), 10);
        if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return '\ufffd';
        return String.fromCodePoint(cp);
      }
      return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, e) ? NAMED_ENTITIES[e] : m;
    });
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

  function buildNode(doc, spec) {
    if (spec.k === 't') return doc.createTextNode(spec.v);
    if (spec.k === 'c') return doc.createComment(spec.v);
    const el = spec.ns ? __foreignElem(doc, spec.ns, spec.tag) : doc.createElement(spec.tag);
    // A parser-built script is "already started": the engine runs the document's
    // scripts itself, in document order, so connecting the tree must not run them
    // a second time. Only what a page inserts later goes through `__ptRunScript`.
    if (spec.tag === 'script') {
      Object.defineProperty(el, '__ptRan', { value: true, configurable: true, enumerable: false });
    }
    for (const [name, value] of spec.attrs) __ptSetA(el, name, value);
    // The parser puts template children into its content and leaves the
    // element empty (`t.childNodes.length === 0` in Chrome too).
    const into = spec.tag === 'template' ? __templateContent(el) : el;
    for (const child of spec.children) into.appendChild(buildNode(doc, child));
    return el;
  }

  // ---- install globals ------------------------------------------------------
  const document = new Document();
  globalThis.document = document;
  // Standard Node type constants, on the constructor and the prototype — drivers
  // check `node.nodeType !== Node.ELEMENT_NODE` before acting on a node.
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
    switch (this.nodeType) {
      case 1: return this.tagName;
      case 3: return '#text';
      case 8: return '#comment';
      case 9: return '#document';
      case 10: return this.name || 'html';
      case 11: return '#document-fragment';
      default: return '#unknown';
    }
  };
  const __nodeMembers = {
    baseURI: { get: function () { const d = this.nodeType === 9 ? this : this.ownerDocument; return (d && d.URL) || (globalThis.location && location.href) || 'about:blank'; } },
    nodeName: { get: __nodeName },
    parentElement: { get: function () { const p = this.parentNode; return p && p.nodeType === 1 ? p : null; } },
    nodeValue: {
      get: function () { return (this.nodeType === 3 || this.nodeType === 8) ? this.data : null; },
      set: function (v) { if (this.nodeType === 3 || this.nodeType === 8) this.data = String(v); },
    },
    isSameNode: { value: function isSameNode(other) { return this === other; } },
    isEqualNode: {
      value: function isEqualNode(other) {
        if (!other || this.nodeType !== other.nodeType) return false;
        if (this.nodeName !== other.nodeName) return false;
        if (this.nodeType === 3 || this.nodeType === 8) return this.data === other.data;
        if (this.nodeType === 1) {
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
        if (this.contains && this.contains(other)) return 20;   // CONTAINED_BY | FOLLOWING
        if (other.contains && other.contains(this)) return 10;  // CONTAINS | PRECEDING
        const root = (n) => { while (n.parentNode) n = n.parentNode; return n; };
        if (root(this) !== root(other)) return 35;              // DISCONNECTED | IMPLEMENTATION_SPECIFIC | PRECEDING
        const order = [];
        (function walk(n) { order.push(n); for (const c of n.childNodes) walk(c); })(root(this));
        return __s_indexOf(order, this) < __s_indexOf(order, other) ? 4 : 2;
      },
    },
    normalize: {
      value: function normalize() {
        const kids = this.childNodes;
        for (let i = kids.length - 1; i > 0; i--) {
          const cur = kids[i], prev = kids[i - 1];
          if (cur.nodeType === 3 && prev.nodeType === 3) { prev.data += cur.data; this.removeChild(cur); }
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
      if (new.target && new.target !== C) return Reflect.construct(Element, [__pendingTag], new.target);
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
  };
  // Tags known to HTML without their own interface: HTMLElement.
  const PLAIN_TAGS = new Set(['abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo',
    'cite', 'code', 'dd', 'dfn', 'dt', 'em', 'figcaption', 'figure', 'footer', 'header',
    'hgroup', 'i', 'kbd', 'main', 'mark', 'nav', 'noscript', 'rp', 'rt', 'ruby', 's',
    'samp', 'search', 'section', 'small', 'strong', 'sub', 'summary', 'sup', 'u', 'var',
    'wbr', 'center', 'font', 'big', 'strike', 'tt', 'nobr']);
  for (const name of new Set(Object.values(TAG_IFACE))) __ifaceProto.set(name, __mkIface(name, __htmlProto));
  // Media elements inherit HTMLMediaElement.
  const __mediaProto = __mkIface('HTMLMediaElement', __htmlProto);
  for (const n of ['HTMLVideoElement', 'HTMLAudioElement']) {
    try { Object.setPrototypeOf(globalThis[n].prototype, __mediaProto); } catch (e) {}
  }
  __ifaceProto.set('HTMLUnknownElement', __mkIface('HTMLUnknownElement', __htmlProto));
  for (const n of ['HTMLFrameSetElement', 'HTMLFrameElement', 'HTMLMarqueeElement',
                   'HTMLDirectoryElement', 'HTMLFontElement', 'HTMLParamElement']) {
    if (!globalThis[n]) __mkIface(n, __htmlProto);
  }
  // Form and table collections: `table.rows`, `tr.cells`, `select.options`,
  // `form.elements`… (the Cloudflare challenge parses its test markup this way).
  {
    const proto = (n) => __ifaceProto.get(n);
    const defGet = (P, k, get) => { if (!P) return; try { Object.defineProperty(P, k, { get, enumerable: true, configurable: true }); } catch (e) {} };
    const defFn = (P, k, fn) => { if (!P) return; try { Object.defineProperty(P, k, { value: fn, writable: true, enumerable: true, configurable: true }); } catch (e) {} };
    const kids = (el) => (el && el.__ptKids ? el.__ptKids : []).filter((k) => k.nodeType === ELEMENT_NODE);
    const local = (el) => __s_toLowerCase(String(el.__ptLocal || ''));
    const isTag = (el, ...names) => el && el.nodeType === ELEMENT_NODE && __s_includes(names, local(el));
    const branded = (arr, name) => {
      const c = __collection(arr);
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
    const defAcc = (P, k, get, set) => { try { Object.defineProperty(P, k, { get, set, enumerable: true, configurable: true }); } catch (e) {} };
    const tableSet = (t, tag, v, where) => {
      if (v !== null && !(v && isTag(v, tag))) throw __pt_mkErr(TypeError, "Failed to set the '" + (tag === 'thead' ? 'tHead' : tag === 'tfoot' ? 'tFoot' : tag) + "' property on 'HTMLTableElement': The provided value is not of type '" + (tag === 'caption' ? 'HTMLTableCaptionElement' : 'HTMLTableSectionElement') + "'.");
      const old = kids(t).find((k) => isTag(k, tag)); if (old) t.removeChild(old);
      if (!v) return;
      const ref = where(t); ref ? t.insertBefore(v, ref) : t.appendChild(v);
    };
    defAcc(T, 'tHead', function () { return kids(this).find((k) => isTag(k, 'thead')) || null; },
      function (v) { tableSet(this, 'thead', v, (t) => kids(t).find((k) => !isTag(k, 'caption') && !isTag(k, 'colgroup')) || null); });
    defAcc(T, 'tFoot', function () { return kids(this).find((k) => isTag(k, 'tfoot')) || null; },
      function (v) { tableSet(this, 'tfoot', v, () => null); });
    defAcc(T, 'caption', function () { return kids(this).find((k) => isTag(k, 'caption')) || null; },
      function (v) { tableSet(this, 'caption', v, (t) => kids(t)[0] || null); });
    const S = proto('HTMLTableSectionElement');
    defGet(S, 'rows', function () { return __collection(kids(this).filter((k) => isTag(k, 'tr'))); });
    const R = proto('HTMLTableRowElement');
    defGet(R, 'cells', function () { return __collection(kids(this).filter((k) => isTag(k, 'td', 'th'))); });
    defGet(R, 'rowIndex', function () {
      let t = this.parentNode;
      if (t && isTag(t, 'thead', 'tbody', 'tfoot')) t = t.parentNode;
      if (!t || !isTag(t, 'table')) return -1;
      return __s_indexOf(tableRows(t), this);
    });
    defGet(R, 'sectionRowIndex', function () {
      const p = this.parentNode;
      if (!p || !isTag(p, 'table', 'thead', 'tbody', 'tfoot')) return -1;
      return __s_indexOf(kids(p).filter((k) => isTag(k, 'tr')), this);
    });
    const C = proto('HTMLTableCellElement');
    defGet(C, 'cellIndex', function () {
      const p = this.parentNode;
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
    defGet(SEL, 'options', function () { const c = branded(selOptions(this), 'HTMLOptionsCollection'); try { Object.defineProperty(c, '__ptSelect', { value: this, configurable: true }); } catch (e) {} return c; });
    // selectedIndex and length setters, as Chrome's HTMLSelectElement/HTMLOptionsCollection.
    const selSetIndex = (sel, i) => {
      const opts = selOptions(sel); i = i | 0;
      opts.forEach((o, j) => { o.__ptSelected = (j === i); });
    };
    const selSetLength = (sel, n) => {
      const opts = selOptions(sel); n = Math.max(0, n >>> 0);
      if (n < opts.length) { for (const o of __s_slice(opts, n)) o.parentNode && o.parentNode.removeChild(o); }
      else for (let i = opts.length; i < n; i++) sel.appendChild(sel.ownerDocument.createElement('option'));
    };
    globalThis.__pt_selSetLength = selSetLength;
    globalThis.__pt_selSetIndex = selSetIndex;
    // A select's `value` is the selected option's; option `selected`/`value`/`text`.
    const optValue = (o) => { const v = __ptGetA(o, 'value'); return v != null ? String(v) : __s_trim(__s_replace(String(o.textContent || ''), /\s+/g, ' ')); };
    defAcc(SEL, 'value', function () {
      const opts = selOptions(this); const multiple = __ptHasA(this, 'multiple');
      let chosen = opts.filter(isSelected);
      if (!multiple) { if (chosen.length > 1) chosen = [chosen[chosen.length - 1]]; if (!chosen.length && opts.length && __ptGetA(this, 'size') == null) chosen = [opts[0]]; }
      return chosen.length ? optValue(chosen[0]) : '';
    }, function (v) {
      const opts = selOptions(this); v = String(v); let hit = false;
      for (const o of opts) { if (!hit && optValue(o) === v) { o.__ptSelected = true; hit = true; } else o.__ptSelected = false; }
    });
    const O_ = proto('HTMLOptionElement');
    defAcc(O_, 'selected', function () { return isSelected(this); }, function (v) {
      this.__ptSelected = !!v;
      __markDirty();
      if (v) { let p = this.parentNode; if (p && isTag(p, 'optgroup')) p = p.parentNode; if (p && isTag(p, 'select') && !__ptHasA(p, 'multiple')) for (const o of selOptions(p)) if (o !== this) o.__ptSelected = false; }
    });
    defAcc(O_, 'value', function () { return optValue(this); }, function (v) { __ptSetA(this, 'value', String(v)); });
    defAcc(O_, 'text', function () { return __s_trim(__s_replace(String(this.textContent || ''), /\s+/g, ' ')); }, function (v) { this.textContent = String(v); });
    defGet(SEL, 'selectedOptions', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      let chosen = opts.filter(isSelected);
      if (!multiple) { if (chosen.length > 1) chosen = [chosen[chosen.length - 1]]; if (!chosen.length && opts.length && __ptGetA(this, 'size') == null) chosen = [opts[0]]; }
      return __collection(chosen);
    });
    defAcc(SEL, 'selectedIndex', function () {
      const opts = selOptions(this);
      const multiple = __ptHasA(this, 'multiple');
      const chosen = opts.filter(isSelected);
      if (chosen.length) return __s_indexOf(opts, multiple ? chosen[0] : chosen[chosen.length - 1]);
      return !multiple && opts.length && __ptGetA(this, 'size') == null ? 0 : -1;
    }, function (v) { selSetIndex(this, v); });
    defAcc(SEL, 'length', function () { return selOptions(this).length; }, function (v) { selSetLength(this, v); });
    defGet(SEL, 'type', function () { return __ptHasA(this, 'multiple') ? 'select-multiple' : 'select-one'; });
    defFn(SEL, 'item', function item(i) { return selOptions(this)[i | 0] || null; });
    defFn(SEL, 'namedItem', function namedItem(n) { return selOptions(this).find((o) => o.id === n || __ptGetA(o, 'name') === n) || null; });
    const DL = proto('HTMLDataListElement');
    defGet(DL, 'options', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'option')) out.push(n); }); return __collection(out); });
    // Forms and their elements.
    const LISTED = new Set(['button', 'fieldset', 'input', 'object', 'output', 'select', 'textarea']);
    const formOf = (el) => {
      const id = __ptGetA(el, 'form');
      if (id != null && el.ownerDocument && el.ownerDocument.getElementById) return el.ownerDocument.getElementById(id) || null;
      for (let p = el.parentNode; p; p = p.parentNode) { if (isTag(p, 'form')) return p; if (p.nodeType === 11 && p.__ptHost) { p = p.__ptHost; } }
      return null;
    };
    const formControls = (form) => {
      const out = [];
      const doc = form.ownerDocument;
      const root = doc && doc.documentElement ? doc.documentElement : form;
      __walkTree(root, (n) => {
        if (!n || n.nodeType !== ELEMENT_NODE || !LISTED.has(local(n))) return;
        if (local(n) === 'input' && __s_toLowerCase(String(__ptGetA(n, 'type') || '')) === 'image') return;
        if (formOf(n) === form) out.push(n);
      });
      return out;
    };
    const F = proto('HTMLFormElement');
    defGet(F, 'elements', function () { return branded(formControls(this), 'HTMLFormControlsCollection'); });
    defGet(F, 'length', function () { return formControls(this).length; });
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
        __walkTree(n, (m) => { if (!found && m !== n && m.nodeType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && __s_toLowerCase(String(__ptGetA(m, 'type') || '')) === 'hidden')) found = m; });
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
        if (local(this) === 'legend') { const p = this.parentNode; return p && isTag(p, 'fieldset') ? formOf(p) : null; }
        if (local(this) === 'label') { const c = this.control; return c ? formOf(c) : null; }
        return formOf(this);
      });
    }
    const L = proto('HTMLLabelElement');
    defGet(L, 'control', function () {
      const f = __ptGetA(this, 'for');
      if (f != null) { const el = this.ownerDocument && this.ownerDocument.getElementById ? this.ownerDocument.getElementById(f) : null; return el && LABELABLE.has(local(el)) ? el : null; }
      let found = null;
      __walkTree(this, (m) => { if (!found && m !== this && m.nodeType === ELEMENT_NODE && LABELABLE.has(local(m)) && !(local(m) === 'input' && __s_toLowerCase(String(__ptGetA(m, 'type') || '')) === 'hidden')) found = m; });
      return found;
    });
    const M = proto('HTMLMapElement');
    defGet(M, 'areas', function () { const out = []; __walkTree(this, (n) => { if (isTag(n, 'area')) out.push(n); }); return __collection(out); });
    const O = proto('HTMLOptionElement');
    defGet(O, 'index', function () { let p = this.parentNode; if (p && isTag(p, 'optgroup')) p = p.parentNode; return p && isTag(p, 'select') ? __s_indexOf(selOptions(p), this) : 0; });
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
      const t = __s_toLowerCase(el.localName || '');
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
      const t = __s_toLowerCase(this.localName || '');
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
      const kids = [...(this.__ptKids || [])].filter((k) => k.nodeType === ELEMENT_NODE);
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
      for (let n = el; n && n.nodeType === ELEMENT_NODE; n = n.parentNode) {
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
  globalThis.Text = Text;
  globalThis.Comment = Comment;
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
      const nodes = isHtml ? parseFragment(String(markup == null ? '' : markup)) : (() => {
        const r = this.parseXml(doc, String(markup == null ? '' : markup));
        let root = r.nodes.find((n) => n.nodeType === ELEMENT_NODE);
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
      let root = nodes.find((n) => n.nodeType === ELEMENT_NODE && n.localName === 'html');
      if (!root && isHtml) {
        root = doc.createElement('html');
        const head = doc.createElement('head');
        const body = doc.createElement('body');
        __ptAdd.call(root, head);
        __ptAdd.call(root, body);
        for (const n of nodes) __ptAdd.call(body, n);
      } else if (!root) {
        root = nodes.find((n) => n.nodeType === ELEMENT_NODE) || doc.createElement('html');
      } else if (isHtml) {
        if (!__tags(root, 'head')[0]) __ptInsert.call(root, doc.createElement('head'), root.firstChild);
        if (!__tags(root, 'body')[0]) __ptAdd.call(root, doc.createElement('body'));
      }
      __ptAdd.call(doc, root);
      doc.__ptDocEl = root;
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
      if (node && node.nodeType === 9 && node.documentElement) node = node.documentElement;
      const one = (n, root) => {
        if (n.nodeType === TEXT_NODE) return esc(String(n.data), false);
        if (n.nodeType === COMMENT_NODE) return '<!--' + n.data + '-->';
        if (n.nodeType !== ELEMENT_NODE) {
          // Fragment children (shadow root included) are each a root: xmlns on
          // every top-level element, as in Chrome.
          return (n.__ptKids || []).map((c) => one(c, root)).join('');
        }
        const tag = n.localName;
        let attrs = '';
        if (root && !(n.ownerDocument && n.ownerDocument.__ptXml)) attrs += ' xmlns="http://www.w3.org/1999/xhtml"';
        for (const { name, value } of n.attributes) attrs += ' ' + name + '="' + esc(String(value), true) + '"';
        const kids = (n.__ptKids || []).map((c) => one(c, false)).join('');
        if (!kids && VOID_XML.has(tag)) return '<' + tag + attrs + ' />';
        return '<' + tag + attrs + '>' + kids + '</' + tag + '>';
      };
      // Fragment and shadow root: their top-level children are roots (xmlns).
      return one(node, node && (node.nodeType === ELEMENT_NODE || node.nodeType === DOCUMENT_FRAGMENT_NODE));
    },
  };

  // `window.length` and `window.frames[i]` count live frames, recomputed from
  // the tree so they stay in sync with insertions.
  {
    const frameEls = () => {
      const out = [];
      const doc = globalThis.document;
      if (!doc || !doc.documentElement) return out;
      // Light tree only: Chrome does not count frames inside shadow roots.
      const walk = (n) => {
        if (n.nodeType === ELEMENT_NODE && (n.__ptLocal === 'iframe' || n.__ptLocal === 'frame')) out.push(n);
        for (const k of (n.__ptKids || [])) walk(k);
      };
      walk(doc.documentElement);
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
  const __cspAllowsUrl = (list, url, nonce) => {
    const u = String(url || '');
    if (nonce && list.some((t) => __s_toLowerCase(t) === "'nonce-" + __s_toLowerCase(nonce) + "'" || t === "'nonce-" + nonce + "'")) return true;
    if (__cspHas(list, "'strict-dynamic'")) return false;
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
  // Inline script: nonce/hash/'unsafe-inline' (the last is voided by nonce/hash).
  const __cspAllowsInline = (el) => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const list = d[1];
      const hasNonceOrHash = list.some((t) => /^'(nonce-|sha(256|384|512)-)/i.test(t));
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (nonce && list.some((t) => t === "'nonce-" + nonce + "'")) continue;
      if (!hasNonceOrHash && __cspHas(list, "'unsafe-inline'")) continue;
      return { name: d[0], list };
    }
    return null;
  };
  const __cspReport = (what) => { try { (globalThis.__pt_parentConsole || console).error(what); } catch (e) {} };
  globalThis.__pt_cspBlocksInline = (el) => {
    const v = __cspAllowsInline(el);
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
  globalThis.__pt_cspBlocksScriptUrl = (el, url) => {
    for (const p of __csp.policies) {
      const d = __cspScriptDirective(p);
      if (!d) continue;
      const nonce = el && (__ptGetA(el, 'nonce') || el.__ptNonce || '');
      if (__cspAllowsUrl(d[1], url, nonce)) continue;
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
    __cspWrapEval();
  };
  globalThis.__pt_cspActive = () => __csp.policies.length > 0;
  // Document meta policy: applied as soon as the markup is parsed.
  globalThis.__pt_cspFromMeta = (root) => {
    try {
      if (__csp.headerDelivered) __walkTree(root, (n) => { try { if (n && n.nodeType === ELEMENT_NODE && typeof n.__ptHideNonce === 'function') n.__ptHideNonce(); } catch (e) {} });
      const metas = [];
      __walkTree(root, (n) => { if (n && n.nodeType === ELEMENT_NODE && __s_toLowerCase(String(n.__ptLocal || '')) === 'meta' && __s_toLowerCase(String(__ptGetA(n, 'http-equiv') || '')) === 'content-security-policy') metas.push(n); });
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
    const nodes = parseFragment(String(html == null ? '' : html));
    let root = nodes.find((n) => n.nodeType === 1 && n.tagName === 'HTML');
    if (!root) {
      root = document.createElement('html');
      for (const n of nodes) root.appendChild(n);
    }
    if (!__tags(root, 'head')[0]) root.insertBefore(document.createElement('head'), root.firstChild);
    let body = __tags(root, 'body')[0];
    if (!body) {
      body = document.createElement('body');
      // Anything the markup put outside head is body content.
      const head = __tags(root, 'head')[0];
      for (const n of root.childNodes.slice ? __s_slice(root.childNodes) : Array.from(root.childNodes)) {
        if (n !== head) { root.removeChild(n); body.appendChild(n); }
      }
      root.appendChild(body);
    }
    document.__ptKids = [];
    document.__ptDocEl = null;
    // Policy before attaching the tree: scripts run on attach.
    __pt_cspFromMeta(root);
    document.appendChild(root);
    document.__ptDocEl = root;
    document.__ptReady = 'complete';
    // Markup scripts run here and now, in this window.
    for (const el of __tags(root, 'script')) {
      try { el.__ptRunScript(); } catch (e) {}
    }
    return document;
  };

  globalThis.__pt_installDocument = (tree, dt, markup) => {
    if (typeof markup === 'string') { try { Object.defineProperty(document, '__ptMarkup', { value: markup, configurable: true, writable: true }); } catch (e) {} }
    document.__ptKids = [];
    document.__ptDocEl = null;
    document.__ptCurScript = null;
    // `<!DOCTYPE html>` is a node, the document's first child, not a flag.
    document.__ptDoctype = null;
    if (dt) {
      // `Object.prototype.toString.call(doctype)` must be `[object DocumentType]`.
      try {
        if (globalThis.DocumentType && !Object.getOwnPropertyDescriptor(DocumentType.prototype, Symbol.toStringTag)) {
          Object.defineProperty(DocumentType.prototype, Symbol.toStringTag, { value: 'DocumentType', configurable: true });
        }
      } catch (e) {}
      const node = Object.create((globalThis.DocumentType && DocumentType.prototype) || Object.prototype);
      Object.defineProperty(node, '__ptE', { value: {}, enumerable: false, writable: true });
      for (const [k, v] of [['name', String(dt.name || 'html')], ['publicId', String(dt.publicId || '')],
                            ['systemId', String(dt.systemId || '')], ['nodeName', String(dt.name || 'html')],
                            ['nodeType', 10], ['nodeValue', null], ['textContent', null],
                            ['ownerDocument', document], ['parentNode', document], ['childNodes', []]]) {
        Object.defineProperty(node, k, { get: () => v, configurable: true });
      }
      document.__ptDoctype = node;
      document.__ptKids.push(node);
    }
    if (tree && tree.k === 'e') {
      const html = buildNode(document, tree);
      __pt_cspFromMeta(html);
      document.appendChild(html);
      document.__ptDocEl = html;
    }
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
      if (src) { let abs = String(src); try { abs = new URL(src, (globalThis.location && location.href) || undefined).href; } catch (e) {} return __pt_cspBlocksScriptUrl(el, abs); }
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
        try { if (src) src = new URL(src, location.href).href; } catch (e) {}
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
  globalThis.__pt_finishLoad = () => {
    // readyState changes are visible: Chrome fires `readystatechange` at each
    // step.
    const setReadyState = (v) => {
      document.__ptReady = v;
      try { document.dispatchEvent(__ptTrust(new Event('readystatechange'))); } catch (e) {}
    };
    // Parsing may have finished earlier, before deferred scripts.
    if (document.__ptReady === 'loading') { __ptMark('interactive'); setReadyState('interactive'); }
    __ptMark('dclStart');
    // Lifecycle events come from the browser: `e.isTrusted` is true, and
    // pages check it first.
    const dcl = __ptTrust(new Event('DOMContentLoaded', { bubbles: true }));
    document.dispatchEvent(dcl);
    // The event bubbles from document to window, where it is most often
    // listened for: Turnstile's api.js sets up auto-render via
    // `window.addEventListener('DOMContentLoaded', …)`. Window and document are
    // separate targets here, so dispatch it on the window explicitly.
    try {
      if (globalThis.dispatchEvent) {
        try { dcl.target = document; dcl.currentTarget = globalThis; } catch (e) {}
        globalThis.dispatchEvent(dcl);
      }
    } catch (e) {}
    __ptMark('dclEnd');
    __ptMark('complete');
    setReadyState('complete');
    __ptMark('loadStart');
    const load = __ptTrust(new Event('load'));
    globalThis.dispatchEvent && globalThis.dispatchEvent(load);
    // In Chrome `load` reaches the document and the body too.
    try { document.dispatchEvent(__ptTrust(new Event('load'))); } catch (e) {}
    __ptMark('loadEnd');
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
    else if (v.nodeType === 1) { subtype = 'node'; description = v.localName || 'element'; }
    else if (v.nodeType) { subtype = 'node'; description = __s_toLowerCase(v.nodeName || 'node'); }
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
      childNodeCount: (n.__ptKids || []).length, attributes: attrs
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
  };
  let __layoutSeq = 0;      // bumped on every DOM mutation
  let __layoutBuilt = -1;   // __layoutSeq the current boxes were built at
  let __rows = [];          // elements in paint order
  let __boxes = [];         // same, for hit testing
  let __mouseDownEl = null;
  let __hoverEl = null; // element the pointer is currently over

  function __markDirty() {
    __layoutSeq++;
    // Indexed window properties track frames: one per frame in the tree, so
    // mutations change them.
    if (globalThis.__pt_syncFrameSlots) { try { __pt_syncFrameSlots(); } catch (e) {} }
  }

  // --- MutationObserver ---------------------------------------------------
  // A stub that never fires is worse than none: a page waiting on a mutation
  // simply stops, with no error to explain it. Records are collected on the same
  // hooks that already mark the tree dirty and delivered in a microtask, as the
  // spec requires (callbacks must not run inside the mutation itself).
  const __observers = [];
  let __moScheduled = false;

  function __moDeliver() {
    __moScheduled = false;
    for (const o of __observers) {
      if (!o.records.length) continue;
      const batch = o.records.splice(0);
      try { o.cb(batch, o.api); } catch (e) {}
    }
  }

  function __moWatches(entry, rec) {
    if (entry.target === rec.target) return true;
    return !!entry.opts.subtree && entry.target.contains && entry.target.contains(rec.target);
  }

  function __moWants(entry, rec) {
    if (rec.type === 'childList') return !!entry.opts.childList;
    if (rec.type === 'attributes') {
      if (!entry.opts.attributes) return false;
      const filter = entry.opts.attributeFilter;
      return !filter || filter.some(a => __s_toLowerCase(String(a)) === rec.attributeName);
    }
    return !!entry.opts.characterData;
  }

  function __mutation(rec) {
    if (!__observers.length) return;
    let queued = false;
    for (const o of __observers) {
      if (!o.entries.some(e => __moWatches(e, rec) && __moWants(e, rec))) continue;
      o.records.push(rec);
      queued = true;
    }
    if (queued && !__moScheduled) {
      __moScheduled = true;
      queueMicrotask(__moDeliver);
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
      const state = { cb, entries: [], records: [], api: this };
      __observers.push(state);
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target, opts) {
      opts = opts || {};
      // The spec default: with neither childList nor attributes nor
      // characterData asked for, this is a TypeError, not a silent no-op.
      if (!opts.childList && !opts.attributes && !opts.characterData && !opts.attributeFilter) {
        throw __pt_mkErr(TypeError, "Failed to execute 'observe' on 'MutationObserver': The options object must set at least one of 'attributes', 'characterData', or 'childList' to true.");
      }
      if (opts.attributeFilter) opts.attributes = true;
      this.__ptState.entries.push({ target, opts });
    }
    disconnect() { this.__ptState.entries = []; this.__ptState.records = []; }
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
    const ev = { type: ok ? 'load' : 'error', target: el, currentTarget: el, isTrusted: true };
    // dispatchEvent calls `on…` itself; calling it separately fires twice.
    try { el.dispatchEvent && el.dispatchEvent(ev); } catch (e) {}
  };

  // Tear down a frame whose element left the document, and let the element be
  // connected again later as a fresh one.
  const __ptDisconnectFrame = (el) => {
    const id = el.__ptFrameId;
    if (!id) return;
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
  };

  globalThis.__pt_frameFailed = (id) => {
    const st = __frames.get(id);
    if (!st) return;
    __frames.delete(id);
    const ev = { type: 'error', target: st.el, currentTarget: st.el, isTrusted: true };
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
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
    // `window.name` is the element's `name`: reCAPTCHA's checkbox frame derives
    // its challenge frame's name from its own and looks it up in `parent.frames`.
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
    if (!((1 << (node.nodeType - 1)) & walker.__ptShow)) return FILTER_SKIP;
    const f = walker.__ptFilter;
    if (!f) return FILTER_ACCEPT;
    const v = typeof f === 'function' ? f(node) : (f.acceptNode ? f.acceptNode(node) : FILTER_ACCEPT);
    return v === undefined || v === null ? FILTER_ACCEPT : v;
  };

  // The node after `node` in document order, without leaving `root`.
  const __ptFollowing = (node, root, skipChildren) => {
    if (!skipChildren && node.__ptKids && node.__ptKids.length) return node.__ptKids[0];
    for (let n = node; n && n !== root; n = n.parentNode) {
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
          node = node.parentNode;
          if (!node || node === this.__ptRoot) return null;
        }
        if (__ptVerdict(this, node) === FILTER_ACCEPT) { this.__ptCur = node; return node; }
      }
      return null;
    }
    parentNode() {
      for (let n = this.__ptCur; n && n !== this.__ptRoot; ) {
        n = n.parentNode;
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
      setStartBefore(n) { start = n.parentNode || n; startOff = 0; },
      setStartAfter(n) { start = n.parentNode || n; startOff = 0; },
      setEndBefore(n) { end = n.parentNode || n; endOff = 0; },
      setEndAfter(n) { end = n.parentNode || n; endOff = 0; },
      selectNode(n) { start = end = n.parentNode || n; startOff = 0; endOff = 0; },
      selectNodeContents(n) { start = end = n; startOff = 0; endOff = (n.childNodes || []).length; },
      collapse(toStart) { if (toStart) { end = start; endOff = startOff; } else { start = end; startOff = endOff; } },
      cloneRange() { const c = __range(); c.setStart(start, startOff); c.setEnd(end, endOff); return c; },
      detach() {},
      toString() { return ''; },
      // Pages measure text through a range (second only to `measureText`).
      // Chrome returns one rect per line, which shows how the text wrapped.
      getClientRects() {
        const node = start;
        const el = node && node.nodeType === ELEMENT_NODE ? node
                 : (node && node.parentNode) || null;
        const b = el && el.nodeType === ELEMENT_NODE ? __boxOf(el) : null;
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
          if (this.__ptLoadImage) this.__ptLoadImage();
        },
        enumerable: true, configurable: true,
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
  const __IFACE = {
    a: 'HTMLAnchorElement', area: 'HTMLAreaElement', audio: 'HTMLAudioElement',
    base: 'HTMLBaseElement', body: 'HTMLBodyElement', br: 'HTMLBRElement',
    button: 'HTMLButtonElement', canvas: 'HTMLCanvasElement', data: 'HTMLDataElement',
    datalist: 'HTMLDataListElement', dialog: 'HTMLDialogElement', div: 'HTMLDivElement',
    dl: 'HTMLDListElement', embed: 'HTMLEmbedElement', fieldset: 'HTMLFieldSetElement',
    form: 'HTMLFormElement', head: 'HTMLHeadElement', hr: 'HTMLHRElement',
    html: 'HTMLHtmlElement', iframe: 'HTMLIFrameElement', img: 'HTMLImageElement',
    input: 'HTMLInputElement', label: 'HTMLLabelElement', legend: 'HTMLLegendElement',
    li: 'HTMLLIElement', link: 'HTMLLinkElement', map: 'HTMLMapElement',
    menu: 'HTMLMenuElement', meta: 'HTMLMetaElement', meter: 'HTMLMeterElement',
    object: 'HTMLObjectElement', ol: 'HTMLOListElement', optgroup: 'HTMLOptGroupElement',
    option: 'HTMLOptionElement', output: 'HTMLOutputElement', p: 'HTMLParagraphElement',
    picture: 'HTMLPictureElement', pre: 'HTMLPreElement', progress: 'HTMLProgressElement',
    q: 'HTMLQuoteElement', script: 'HTMLScriptElement', select: 'HTMLSelectElement',
    slot: 'HTMLSlotElement', source: 'HTMLSourceElement', span: 'HTMLSpanElement',
    style: 'HTMLStyleElement', table: 'HTMLTableElement', tbody: 'HTMLTableSectionElement',
    td: 'HTMLTableCellElement', template: 'HTMLTemplateElement', textarea: 'HTMLTextAreaElement',
    tfoot: 'HTMLTableSectionElement', th: 'HTMLTableCellElement', thead: 'HTMLTableSectionElement',
    title: 'HTMLTitleElement', tr: 'HTMLTableRowElement', track: 'HTMLTrackElement',
    ul: 'HTMLUListElement', video: 'HTMLVideoElement',
  };
  const __tagFor = (el) => {
    const local = el.__ptLocal || '';
    if (__IFACE[local]) return __IFACE[local];
    // A dashed name is a custom element (HTMLElement); an unknown single-word
    // tag is HTMLUnknownElement.
    if (__s_indexOf(local, '-') > 0) return 'HTMLElement';
    return /^(abbr|address|article|aside|b|bdi|bdo|cite|code|dd|dfn|dt|em|figcaption|figure|footer|h1|h2|h3|h4|h5|h6|header|hgroup|i|ins|del|kbd|main|mark|nav|noscript|rp|rt|ruby|s|samp|section|small|strong|sub|summary|sup|time|u|var|wbr|details|blockquote|caption|colgroup|col)$/.test(local)
      ? 'HTMLElement' : 'HTMLUnknownElement';
  };
  for (const [C, name] of [[Node, 'Node'], [Element, 'Element'], [Text, 'Text'], [Comment, 'Comment'],
    [Document, 'Document'], [DocumentFragment, 'DocumentFragment'], [ShadowRoot, 'ShadowRoot']]) {
    if (!C) continue;
    try {
      // The prototype itself gets its own name (`[object Element]`), instances
      // the tag's interface name.
      Object.defineProperty(C.prototype, Symbol.toStringTag, name
        ? { value: name, configurable: true }
        : { get: function () { if (this === C.prototype) return C === Element ? 'Element' : 'Node'; return this.nodeType === ELEMENT_NODE ? __tagFor(this) : 'Node'; }, configurable: true });
    } catch (e) {}
  }

  // ChildNode: `after`, `before`, `replaceWith` — on elements they were
  // name-only stubs that did nothing, so a page that moved nodes with them
  // (jQuery's `replaceWith` falls through to them in places) kept its DOM as is.
  // Strings become text nodes; the anchor is the nearest sibling not among the
  // nodes being inserted, as the DOM standard's "viable sibling" rule says.
  const __asNodes = (ns) => ns.map((n) => (typeof n === 'string' ? new Text(n) : n));
  const __afterSelf = function after(...ns) {
    const p = this.parentNode; if (!p) return;
    let ref = this.nextSibling; while (ref && __s_includes(ns, ref)) ref = ref.nextSibling;
    for (const n of __asNodes(ns)) p.insertBefore(n, ref);
  };
  const __beforeSelf = function before(...ns) {
    const p = this.parentNode; if (!p) return;
    let prev = this.previousSibling; while (prev && __s_includes(ns, prev)) prev = prev.previousSibling;
    const ref = prev ? prev.nextSibling : p.firstChild;
    for (const n of __asNodes(ns)) p.insertBefore(n, ref);
  };
  const __replaceSelf = function replaceWith(...ns) {
    const p = this.parentNode; if (!p) return;
    let ref = this.nextSibling; while (ref && __s_includes(ns, ref)) ref = ref.nextSibling;
    const nodes = __asNodes(ns);
    if (this.parentNode === p && !__s_includes(nodes, this)) p.removeChild(this);
    for (const n of nodes) p.insertBefore(n, ref);
  };
  for (const C of [Element, Text, Comment]) {
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
    if (__UNRENDERED.has(el.tagName)) return true;
    if (__noneBySheet.has(el)) return true;
    if (el.hasAttribute && __ptHasA(el, 'hidden')) return true;
    // A hidden input takes no space, nor a line.
    if (el.tagName === 'INPUT' && /^hidden$/i.test(__ptGetA(el, 'type') || '')) return true;
    const s = el.style;
    if (s && __s_toLowerCase(String(s.display || '')) === 'none') return true;
    return false;
  }

  function __isHiddenEl(el) {
    if (__isUnboxed(el)) return true;
    if (__hiddenBySheet.has(el)) return true;
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
  function __styleTouch(node) {
    if (__styleAllStale || !node) return;
    const root = node.parentNode || node;
    if (__styleTouched.length >= 2000) { __styleAllStale = true; __styleTouched = []; return; }
    __styleTouched.push(root);
  }
  const __STATE_PSEUDO = /:(checked|indeterminate|valid|invalid|user-valid|user-invalid|in-range|out-of-range|placeholder-shown)\b/i;
  let __styleWorld = '';
  let __styleActive = null;
  // At the start of a pass: drop what mutations since the last one reached.
  function __styleRevalidate() {
    __stylePass = new WeakMap();
    __styleVolatile = new WeakSet();
    if (__styleRulesSeen !== __rules || __rules.__ptHasHas) __styleAllStale = true;
    const doc = globalThis.document;
    let hash = '';
    try { hash = String(globalThis.location && globalThis.location.hash || ''); } catch (e) {}
    const world = hash + '|' + __customs.size;
    if (world !== __styleWorld || (doc && doc.__ptActive !== __styleActive)) __styleAllStale = true;
    __styleWorld = world;
    __styleActive = doc ? doc.__ptActive : null;
    __styleRulesSeen = __rules;
    if (__styleAllStale) {
      __styleCache = new WeakMap();
      __styleTouched = [];
      __styleAllStale = false;
      return;
    }
    const drop = (n) => {
      __styleCache.delete(n);
      for (const k of (n.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) drop(k);
      if (n.__ptShadow) for (const k of (n.__ptShadow.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) drop(k);
    };
    for (const r of __styleTouched) drop(r);
    __styleTouched = [];
  }
  // Font size and inherited values walk the ancestors and are asked many
  // times per pass; cache them for the cascade's lifetime.
  let __passFont = new WeakMap();
  let __passInherit = new WeakMap();
  let __passCustom = new WeakMap();
  let __hiddenBySheet = new WeakSet();
  let __noneBySheet = new WeakSet();

  // Rules of one tree: its stylesheets flattened into a list. Separate because
  // there can be more than one document (see `__rulesFor`).
  function __gatherRules(docEl, out) {
    const state = { order: out.length };
    const take = (root, rules) => {
      for (const r of rules || []) {
        if (r.type === 4 || r.type === 12) {          // @media / @supports
          if (r.type !== 4 || __mediaApplies(r.conditionText)) take(root, r.cssRules);
          continue;
        }
        if (r.type !== 1 || !r.selectorText) continue;
        for (const one of __selSplit(r.selectorText)) {
          const sel = __s_trim(one);
          if (!sel) continue;
          out.push({ root, sel, spec: __specificity(sel), order: state.order++, rule: r });
        }
      }
    };
    const sheetsOf = (node, root) => {
      for (const n of (node.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if ((n.tagName === 'STYLE' || (n.tagName === 'LINK' && n.__ptSheetText)) && n.sheet) {
          take(root, n.sheet.cssRules);
        }
        if (n.__ptShadow) sheetsOf(n.__ptShadow, n.__ptShadow);
        sheetsOf(n, root);
      }
    };
    sheetsOf(docEl, docEl);
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
    let m = /#([\w-]+)/.exec(flat);
    if (m) return 'i' + m[1];
    m = /\.([\w-]+)/.exec(flat);
    if (m) return 'c' + m[1];
    m = /^([a-zA-Z][\w-]*)/.exec(flat);
    if (m) return 't' + __s_toLowerCase(m[1]);
    return null;
  }
  const __ruleIndexes = new WeakMap();
  function __ruleIndex(rules) {
    let ix = __ruleIndexes.get(rules);
    if (ix && ix.n === rules.length) return ix;
    ix = { n: rules.length, keyed: new Map(), any: [] };
    for (const r of rules) {
      const k = __ruleKey(r.sel);
      if (k == null) { ix.any.push(r); continue; }
      let list = ix.keyed.get(k);
      if (!list) ix.keyed.set(k, (list = []));
      list.push(r);
    }
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
      const p = n.parentNode;
      if (!p) return n.nodeType === 11 && n.__ptHost ? n : (n.ownerDocument && n.ownerDocument.documentElement) || n;
      if (p.nodeType === 11 && p.__ptHost) return p;
      n = p;
    }
    return null;
  }
  function __candidateRules(el) {
    const ix = __ruleIndex(__rulesFor(el.ownerDocument));
    const root = __treeRootOf(el);
    const docEl = el.ownerDocument && el.ownerDocument.documentElement;
    const inScope = (r) => !r.root || r.root === root || (root === docEl && r.root === docEl) || (root && root.nodeType !== 11 && r.root && r.root.nodeType !== 11);
    const out = ix.any.filter(inScope);
    const add = (k) => { const l = ix.keyed.get(k); if (l) for (const r of l) if (inScope(r)) out.push(r); };
    add('t' + __s_toLowerCase(String(el.localName || '')));
    const id = __ptGetA(el, 'id');
    if (id) add('i' + id);
    const cls = __ptGetA(el, 'class');
    if (cls) {
      const seen = new Set();
      for (const c of __s_split(cls, /[\t\n\f\r ]+/)) if (c && !seen.has(c)) { seen.add(c); add('c' + c); }
    }
    return out;
  }

  /// A rule's declarations as written.
  function __ruleMap(rr) {
    const rule = rr.rule;
    if (!rule) return null;
    if (rule.__ptDecls) return rule.__ptDecls;
    const d = rule.style;
    const raw = d && __declRaw.get(d);
    return raw ? raw() : null;
  }

  function __rulesFor(doc) {
    if (!doc || doc === globalThis.document) return __rules;
    let hit = __foreignRules.get(doc);
    if (hit) return hit;
    hit = doc.documentElement ? __gatherRules(doc.documentElement, []) : [];
    __foreignRules.set(doc, hit);
    return hit;
  }

  function __collectHidden() {
    __rules = [];
    __passBloom = new WeakMap();
    __passFont = new WeakMap();
    __passInherit = new WeakMap();
    __passCustom = new WeakMap();
    __hiddenBySheet = new WeakSet();
    __noneBySheet = new WeakSet();
    __foreignRules = new WeakMap();
    const doc = globalThis.document;
    if (!doc || !doc.documentElement) return;
    __rules = __gatherRulesCached(doc.documentElement);
    __styleRevalidate();
    // Hiding is collected in the same pass; it is just another declaration.
    // One walk per tree, testing only the hiding rules an element's keys and
    // ancestors allow: the same sets as querying each rule over the tree.
    const byRoot = new Map();
    for (const r of __rules) {
      const d = __ruleMap(r);
      if (!d) continue;
      const disp = __s_toLowerCase(String(d.get('display') || ''));
      const vis = __s_toLowerCase(String(d.get('visibility') || ''));
      if (disp !== 'none' && vis !== 'hidden' && vis !== 'collapse') continue;
      let list = byRoot.get(r.root);
      if (!list) byRoot.set(r.root, (list = []));
      list.push({ r, none: disp === 'none' });
    }
    for (const [root, list] of byRoot) {
      const keyed = new Map(), any = [];
      for (const h of list) {
        const k = __ruleKey(h.r.sel);
        if (k == null) { any.push(h); continue; }
        let l = keyed.get(k);
        if (!l) keyed.set(k, (l = []));
        l.push(h);
      }
      const ctx = { scope: root };
      const test = (e, h) => {
        const r = h.r;
        try {
          if (r.__ptSel === undefined) r.__ptSel = __selCompiled(r.sel) || null;
          if (!r.__ptSel || !__bloomMayMatch(r.__ptSel, __ancBloom(e)) || !__selAny(r.__ptSel, e, ctx)) return;
        } catch (err) { return; }
        __hiddenBySheet.add(e);
        if (h.none) __noneBySheet.add(e);
      };
      const byKey = (e, k) => { const l = keyed.get(k); if (l) for (const h of l) test(e, h); };
      walk(root, (e) => {
        for (const h of any) test(e, h);
        if (!keyed.size) return;
        byKey(e, 't' + __s_toLowerCase(String(e.localName || '')));
        const id = __ptGetA(e, 'id');
        if (id) byKey(e, 'i' + id);
        const set = __ptClassSet(e);
        if (set) for (const c of set) if (c) byKey(e, 'c' + c);
      });
    }
  }

  // The rule list is rebuilt only when a stylesheet changed: every CSSOM
  // change replaces a sheet's `cssRules`, and `@media` follows the viewport.
  let __gatherKey = null, __gatherHit = null;
  function __gatherRulesCached(docEl) {
    const key = [docEl, LAYOUT.W, LAYOUT.H];
    const scan = (node, root) => {
      for (const n of (node.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if ((n.tagName === 'STYLE' || (n.tagName === 'LINK' && n.__ptSheetText)) && n.sheet) key.push(root, n.sheet.cssRules);
        if (n.__ptShadow) scan(n.__ptShadow, n.__ptShadow);
        scan(n, root);
      }
    };
    scan(docEl, docEl);
    const old = __gatherKey;
    if (old && old.length === key.length && old.every((v, i) => v === key[i])) return __gatherHit;
    __gatherKey = key;
    __gatherHit = __gatherRules(docEl, []);
    __gatherHit.__ptHasHas = __gatherHit.some((r) => /:has\(/i.test(r.sel));
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
  function __cascadeFor(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return new Map();
    const hit = __styleCache.get(el) || __stylePass.get(el);
    if (hit) return hit;
    // State-dependent ancestors make this one state-dependent too.
    let volatile = el.ownerDocument !== globalThis.document;
    const up = el.parentNode;
    if (!volatile && up && up.nodeType === ELEMENT_NODE) { __cascadeFor(up); volatile = __styleVolatile.has(up); }
    const out = new Map();
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
    const won = [];
    const bloom = __ancBloom(el);
    for (const r of __candidateRules(el)) {
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
    won.sort((a, b) => (a.spec - b.spec) || (a.order - b.order));
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
    const noteAll = (d) => {
      const raw = __declRaw.get(d);
      if (raw) { const m = raw(); for (const [n, v] of m) note(n, String(__cssPreciseGet(m, n))); return; }
      for (let i = 0; i < d.length; i++) {
        const n = d.item(i);
        note(n, d.getPropertyValue(n));
      }
    };
    for (const r of won) {
      const m = __ruleMap(r);
      if (m) for (const [n, v] of m) note(n, String(v));
    }
    const own = el.style;
    if (own) noteAll(own);
    const vars = __customsFor(el, mine);
    // `inherit` takes the parent's cascaded value; `initial` and `unset` act
    // as if unset (`* { box-sizing: inherit }` must propagate `border-box`).
    const parentOf = () => {
      const p = el.parentNode;
      return p && p.nodeType === ELEMENT_NODE ? __cascadeFor(p) : null;
    };
    for (let k = 0; k < decls.length; k++) {
      const v = __s_toLowerCase(__s_trim(String(decls[k][1])));
      if (v === 'initial' || v === 'unset' || v === 'revert' || v === 'revert-layer') { decls[k][1] = null; continue; }
      if (v !== 'inherit') continue;
      const pc = parentOf();
      const got = pc ? pc.get(decls[k][0]) : undefined;
      decls[k][1] = got != null ? got : null;
    }
    for (const [n, v] of decls) {
      if (v == null) { out.delete(n); continue; }
      if (__s_indexOf(v, 'var(') < 0) { take(n, v); continue; }
      // A failed substitution makes the declaration invalid: as if not written.
      const sub = __ptSubstVars(v, vars);
      if (sub != null) take(n, sub);
    }
    if (volatile) { __styleVolatile.add(el); __stylePass.set(el, out); } else __styleCache.set(el, out);
    return out;
  }

  /// Element custom properties: own over inherited. Kept as a prototype chain,
  /// not a copy (hundreds at the root, thousands of nodes).
  function __customsFor(el, mine) {
    const hit = __passCustom.get(el);
    if (hit) return hit;
    const parent = el.parentNode && el.parentNode.nodeType === ELEMENT_NODE ? el.parentNode
      : (el.parentNode && el.parentNode.host) || null;
    let base = null;
    if (parent) { __cascadeFor(parent); base = __passCustom.get(parent) || null; }
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

  function __lengthPx(raw, fs, base) {
    if (raw == null) return null;
    const v = __s_trim(String(raw));
    let m;
    if ((m = /^(-?(?:\d+\.?\d*|\.\d+))([a-z%]*)$/i.exec(v))) {
      const u = __s_toLowerCase(m[2]);
      const px = __unitPx(parseFloat(m[1]), u, fs, base);
      if (px == null) return null;
      // Viewport units and percentages are kept at 1/64 px precision.
      return u === '%' || /v/.test(u) ? Math.round(px * 64) / 64 : px;
    }
    if (__CALC_FN.test(v)) {
      const px = __ptCalcPx(v, fs, base);
      return px == null ? null : Math.round(px * 64) / 64;
    }
    return null;
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
  const __widths = new Map();
  // SVG whitespace collapses: newlines dropped, tabs become spaces, runs
  // squeezed, ends trimmed. `<text>  ii  </text>` measures as "ii".
  const __svgText = (el) => __s_trim(__s_replace(__s_replace(__s_replace(String((el && el.textContent) || ''), /[\r\n]/g, ''), /\t/g, ' '), / +/g, ' '));

  function __textMetrics(text, fs, family, bold, italic) {
    const t = String(text);
    const key = fs + '|' + (family || 'sans-serif') + '|' + (bold ? 1 : 0) + (italic ? 1 : 0) + '|' + t;
    const hit = __widths.get(key);
    if (hit !== undefined) return hit;
    let m = null;
    if (typeof __pt_canvasMeasureText === 'function') {
      try { m = __pt_canvasMeasureText(t, fs, family || 'sans-serif', !!bold, !!italic); }
      catch (e) {}
    }
    if (!m) m = [t.length * fs * 0.5, 0, t.length * fs * 0.5, fs * 0.9, fs * 0.2, fs * 0.9, fs * 0.2, fs * 1.15];
    if (__widths.size > 20000) __widths.clear();
    __widths.set(key, m);
    return m;
  }

  function __textWidth(text, fs, family, bold, italic) {
    // Text width rounds up to 1/64 px, like Chrome's LayoutUnit: flooring
    // wrapped a word in a column shrunk to its text.
    const w = __textMetrics(text, fs, family, bold, italic)[0] || 0;
    return Math.ceil(w * 64 - 1e-6) / 64;
  }

  // Word wrapping: greedy, at spaces; the trailing space does not count
  // toward the line width, as in Chrome.
  function __wrapLines(text, maxWidth, fs, family, bold) {
    const words = __s_split(String(text), ' ').filter((w) => w.length);
    const out = [];
    if (!words.length) return out;
    if (!(maxWidth > 0)) {
      const all = words.join(' ');
      return [{ text: all, width: Math.round(__textWidth(all, fs, family, bold, false) * 64) / 64 }];
    }
    let line = '';
    for (const w of words) {
      const next = line ? line + ' ' + w : w;
      const width = __textWidth(next, fs, family, bold, false);
      if (line && width > maxWidth) {
        out.push({ text: line, width: __textWidth(line, fs, family, bold, false) });
        line = w;
      } else {
        line = next;
      }
    }
    if (line) out.push({ text: line, width: __textWidth(line, fs, family, bold, false) });
    // Line widths are kept in 1/64 px too.
    for (const l of out) l.width = Math.round(l.width * 64) / 64;
    return out;
  }

  const __OWN_TEXT = (el) => {
    let t = '';
    for (const c of (el.__ptKids || [])) if (c.nodeType === TEXT_NODE) t += c.data || '';
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

  function __uaMargin(tag, fs) {
    const px = UA_MARGIN_PX[tag];
    if (px) return px;
    const em = UA_MARGIN[tag];
    return em ? [em[0] * (fs || 16), em[1]] : null;
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
    if (depth > 40 || !el || el.nodeType !== ELEMENT_NODE || __isUnboxed(el)) return 0;
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = __s_toLowerCase(el.localName || '');
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
      if (c.nodeType !== ELEMENT_NODE || __isUnboxed(c)) continue;
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
    const tag = __s_toLowerCase(el.localName || '');
    const d = __s_toLowerCase(String(__cascadeFor(el).get('display') || CS_DISPLAY[tag] || 'block'));
    return /^inline(-block|-flex|-grid|-table)?$/.test(d);
  }

  // Atomic inline: a box placed whole on the line (`inline-block`, image,
  // input). A plain `<span>` is not: it flows and takes its font's height.
  const __ATOMIC_TAGS = new Set(['img', 'input', 'button', 'select', 'textarea', 'svg',
    'canvas', 'video', 'audio', 'object', 'embed', 'iframe', 'meter', 'progress']);
  function __isAtomicInline(el) {
    const tag = __s_toLowerCase(el.localName || '');
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
      const kids = (el.__ptKids || []).filter((k) => k.nodeType === ELEMENT_NODE);
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

  // Move an already laid-out box with everything inside it.
  function __ptShiftBox(el, x, y) {
    const b = el.__ptBox;
    if (!b) return;
    const dx = x - b.x, dy = y - b.y;
    if (!dx && !dy) return;
    // A moved box is a new object: layout results are kept by reference
    // (see `__layoutOne`) and must not change under them.
    const walk = (node) => {
      const old = node.__ptBox;
      if (old) {
        const nb = node.__ptBox = Object.assign({}, old);
        nb.x += dx; nb.y += dy;
        nb.cx += dx; nb.cy += dy;
        if (nb.lineTop != null) nb.lineTop += dy;
      }
      for (const k of (node.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) walk(k);
      if (node.__ptShadow) {
        for (const k of (node.__ptShadow.__ptKids || [])) if (k.nodeType === ELEMENT_NODE) walk(k);
      }
    };
    walk(el);
  }

  // Flex and grid lay a child out more than once (measure, then place), so
  // nested containers repeated whole subtrees exponentially: 60 s on a store
  // locator page. Within one pass, a call with the same constraints as an
  // earlier one restores that result instead, moved to the new origin. Only
  // moves on the 1/64 px grid: lengths are floored to it, and such a move
  // floors the same as a fresh layout (off-grid positions may differ in the
  // last bit of the double).
  let __layoutMemo = new WeakMap();
  // Frames told their size during this pass, in order: a restored subtree
  // tells them again exactly as a fresh layout would.
  let __tellLog = [];
  function __ptTellLogged(el, box) {
    __tellLog.push([el, box && Object.assign({}, box)]);
    __ptTellFrame(el, box);
  }
  const __on64 = (v) => typeof v === 'number' && Number.isInteger(v * 64) && Math.abs(v) < 2 ** 40;
  function __layoutOne(el, originX, originY, availW, strut, forced) {
    if (forced && forced.cb) return __layoutOneRaw(el, originX, originY, availW, strut, forced);
    const up = el.parentNode;
    const key = availW + '|' + (strut ? strut.line + ',' + strut.asc + ',' + strut.desc : '-') + '|'
      + (forced ? (forced.w === undefined ? 'u' : forced.w) + ',' + (forced.h === undefined ? 'u' : forced.h) + ',' + (forced.block ? 1 : 0) : '-')
      + '|' + (up && up.nodeType === ELEMENT_NODE ? up.__ptDefH : '-');
    let mine = __layoutMemo.get(el);
    const hit = mine && mine.get(key);
    if (hit) {
      const dx = originX - hit.ox, dy = originY - hit.oy;
      if (__on64(dx) && __on64(dy)) {
        for (const [node, box, defH] of hit.snap) {
          let b = box;
          if (dx || dy) {
            b = Object.assign({}, box);
            b.x += dx; b.y += dy; b.cx += dx; b.cy += dy;
            if (b.lineTop != null) b.lineTop += dy;
          }
          node.__ptBox = b;
          node.__ptBoxV = __layoutBuilt;
          node.__ptDefH = defH;
        }
        for (const n of hit.seq) __boxes.push(n);
        for (const [n, b] of hit.tells) __ptTellLogged(n, b);
        return el.__ptBox;
      }
    }
    const start = __boxes.length, tellStart = __tellLog.length;
    const ret = __layoutOneRaw(el, originX, originY, availW, strut, forced);
    const seq = __s_slice(__boxes, start), tells = __s_slice(__tellLog, tellStart);
    const snap = [];
    const seen = new Set();
    for (const n of seq) {
      if (seen.has(n)) continue;
      seen.add(n);
      if (n.__ptBox) snap.push([n, n.__ptBox, n.__ptDefH]);
    }
    if (!mine) __layoutMemo.set(el, (mine = new Map()));
    mine.set(key, { ox: originX, oy: originY, snap, seq, tells });
    return ret;
  }

  function __layoutOneRaw(el, originX, originY, availW, strut, forced) {
    // Document order, not after children: hit testing scans from the end and a
    // deeper element must come after its parent.
    __boxes.push(el);
    const cs = __cascadeFor(el);
    const fs = __usedFontSize(el);
    const tag = __s_toLowerCase(el.localName || '');
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
    const side = (prefix, suffix) => {
      const all = cs.get(prefix);
      const one = ['top', 'right', 'bottom', 'left'].map((k) => len(prefix + '-' + k, availW));
      if (all != null) {
        const parts = __s_split(__s_trim(String(all)), /\s+/);
        const pick = (i) => parts[[0, 1, 2, 3].map((k) => Math.min(k, parts.length - 1))[i]];
        ['top', 'right', 'bottom', 'left'].forEach((k, i) => {
          if (one[i] == null) one[i] = __lengthPx(pick(i), fs, availW);
        });
      }
      return one;
    };
    const rawM = side('margin');
    // An author 0 is a set value: `body { margin: 0 }` must not get the UA 8px.
    const setM = rawM.map((v) => v != null);
    let [mt, mr, mb, ml] = rawM.map((v) => v || 0);
    let [pt_, pr, pb, pl] = side('padding').map((v) => v || 0);
    let [bt, br, bb, bl] = ['top', 'right', 'bottom', 'left']
      .map((k) => len('border-' + k + '-width', availW) || 0);
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

    const uam = __uaMargin(tag, fs);
    if (uam) {
      if (!setM[0] && !setM[2]) { mt = uam[0]; mb = uam[0]; }
      if (!setM[3] && !setM[1]) { ml = uam[1]; mr = uam[1]; }
    }
    const ua = __uaBox(el, tag);
    if (ua) {
      if (!pt_ && !pb && ua.p) { pt_ = ua.p[0]; pb = ua.p[0]; }
      if (!pl && !pr && ua.p) { pl = ua.p[1]; pr = ua.p[1]; }
      if (!bt && !br && !bb && !bl && ua.b) { bt = br = bb = bl = ua.b; }
      if (!setM[0] && !setM[2] && ua.m) { mt = ua.m[0]; mb = ua.m[0]; }
      if (!setM[3] && !setM[1] && ua.m) { ml = ua.m[1]; mr = ua.m[1]; }
    }
    // `box-sizing: border-box`: the size includes padding and border.
    const bbox = /^border-box$/i.test(__s_trim(String(cs.get('box-sizing') || '')));
    const inW = (v) => (v == null ? null : bbox ? Math.max(0, v - pl - pr - bl - br) : v);
    const inH = (v) => (v == null ? null : bbox ? Math.max(0, v - pt_ - pb - bt - bb) : v);
    // Percent heights are relative to the parent's set height; the root's is
    // the viewport.
    const up = el.parentNode;
    // An absolute child resolves percentages against the containing block the
    // parent passed (its padding box), not the page.
    const __cb = (position === 'absolute' || position === 'fixed') && forced && forced.cb ? forced.cb : null;
    const baseH = __cb && __cb.h != null ? __cb.h : (up && up.nodeType === ELEMENT_NODE
      ? (up.__ptDefH != null ? up.__ptDefH : null) : LAYOUT.H);
    if (__cb && __cb.w != null) availW = __cb.w;
    const explicitW = inW(len('width', availW));
    const explicitH = inH(len('height', baseH));
    el.__ptDefH = explicitH;
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
    const boxedKids = kids.filter((c) => c.nodeType === ELEMENT_NODE && !__isUnboxed(c));

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
        lineH = /^[\d.]+$/.test(t) ? parseFloat(t) * fs : /^[\d.]+%$/.test(t) ? parseFloat(t) / 100 * fs : (__lengthPx(t, fs, availW) || fbox.line);
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
      const parentDisp = __s_toLowerCase(String((el.parentNode && el.parentNode.nodeType === ELEMENT_NODE ? __cascadeFor(el.parentNode).get('display') : '') || ''));
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
      if (globalThis.__pt_gridTrace) { try { (globalThis.__pt_parentConsole || console).error('[grid] ' + __ptJSON.stringify({ tag: el.localName, id: el.id, availW, cw, shrinkGrid, forcedW: !!forcedW, explicitW, n, place, widths, totalW, want })); } catch (e) {} }
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

  function __relayout() {
    if (__layoutBuilt === __layoutSeq) return;
    __layoutBuilt = __layoutSeq;
    __collectHidden();
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
    __layoutMemo = new WeakMap();
    __tellLog = [];
    __layoutOne(de, 0, 0, LAYOUT.W);
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
  /// Value of an inherited property: the nearest ancestor that sets it.
  const __inheritedValue = (el, prop) => {
    let own = el && el.nodeType === ELEMENT_NODE ? __passInherit.get(el) : null;
    if (own) {
      const hit = own.get(prop);
      if (hit !== undefined) return hit;
    }
    let out = null;
    for (let e = el && el.parentNode; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
      const raw = __cascadeFor(e).get(prop);
      if (raw != null) { out = __resolveLength(raw, prop, __usedFontSize(e), e); break; }
    }
    if (el && el.nodeType === ELEMENT_NODE) {
      if (!own) { own = new Map(); __passInherit.set(el, own); }
      own.set(prop, out);
    }
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

  // Computed style is expensive and pages ask for it repeatedly; cache it
  // until the next tree mutation.
  const __computedCache = new WeakMap();

  // Whether a node is in the flat tree: a shadow host's child gets there only
  // through a slot of the same name; the rest are hidden and have no style.
  function __inFlatTree(el) {
    let n = el;
    for (let guard = 0; n && guard < 10000; guard++) {
      const p = n.parentNode;
      // The root is a document (the caller checks which one via ownerDocument:
      // in a realm the tree root and the global `document` differ).
      if (!p) return n.nodeType === 9;
      if (p.nodeType === ELEMENT_NODE && p.__ptShadow) {
        const sr = p.__ptShadow;
        const want = n.nodeType === ELEMENT_NODE ? (__ptGetA(n, 'slot') || '') : '';
        let slot = null;
        try { __walkTree(sr, (x) => { if (!slot && x.nodeType === ELEMENT_NODE && x.__ptLocal === 'slot' && (__ptGetA(x, 'name') || '') === want) slot = x; }); } catch (e) {}
        if (!slot) return false;
        n = slot;
        continue;
      }
      if (p.nodeType === 11 && p.__ptHost) { n = p.__ptHost; continue; }
      n = p;
    }
    return false;
  }
  globalThis.__pt_inFlatTree = __inFlatTree;

  globalThis.getComputedStyle = (el, pseudo) => {
    if (el && !pseudo && el.nodeType === ELEMENT_NODE) {
      __relayout();
      const hit = __computedCache.get(el);
      if (hit && hit.at === __layoutBuilt) return hit.style;
    }
    const map = new Map();
    // An element outside the rendered tree has no computed style: Chrome
    // returns '' for every property and `length` 0.
    const connected = !!(el && el.nodeType === ELEMENT_NODE && el.isConnected);
    // A windowless document (DOMParser, createHTMLDocument): empty, length 0.
    // A node in the window but outside the flat tree (unslotted shadow host
    // child): names present, values empty.
    const inView = connected && (!el.ownerDocument || el.ownerDocument === document || !!el.ownerDocument.defaultView);
    if (!connected || !inView) {
      for (const k of CS_ORDER) map.set(k, '');
      return __makeComputed(map, []);
    }
    if (!__inFlatTree(el)) {
      for (const k of CS_ORDER) map.set(k, '');
      const names = [...map.keys()];
      __addShorthands(map);
      return __makeComputed(map, names);
    }
    for (const k of CS_ORDER) map.set(k, CS_BASE[k]);
    const tag = (el && el.localName) || 'div';
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
      __relayout();
      const cascade = el ? __cascadeFor(el) : new Map();
      const fs = el ? __usedFontSize(el) : 16;
      // Inherited values first, then own on top.
      for (const prop of CSS_INHERITED) {
        if (cascade.has(prop)) continue;
        const v = __inheritedValue(el, prop);
        if (v == null) continue;
        const pairs = __ptExpand(prop, v);
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
        map.set(k, __resolveLength(__s_trim(String(raw)), k, fs, el));
      };
      const written = new Set();
      for (const [n, raw] of cascade) {
        const v = __resolveLength(raw, n, fs, el);
        const pairs = __ptExpand(n, v);
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
        const uam = __uaMargin(tag, fs);
        if (uam) {
          for (const [k, v] of [['margin-top', uam[0]], ['margin-bottom', uam[0]],
                                ['margin-left', uam[1]], ['margin-right', uam[1]]]) {
            if (!written.has(k) && map.has(k)) map.set(k, q(v));
          }
        }
        // Chrome prints the used margin, not `auto` (half the free space when
        // centred).
        const ab = __boxOf(el);
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
      // Any sRGB colour is normalised to `rgb(…)`.
      for (const k of map.keys()) {
        if (k !== 'color' && !__s_endsWith(k, '-color')) continue;
        const norm = globalThis.__pt_cssColour && globalThis.__pt_cssColour(map.get(k));
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
        const parent = el.parentNode;
        const pd = parent && parent.nodeType === ELEMENT_NODE
          ? String(__cascadeFor(parent).get('display') || CS_DISPLAY[parent.localName] || '')
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
      // A line-height multiplier is printed in pixels.
      const lh = String(map.get('line-height') || '');
      if (/^[\d.]+$/.test(lh)) {
        const px = parseFloat(lh) * parseFloat(map.get('font-size')) || 0;
        map.set('line-height', (Math.round(px * 1e4) / 1e4) + 'px');
      }
      // Links have a UA default style, visible in computed style.
      if (el.localName === 'a' && __ptHasA(el, 'href')) {
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
      if (el && el.nodeType === ELEMENT_NODE) {
        if (__isUnboxed(el)) map.set('display', 'none');
        const b = __boxOf(el);
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
    if (el && el.nodeType === ELEMENT_NODE) {
      const BLOCKIFY = { inline: 'block', 'inline-block': 'block', 'inline-flex': 'flex', 'inline-grid': 'grid', 'inline-table': 'table', 'inline-flow-root': 'flow-root', 'list-item': null };
      const d = map.get('display');
      const to = BLOCKIFY[d];
      if (to) {
        let why = el.ownerDocument && el === el.ownerDocument.documentElement;
        const pos = map.get('position');
        if (pos === 'absolute' || pos === 'fixed') why = true;
        if (map.get('float') && map.get('float') !== 'none') why = true;
        let p = el.parentNode;
        while (!why && p && p.nodeType === ELEMENT_NODE) {
          const pd = __s_toLowerCase(__s_trim(String(__cascadeFor(p).get('display') || CS_DISPLAY[p.localName] || '')));
          if (pd === 'contents') { p = p.parentNode; continue; }
          if (/^(inline-)?(flex|grid)$/.test(pd)) why = true;
          break;
        }
        if (why) map.set('display', to);
      }
    }
    // Numbers print with six significant digits: `138.828125px` -> `138.828px`.
    for (const k of map.keys()) {
      const v = map.get(k);
      if (typeof v === 'string' && v && /\d/.test(v) && !(__s_charCodeAt(k, 0) === 45 && __s_charCodeAt(k, 1) === 45)) {
        try { map.set(k, __cssNumbers(v)); } catch (e) {}
      }
    }
    const names = [...map.keys()];
    __addShorthands(map);
    // Custom properties are readable via `getPropertyValue('--name')` but not
    // enumerated.
    if (el && el.nodeType === ELEMENT_NODE) {
      const vars = __passCustom.get(el);
      if (vars) for (const k in vars) if (typeof vars[k] === 'string') map.set(k, vars[k]);
    }
    const made = __makeComputed(map, names);
    if (el && !pseudo && el.nodeType === ELEMENT_NODE) {
      try { __computedCache.set(el, { at: __layoutBuilt, style: made }); } catch (e) {}
    }
    return made;
  };

  /// Computed style declaration. `names` is empty when the element is not
  /// rendered: no indexed properties and `length` 0, but the 745 camelCase
  /// names are present either way.
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

  function __makeComputed(map, names) {
    // `[object CSSStyleDeclaration]`, as in Chrome.
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    // The interface stub may lack its name; set it.
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    // Chrome's shape: own properties are indices and camelCase names only;
    // methods and `length` live on the prototype. Dashed names are readable
    // but not own, so a Proxy answers them.
    const decl = Object.create(__inlineStyleProto());
    __cssReaders.set(decl, { computed: true, names, map });
    const own = (name, d) => { try { Object.defineProperty(decl, name, d); } catch (e) {} };
    for (let i = 0; i < names.length; i++) own(String(i), { value: names[i], enumerable: true, configurable: true });
    for (const name of CSS_PROPS) {
      // `webkitBorderAfter` is `-webkit-border-after` (leading dash for vendor
      // names), while `webkitAlignItems` is just another name for
      // `align-items` and returns the same value.
      const plain = __s_toLowerCase(__s_replace(name, /[A-Z]/g, (c) => '-' + __s_toLowerCase(c)));
      const keys = /^(webkit|moz|ms|o)-/.test(plain)
        ? ['-' + plain, plain, __s_replace(plain, /^(webkit|moz|ms|o)-/, '')]
        : [plain];
      // A data property, not an accessor: Chrome's descriptor has `value` and
      // no `get`. The computed snapshot does not change anyway.
      let v = '';
      for (const k of keys) { const got = map.get(k); if (got) { v = got; break; } }
      own(name, { value: v, writable: true, enumerable: true, configurable: true });
    }
    const dashOf = (p) => __s_replace(String(p), /[A-Z]/g, (c) => '-' + __s_toLowerCase(c));
    return __ptProxy(decl, {
      // Only ownKeys: descriptors are already right, and another trap would
      // cost ~1.5 ms per style enumeration.
      ownKeys: (t) => __withEpub(Reflect.ownKeys(t)),
      get: (t, p) => {
        if (typeof p === 'string' && EPUB_SET.has(p)) return undefined;
        if (typeof p === 'string' && !(p in t)) return map.get(__s_toLowerCase(p)) || '';
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
    });
  }

  /// Font size in effect on an element (inherited; `em` resolves against it).
  function __usedFontSize(el) {
    if (el && el.nodeType === ELEMENT_NODE) {
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

  function __usedFontSizeRaw(el) {
    let size = 16;
    const chain = [];
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) chain.push(e);
    // Form controls do not inherit the page font size; the UA gives their own.
    const own = (el && el.localName) || '';
    if (own === 'input' || own === 'button' || own === 'select' || own === 'textarea') {
      size = UA_FORM_FONT;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return size;
    }
    // Monospace text uses 13px, not 16px, so `pre` without its own rule gets
    // 13px margins.
    if (own !== 'textarea' && UA_MONO.has(own)) {
      size = 13;
      const raw = __cascadeFor(el).get('font-size');
      if (raw == null) return size;
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      const raw = __cascadeFor(chain[i]).get('font-size');
      if (raw == null) {
        const f = UA_FONT_SIZE[__s_toLowerCase(chain[i].localName || '')];
        if (f) size *= f;
        continue;
      }
      let v = __s_toLowerCase(__s_trim(String(raw)));
      // `rem` on the root means the initial font size, not its own.
      const e = chain[i];
      if (e.ownerDocument && e === e.ownerDocument.documentElement) v = __s_replace(v, /(\d)rem\b/g, '$1em');
      if (FONT_KEYWORDS[v]) { size = FONT_KEYWORDS[v]; continue; }
      if (v === 'smaller') { size /= 1.2; continue; }
      if (v === 'larger') { size *= 1.2; continue; }
      // `em`, percentages, `calc()` and `clamp()` resolve against the parent's size.
      const px = __lengthPx(v, size, size);
      if (px != null && px >= 0) size = px;
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
    const parent = el && el.parentNode;
    if (!parent || parent.nodeType !== ELEMENT_NODE) return LAYOUT.W;
    const b = parent.__ptBoxV === __layoutBuilt ? parent.__ptBox : null;
    return b ? b.cw : LAYOUT.W;
  }

  function __boxOf(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return null;
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
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
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
    if (!el || el.nodeType !== ELEMENT_NODE) return '';
    // A non-rendered element returns its `textContent`, styles and scripts
    // included: in Chrome `d.style.display='none'; d.innerText` gives
    // ".z{color:red}text".
    if (__isHiddenEl(el)) return el.textContent || '';
    // `innerText` renders only visible content — the text inside <script>/<style>
    // etc. is not rendered, so it must not leak into it (`textContent` includes it).
    if (__INNERTEXT_SKIP.has(el.tagName)) return '';
    let s = '';
    for (const c of el.__ptKids) {
      if (c.nodeType === TEXT_NODE) s += c.data;
      else if (c.nodeType === ELEMENT_NODE && !__isHiddenEl(c)) s += ' ' + __innerText(c);
    }
    return __s_trim(__s_replace(s, /\s+/g, ' '));
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
        if (n.nodeType !== ELEMENT_NODE) continue;
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
              for (let a = n.parentNode; a && a.nodeType === ELEMENT_NODE; a = a.parentNode) {
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
        if (c.nodeType !== ELEMENT_NODE) continue;
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
        if (out || !n || n.nodeType !== ELEMENT_NODE) return;
        if ((n.__ptLocal === 'input' || n.__ptLocal === 'textarea') && /^(cf-turnstile-response|g-recaptcha-response)$/.test(__ptGetA(n, 'name') || '')) { const v = n.value; if (v) out = String(v); }
      });
    } catch (e) {}
    return out;
  };
  // What the page shows in front of the site, for the driver; walks the tree
  // internally so no page API call shows up in the challenge's report.
  globalThis.__pt_gateInfo = () => {
    const out = { title: '', url: '', inter: false, widget: false, recaptcha: false, token: false, datadome: false, orchestrator: false };
    try {
      out.title = String((globalThis.document && document.title) || '');
      out.url = String((globalThis.location && location.href) || '');
      out.inter = /Just a moment/.test(out.title);
      __walkTree(globalThis.document, (n) => {
        if (!n || n.nodeType !== ELEMENT_NODE) return;
        const t = n.__ptLocal;
        if (t === 'iframe' && /challenges\.cloudflare\.com/.test(__ptGetA(n, 'src') || '')) out.widget = true;
        // A reCAPTCHA checkbox (Google's /sorry/ page among others); the invisible
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
    } catch (e) {}
    return __ptJSON.stringify(out);
  };
  globalThis.__pt_frameRectById = (id) => {
    const walk = (n) => {
      for (let c = n.firstChild; c; c = c.nextSibling) {
        if (c.nodeType !== ELEMENT_NODE) continue;
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
    for (let el = __elementFromPoint(x, y); el && el.nodeType === ELEMENT_NODE; el = el.parentNode) {
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
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
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
  // under its centre (reCAPTCHA's footer buttons land below the frame's window).
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
