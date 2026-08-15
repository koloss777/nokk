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

  // Every node in a subtree, shadow trees included. Frames and scripts come to
  // life as part of whatever tree they are inserted with — a widget hands the DOM
  // a finished tree, not a bare element.
  function __walkTree(node, fn) {
    if (!node) return;
    fn(node);
    const kids = node.__ptKids;
    if (kids) for (const c of kids.slice()) __walkTree(c, fn);
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
    if (n.nodeType === ELEMENT_NODE && __customs.has(n.__ptLocal)) {
      if (!n.__ptUpgraded) __customUpgrade(n, __customs.get(n.__ptLocal));
      else __customCallback(n, 'connectedCallback');
    }
  });

  // Массив в обёртке HTMLCollection: length/item/namedItem/итератор, но не Array.
  // Страницы читают `.length` и перебирают — этого достаточно, а `Array.isArray`
  // на настоящей коллекции ложен, как и должно быть.
  function __collection(arr) {
    const list = Object.create(__collectionProto);
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, 'length', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // childNodes отдаёт NodeList, а не массив: `Array.isArray(node.childNodes)`
  // на платформе ложен, и сборщик отпечатков Turnstile метит массив отдельной
  // категорией. Список живой и тождественный самому себе — виджеты сравнивают
  // `a.childNodes === a.childNodes`, — поэтому он кэшируется на узле, а индексы
  // пересобираются при каждом обращении.
  function __nodeList(node) {
    __linkNodeList();
    let list = node.__ptList;
    if (!list) {
      list = Object.create(__nodeListProto);
      Object.defineProperty(node, '__ptList', { value: list, enumerable: false, writable: true });
    }
    const kids = node.__ptKids, prev = list.length | 0;
    for (let i = 0; i < kids.length; i++) list[i] = kids[i];
    for (let i = kids.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, 'length', { value: kids.length, enumerable: false, configurable: true });
    return list;
  }
  // Прототип связывается с интерфейсом NodeList при первом обращении: сам
  // интерфейс появляется позже этого файла, а список создаётся уже на странице.
  const __linkNodeList = () => {
    const I = globalThis.NodeList;
    if (!I || __nodeListProto.__ptLinked) return;
    __nodeListProto.__ptLinked = true;
    for (const k of Reflect.ownKeys(__nodeListProto)) {
      if (k === '__ptLinked') continue;
      Object.defineProperty(I.prototype, k, Object.getOwnPropertyDescriptor(__nodeListProto, k));
    }
    Object.setPrototypeOf(__nodeListProto, I.prototype);
    for (const k of Reflect.ownKeys(__nodeListProto)) {
      if (k !== '__ptLinked') delete __nodeListProto[k];
    }
  };
  const __nodeListProto = {
    get [Symbol.toStringTag]() { return 'NodeList'; },
    item(i) { return this[i] != null ? this[i] : null; },
    forEach(fn, thisArg) { for (let i = 0; i < this.length; i++) fn.call(thisArg, this[i], i, this); },
    *entries() { for (let i = 0; i < this.length; i++) yield [i, this[i]]; },
    *keys() { for (let i = 0; i < this.length; i++) yield i; },
    *values() { for (let i = 0; i < this.length; i++) yield this[i]; },
    [Symbol.iterator]() { return this.values(); },
  };

  const __collectionProto = {
    item(i) { return this[i] != null ? this[i] : null; },
    namedItem(n) {
      for (let i = 0; i < this.length; i++) {
        const e = this[i];
        if (e && (e.id === n || (e.getAttribute && e.getAttribute('name') === n))) return e;
      }
      return null;
    },
    [Symbol.iterator]() { let i = 0; const self = this; return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };

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
      const i = p.__ptKids.indexOf(this); return p.__ptKids[i + 1] || null;
    }
    get previousSibling() {
      const p = this.parentNode; if (!p) return null;
      const i = p.__ptKids.indexOf(this); return p.__ptKids[i - 1] || null;
    }
    hasChildNodes() { return this.__ptKids.length > 0; }
    contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; }
    // Walks out through a shadow host too: a node inside an attached shadow tree
    // is connected, even though the root itself has no parent.
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

    appendChild(child) { return this.insertBefore(child, null); }
    insertBefore(child, ref) {
      if (child.nodeType === DOCUMENT_FRAGMENT_NODE) {
        for (const c of child.__ptKids.slice()) this.insertBefore(c, ref);
        return child;
      }
      if (child.parentNode) child.parentNode.removeChild(child);
      const i = ref ? this.__ptKids.indexOf(ref) : -1;
      if (i < 0) this.__ptKids.push(child); else this.__ptKids.splice(i, 0, child);
      child.parentNode = this;
      __markDirty();
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
      const i = this.__ptKids.indexOf(child);
      if (i < 0) throw new Error('NotFoundError: removeChild');
      const prev = this.__ptKids[i - 1] || null, next = this.__ptKids[i + 1] || null;
      this.__ptKids.splice(i, 1); child.parentNode = null; __markDirty();
      __mutation(__childListRecord(this, [], [child], prev, next));
      // A removed frame is a closed browsing context. Without this its V8 context
      // outlives the element forever — a widget that replaces its iframe on a
      // retry (Turnstile does, repeatedly) would pile them up until the cap. The
      // whole subtree goes, for the same reason it connects as a whole.
      __walkTree(child, (f) => {
        if (f.__ptFrameId) __ptDisconnectFrame(f);
        if (f.__ptUpgraded) __customCallback(f, 'disconnectedCallback');
      });
      return child;
    }
    replaceChild(nw, old) { this.insertBefore(nw, old); return this.removeChild(old); }
    cloneNode(deep) {
      const c = this.__ptShallowClone();
      if (deep) for (const ch of this.__ptKids) c.appendChild(ch.cloneNode(true));
      return c;
    }

    get textContent() {
      // У документа и doctype его нет вовсе — браузер отвечает null, а не
      // склеенным текстом страницы.
      if (this.nodeType === 9 || this.nodeType === 10) return null;
      let s = ''; for (const c of this.__ptKids) s += c.textContent; return s;
    }
    set textContent(v) {
      if (this.nodeType === 9 || this.nodeType === 10) return;
      this.__ptKids = [];
      if (v !== '') this.appendChild(new Text(String(v)));
    }

    // EventTarget
    addEventListener(type, fn, opts) {
      if (!fn) return;
      const cap = !!(opts && (opts === true || opts.capture));
      (this.__ptLis[type] || (this.__ptLis[type] = [])).push({ fn, cap });
    }
    removeEventListener(type, fn, opts) {
      const cap = !!(opts && (opts === true || opts.capture));
      const l = this.__ptLis[type]; if (!l) return;
      this.__ptLis[type] = l.filter(e => !(e.fn === fn && e.cap === cap));
    }
    __ptDispatch(event) {
      event.target = this;
      // Build the ancestor path for capture/bubble.
      const path = []; for (let n = this; n; n = n.parentNode) path.push(n);
      // Capture phase (root -> target), then bubble (target -> root).
      const fire = (node) => {
        const l = node.__ptLis[event.type]; if (!l) return;
        for (const { fn } of l.slice()) {
          if (event.__ptStopImm) break;
          event.currentTarget = node;
          try { fn.call(node, event); } catch (e) { /* page handler threw */ }
        }
      };
      for (let i = path.length - 1; i >= 1; i--) { if (event.__ptStop) break; if (path[i].__ptLis && path[i].__ptLis[event.type]) { event.eventPhase = 1; fireCapture(path[i], event); } }
      event.eventPhase = 2;
      if (!event.__ptStop) fire(this);
      // Обработчик-свойство (`onclick`, `onload`, `onmessage`) — такой же
      // слушатель цели, и вызывает его тот же dispatch, а не вызывающий код.
      if (!event.__ptStopImm) {
        const on = this['on' + event.type];
        if (typeof on === 'function') { event.currentTarget = this; try { on.call(this, event); } catch (e) {} }
      }
      if (event.bubbles) for (let i = 1; i < path.length; i++) { if (event.__ptStop) break; event.eventPhase = 3; fire(path[i]); }
      return !event.defaultPrevented;
    }
  }
  function fireCapture(node, event) {
    const l = node.__ptLis && node.__ptLis[event.type]; if (!l) return;
    for (const e of l.slice()) { if (!e.cap) continue; if (event.__ptStopImm) break; event.currentTarget = node; try { e.fn.call(node, event); } catch (_) {} }
  }

  // В браузере эти три метода живут на `EventTarget.prototype` — один раз, для
  // всех целей, и они же разносят событие по дереву, когда цель в дереве. У нас
  // они стояли на `Node.prototype` (лишние имена там, где браузер их не держит)
  // плюс отдельная копия на EventTarget. Теперь реализация одна, а имена — там,
  // где им положено.
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
      // Без получателя цель — окно: голый `addEventListener(...)` даёт
      // `this === undefined`, и браузер подставляет глобальный объект.
      const self_ = (t) => (t === undefined || t === null ? globalThis : t);
      const proto = ET.prototype;
      for (const [name, fn] of [
        ['addEventListener', function addEventListener(type, fn, opts) {
          const t = self_(this); if (!fn) return;
          const cap = !!(opts && (opts === true || opts.capture));
          const l = store(t); (l[type] = l[type] || []).push({ fn, cap, once: !!(opts && opts.once) });
        }],
        ['removeEventListener', function removeEventListener(type, fn, opts) {
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
      // Узел наследует их оттуда же, откуда и браузерный.
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
  // Имена кодировок Chrome отдаёт каноническими: utf-8 → UTF-8, latin1 →
  // windows-1252. Прочие проходят как есть, в нижнем регистре.
  const __ENCODINGS = {
    'utf-8': 'UTF-8', 'utf8': 'UTF-8', 'unicode-1-1-utf-8': 'UTF-8',
    'iso-8859-1': 'windows-1252', 'latin1': 'windows-1252', 'ascii': 'windows-1252',
    'us-ascii': 'windows-1252', 'windows-1252': 'windows-1252', 'cp1252': 'windows-1252',
    'utf-16': 'UTF-16LE', 'utf-16le': 'UTF-16LE', 'utf-16be': 'UTF-16BE',
  };
  const __normEncoding = (name) => {
    const k = String(name).trim().toLowerCase();
    return __ENCODINGS[k] || k;
  };

  // ChildNode.remove живёт на элементах и текстовых узлах — у документа его нет,
  // и лишнее имя на `document` заметно ровно так же, как недостающее.
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
    set data(v) { this.__ptData = String(v); }
    get nodeName() { return '#text'; }
    get nodeValue() { return this.data; }
    set nodeValue(v) { this.data = String(v); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
    __ptShallowClone() { return new Text(this.data); }
  }
  class Comment extends Node {
    constructor(data) { super(COMMENT_NODE); this.__ptData = String(data); }
    get data() { return this.__ptData; }
    set data(v) { this.__ptData = String(v); }
    get nodeName() { return '#comment'; }
    get nodeValue() { return this.data; }
    get textContent() { return ''; }
    __ptShallowClone() { return new Comment(this.data); }
  }

  // ---- Element --------------------------------------------------------------
  /// A shadow root: a fragment that carries the query surface of an element and
  /// remembers its host, so a subtree can live outside the document tree while
  /// still being connected through it.
  class ShadowRoot extends Node {
    constructor(host, mode) {
      super(DOCUMENT_FRAGMENT_NODE);
      this.__ptHost = host;
      this.__ptMode = mode;
      this.ownerDocument = host.ownerDocument;
    }
    get host() { return this.__ptHost; }
    get mode() { return this.__ptMode; }
    get nodeName() { return '#document-fragment'; }
    get nodeValue() { return null; }
    get textContent() { return this.__ptKids.map(n => n.textContent).join(''); }
    set textContent(v) { this.__ptKids = []; if (v !== '') this.appendChild(new Text(String(v))); }
    get innerHTML() { return this.__ptKids.map(serializeNode).join(''); }
    set innerHTML(html) { this.__ptKids = []; for (const n of parseFragment(String(html))) this.appendChild(n); }
    get children() { return this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE); }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get childElementCount() { return this.children.length; }
    // В браузере это `<body>`, как только тело есть, — не null. И это
    // свойство присваивают (`focus()`), так что одного геттера мало:
    // присваивание в него молча пропадало.
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    get styleSheets() { return []; }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    getElementById(id) { return firstMatch(this, e => e.id === id); }
    getElementsByTagName(t) { const tag = String(t).toUpperCase(); return collect(this, e => t === '*' || e.tagName === tag); }
    getElementsByClassName(c) { const cs = String(c).split(/\s+/).filter(Boolean); return collect(this, e => cs.every(x => e.classList.contains(x))); }
    querySelector(sel) { return query(this, sel)[0] || null; }
    querySelectorAll(sel) { return query(this, sel); }
    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }
    elementFromPoint() { return null; }
  }

  // --- пользовательские элементы -------------------------------------------
  // `customElements` был объектом без методов: `customElements.get` роняло любой
  // бандл, который просто спрашивает, определён ли компонент. Реестр настоящий:
  // определение, обновление уже стоящих в документе узлов и три обратных вызова
  // жизненного цикла.
  const __customs = new Map();          // имя → класс
  const __customPending = new Map();    // имя → { promise, resolve }
  const __customName = (ctor) => {
    for (const [name, C] of __customs) if (C === ctor) return name;
    return null;
  };
  const __customCallback = (el, name, args) => {
    const fn = el[name];
    if (typeof fn === 'function') { try { fn.apply(el, args || []); } catch (e) { /* компонент бросил */ } }
  };
  const __customUpgrade = (el, Ctor) => {
    if (el.__ptUpgraded) return;
    Object.defineProperty(el, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
    // Повторно выполнить тело конструктора над готовым узлом нельзя, поэтому
    // элемент получает прототип класса — методы и обратные вызовы на месте.
    try { Object.setPrototypeOf(el, Ctor.prototype); } catch (e) { return; }
    const watched = Ctor.observedAttributes;
    if (Array.isArray(watched)) {
      for (const a of watched) {
        const v = el.getAttribute(a);
        if (v !== null) __customCallback(el, 'attributeChangedCallback', [a, null, v, null]);
      }
    }
    if (el.isConnected) __customCallback(el, 'connectedCallback');
  };

  class CustomElementRegistry {
    define(name, ctor, options) {
      name = String(name);
      if (!/^[a-z][a-z0-9._]*-[a-z0-9._-]*$/.test(name)) {
        throw new (globalThis.DOMException || Error)(`"${name}" is not a valid custom element name`, 'SyntaxError');
      }
      if (__customs.has(name)) {
        throw new (globalThis.DOMException || Error)(`"${name}" has already been defined`, 'NotSupportedError');
      }
      if (typeof ctor !== 'function') throw new TypeError('constructor is not a constructor');
      __customs.set(name, ctor);
      const doc = globalThis.document;
      if (doc && doc.documentElement) {
        for (const el of doc.getElementsByTagName(name)) __customUpgrade(el, ctor);
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
      // `new MyElement()` не передаёт имя тега — его знает реестр, по классу,
      // от которого элемент произошёл. Так работает и настоящий HTMLElement.
      if (tag === undefined && new.target) tag = __customName(new.target) || 'unknown';
      this.__ptTag = String(tag).toUpperCase();
      this.__ptLocal = String(tag).toLowerCase();
      this.__ptAttrs = new Map();
      this.__ptStyle = makeStyle();
    }
    get nodeName() { return this.tagName; }
    get tagName() { return this.__ptTag; }
    get localName() { return this.__ptLocal; }
    get style() { return this.__ptStyle; }

    // Attributes
    getAttribute(n) { const v = this.__ptAttrs.get(n.toLowerCase()); return v === undefined ? null : v; }
    setAttribute(n, v) {
      const name = n.toLowerCase(), old = this.__ptAttrs.get(name);
      this.__ptAttrs.set(name, String(v));
      if (this.__ptUpgraded) {
        const watched = this.constructor && this.constructor.observedAttributes;
        if (Array.isArray(watched) && watched.indexOf(name) >= 0) {
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
      const name = n.toLowerCase(), old = this.__ptAttrs.get(name);
      this.__ptAttrs.delete(name);
      __markDirty();
      __mutation({ type: 'attributes', target: this, attributeName: name, attributeNamespace: null,
        oldValue: old === undefined ? null : old, addedNodes: [], removedNodes: [],
        previousSibling: null, nextSibling: null });
    }
    hasAttribute(n) { return this.__ptAttrs.has(n.toLowerCase()); }
    getAttributeNames() { return [...this.__ptAttrs.keys()]; }
    get attributes() { return [...this.__ptAttrs].map(([name, value]) => ({ name, value })); }

    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }
    get classList() { return makeClassList(this); }
    get dataset() { return makeDataset(this); }

    // URL-valued attributes reflect as *absolute* URLs, exactly as in a browser.
    // Not cosmetic: Cloudflare's Turnstile finds its own `<script>` by comparing
    // `script.src` against its api.js URL, and while this returned `''` the
    // widget refused to initialise ("Could not find Turnstile valid script tag").
    get src() { return this.__ptUrlAttr('src'); }
    set src(v) {
      this.setAttribute('src', v);
      if (!this.isConnected) return;
      // The src can arrive after the element is in the document, in either order:
      // `el.src = …; head.appendChild(el)` or `head.appendChild(el); el.src = …`.
      if (this.__ptConnectFrame) this.__ptConnectFrame();
      if (this.__ptRunScript) this.__ptRunScript();
    }
    get href() { return this.__ptUrlAttr('href'); }
    set href(v) { this.setAttribute('href', v); }

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
      const raw = this.getAttribute('href');
      if (raw == null) return undefined;
      const base = (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base); } catch (e) { return undefined; }
    }
    __ptSetLinkPart(part, v) {
      const u = this.__ptLinkURL();
      if (!u) return;
      try { u[part] = v; this.setAttribute('href', u.href); } catch (e) {}
    }
    get action() { return this.__ptUrlAttr('action'); }
    set action(v) { this.setAttribute('action', v); }
    __ptUrlAttr(n) {
      const raw = this.getAttribute(n);
      if (raw == null) return '';
      const base = (globalThis.location && location.href) || 'about:blank';
      try { return new URL(raw, base).href; } catch (e) { return raw; }
    }

    // Plain string/boolean reflections a page can read back off an element.
    get rel() { return this.getAttribute('rel') || ''; }
    set rel(v) { this.setAttribute('rel', v); }
    get target() { return this.getAttribute('target') || ''; }
    set target(v) { this.setAttribute('target', v); }
    get alt() { return this.getAttribute('alt') || ''; }
    set alt(v) { this.setAttribute('alt', v); }
    get integrity() { return this.getAttribute('integrity') || ''; }
    set integrity(v) { this.setAttribute('integrity', v); }
    get nonce() { return this.getAttribute('nonce') || ''; }
    set nonce(v) { this.setAttribute('nonce', v); }
    get crossOrigin() { return this.hasAttribute('crossorigin') ? (this.getAttribute('crossorigin') || 'anonymous') : null; }
    set crossOrigin(v) { this.setAttribute('crossorigin', v); }
    get referrerPolicy() { return this.getAttribute('referrerpolicy') || ''; }
    set referrerPolicy(v) { this.setAttribute('referrerpolicy', v); }
    get async() { return this.hasAttribute('async'); }
    set async(v) { v ? this.setAttribute('async', '') : this.removeAttribute('async'); }
    get defer() { return this.hasAttribute('defer'); }
    set defer(v) { v ? this.setAttribute('defer', '') : this.removeAttribute('defer'); }

    get children() { return this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE); }
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
      const src = this.getAttribute('src');
      if (src && src !== 'about:blank') return null;
      if (typeof globalThis.__pt_makeRealm !== 'function') return null;
      const w = globalThis.__pt_makeRealm();
      if (!w) return null;
      // It is a child: it sees us as its parent, and knows the element it is in.
      for (const [k, v] of [['parent', globalThis], ['top', globalThis.top || globalThis],
        ['frameElement', this], ['self', w], ['window', w]]) {
        try { Object.defineProperty(w, k, { value: v, configurable: true }); } catch (e) {}
      }
      Object.defineProperty(this, '__ptRealm', { value: w, configurable: true, enumerable: false });
      return w;
    }
    // A `<script>` that has just entered the document runs — once. The "already
    // started" flag is the spec's, and it is what keeps a parser-built script
    // (the engine runs those itself, in document order) from running twice, and a
    // re-inserted element from running again.
    __ptRunScript() {
      if (this.__ptRan || this.__ptLocal !== 'script') return;
      const type = String(this.getAttribute('type') || '').toLowerCase().trim();
      // Anything that is not classic JS — a JSON island, a template, an importmap
      // — is data the page reads itself, not code to run.
      if (type && !/^(text|application)\/(java|ecma)script$|^module$/.test(type)) return;
      const src = this.getAttribute('src');
      // Nothing to run *yet*: an element appended empty starts when its `src`
      // arrives, so the flag must not be set until there is something to do.
      if (!src && !this.textContent) return;
      Object.defineProperty(this, '__ptRan', { value: true, configurable: true, enumerable: false });
      // Модуль исполняется не как обычный скрипт: у него свой разбор, свои
      // `import` и своя область. Такой отдаём движку — и со ссылкой, и вписанный
      // прямо в страницу.
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
      // Indirect eval: a classic script runs in global scope, not in ours.
      try { (0, eval)(code); } catch (e) { /* page script threw */ }
    }

    __ptConnectFrame() {
      if (this.__ptFrameId || this.__ptLocal !== 'iframe') return;
      const src = this.getAttribute('src');
      if (!src) return;
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      __frameOps.push({ op: 'open', id, src });
    }

    // Shadow DOM. A widget that draws itself into a shadow root — Cloudflare's
    // Turnstile does, and so does most of the web-component world — dies at the
    // first line without this. The tree is genuinely separate: nothing inside is
    // reachable from `document.querySelector`, which is the point of it.
    attachShadow(init) {
      const mode = (init && init.mode) === 'closed' ? 'closed' : 'open';
      if (this.__ptShadow) throw new Error("Failed to execute 'attachShadow' on 'Element': Shadow root cannot be created on a host which already hosts a shadow tree.");
      this.__ptShadow = new ShadowRoot(this, mode);
      __markDirty();
      return this.__ptShadow;
    }
    get shadowRoot() {
      const r = this.__ptShadow;
      // A closed root is invisible even to its own host's `shadowRoot`.
      return r && r.mode === 'open' ? r : null;
    }

    get innerHTML() { return this.__ptKids.map(serializeNode).join(''); }
    set innerHTML(html) { this.__ptKids = []; for (const n of parseFragment(String(html))) this.appendChild(n); }
    get outerHTML() { return serializeNode(this); }
    // Rendered text (hidden subtrees excluded, whitespace collapsed) — an
    // approximation of `innerText` good enough for tools that read it.
    get innerText() { return __innerText(this); }
    set innerText(v) { this.textContent = String(v); }
    get outerText() { return __innerText(this); }
    insertAdjacentHTML(pos, html) {
      const nodes = parseFragment(String(html));
      if (pos === 'beforeend') for (const n of nodes) this.appendChild(n);
      else if (pos === 'afterbegin') for (const n of nodes.reverse()) this.insertBefore(n, this.firstChild);
      else if (pos === 'beforebegin') for (const n of nodes) this.parentNode.insertBefore(n, this);
      else if (pos === 'afterend') for (const n of nodes.reverse()) this.parentNode.insertBefore(n, this.nextSibling);
    }

    // Synthetic layout (no real rendering): rendered elements report a non-empty
    // box so coordinate + visibility tooling works, hidden/detached ones an empty
    // one. See __relayout / __boxOf below.
    getBoundingClientRect() { const r = __rectFromBox(__boxOf(this)); r.toJSON = function () { return this; }; return r; }
    getClientRects() { const b = __boxOf(this); if (!b) return []; const r = __rectFromBox(b); r.toJSON = function () { return this; }; return [r]; }
    get parentElement() { const p = this.parentNode; return p && p.nodeType === ELEMENT_NODE ? p : null; }
    // Layout-metric accessors derived from the synthetic box. `documentElement`'s
    // client size is the viewport (drivers clamp click boxes to it).
    get clientWidth() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.W; const b = __boxOf(this); return b ? b.w : 0; }
    get clientHeight() { const d = this.ownerDocument || globalThis.document; if (d && this === d.documentElement) return LAYOUT.H; const b = __boxOf(this); return b ? b.h : 0; }
    get clientTop() { return 0; }
    get clientLeft() { return 0; }
    get scrollWidth() { return this.clientWidth; }
    get scrollHeight() { return this.clientHeight; }
    get scrollTop() { return 0; }
    get scrollLeft() { return 0; }
    get offsetWidth() { const b = __boxOf(this); return b ? b.w : 0; }
    get offsetHeight() { const b = __boxOf(this); return b ? b.h : 0; }
    get offsetTop() { const b = __boxOf(this); return b ? b.y : 0; }
    get offsetLeft() { const b = __boxOf(this); return b ? b.x : 0; }
    get offsetParent() { return __boxOf(this) ? this.parentElement : null; }
    scrollIntoView() {} scrollIntoViewIfNeeded() {}
    focus() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement === this) return;
      const prev = doc.activeElement;
      if (prev && prev !== doc.body && prev.dispatchEvent) prev.dispatchEvent(new Event('blur'));
      doc.activeElement = this;
      this.dispatchEvent(new Event('focus'));
      this.dispatchEvent(new Event('focusin', { bubbles: true }));
    }
    blur() {
      const doc = this.ownerDocument || globalThis.document;
      if (!doc || doc.activeElement !== this) return;
      doc.activeElement = doc.body || null;
      this.dispatchEvent(new Event('blur'));
    }
    // Form-field value (reflects the `value` attribute until edited). Generic so
    // input/textarea typing works; harmless on other elements.
    get value() { return this.__ptValue !== undefined ? this.__ptValue : (this.getAttribute('value') || ''); }
    set value(v) { this.__ptValue = String(v); }
    // Common form-field surface, reflected from attributes — drivers gate `fill`
    // and `select` on these (an input with no `type`/`disabled`/`readOnly` fails
    // Playwright's fillability check).
    get type() { const t = (this.getAttribute('type') || '').toLowerCase(); return this.tagName === 'INPUT' ? (t || 'text') : t; }
    set type(v) { this.setAttribute('type', v); }
    get disabled() { return this.hasAttribute('disabled'); }
    set disabled(v) { if (v) this.setAttribute('disabled', ''); else this.removeAttribute('disabled'); }
    get readOnly() { return this.hasAttribute('readonly'); }
    set readOnly(v) { if (v) this.setAttribute('readonly', ''); else this.removeAttribute('readonly'); }
    get name() { return this.getAttribute('name') || ''; }
    set name(v) { this.setAttribute('name', v); }
    get placeholder() { return this.getAttribute('placeholder') || ''; }
    // Reflected dimension attributes. Without these, `canvas.width = 200` would
    // create an *own* property on the element (real ones are prototype
    // accessors), which is exactly the tell we hide everywhere else.
    get width() { const v = parseInt(this.getAttribute('width'), 10); return Number.isFinite(v) ? v : (this.tagName === 'CANVAS' ? 300 : 0); }
    set width(v) { this.setAttribute('width', String(Math.max(0, v | 0))); }
    get height() { const v = parseInt(this.getAttribute('height'), 10); return Number.isFinite(v) ? v : (this.tagName === 'CANVAS' ? 150 : 0); }
    set height(v) { this.setAttribute('height', String(Math.max(0, v | 0))); }
    get checked() { return this.__ptChecked !== undefined ? this.__ptChecked : this.hasAttribute('checked'); }
    set checked(v) { this.__ptChecked = !!v; }
    get selectionStart() { return String(this.value || '').length; }
    get selectionEnd() { return String(this.value || '').length; }
    select() {}
    setSelectionRange() {}
    setRangeText() {}
    get isContentEditable() { const v = (this.getAttribute('contenteditable') || '').toLowerCase(); return v === '' || v === 'true'; }
    click() { this.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); }

    __ptShallowClone() { const e = new Element(this.localName); e.__ptAttrs = new Map(this.__ptAttrs); return e; }
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
    get visibilityState() { return 'visible'; }
    get hidden() { return false; }
    get documentElement() { return this.__ptDocEl; }
    set documentElement(v) { this.__ptDocEl = v; }
    get readyState() { return this.__ptReady; }
    set readyState(v) { this.__ptReady = v; }
    // В браузере это `<body>`, как только тело есть, и никогда не null у
    // загруженного документа: сборщик отпечатка кладёт его в корзину объектов,
    // а null — в корзину «x».
    get activeElement() { return this.__ptActive || this.body || null; }
    set activeElement(v) { this.__ptActive = v; }
    elementFromPoint(x, y) { return __elementFromPoint(x, y); }
    elementsFromPoint(x, y) { const e = __elementFromPoint(x, y); return e ? [e] : []; }
    get nodeName() { return '#document'; }
    get head() { return this.documentElement && this.documentElement.getElementsByTagName('head')[0] || null; }
    get body() { return this.documentElement && this.documentElement.getElementsByTagName('body')[0] || null; }
    get title() { const t = this.getElementsByTagName('title')[0]; return t ? t.textContent.trim() : ''; }
    set title(v) {
      let t = this.getElementsByTagName('title')[0];
      if (!t) { t = this.createElement('title'); (this.head || this.documentElement || this).appendChild(t); }
      t.textContent = String(v);
    }
    // The document's live element collections. Missing, these are not a cosmetic
    // gap: Turnstile's loader answers its widget's `requestExtraParams` with a
    // report that reads `document.scripts.length`, and a `TypeError` there kills
    // the reply — which the widget waits for forever, silently, because a listener
    // that throws is swallowed by the event dispatch. `referrer` is read on the
    // same line and must be a string ('' for a direct load), not `undefined`.
    // Коллекции документа — это HTMLCollection, а не массив: `Array.isArray`
    // на них ложен, а сборщик отпечатка кладёт массив в корзину по его
    // строковому значению, из-за чего пустой список выглядел как пустая строка.
    get scripts() { return __collection(this.getElementsByTagName('script')); }
    get forms() { return __collection(this.getElementsByTagName('form')); }
    get images() { return __collection(this.getElementsByTagName('img')); }
    get embeds() { return __collection(this.getElementsByTagName('embed')); }
    get plugins() { return __collection(this.getElementsByTagName('embed')); }
    // `links` is `<a>`/`<area>` *with an href*, and `anchors` is `<a>` with a name.
    get links() {
      return __collection(this.getElementsByTagName('a').concat(this.getElementsByTagName('area'))
        .filter(e => e.hasAttribute('href')));
    }
    get anchors() { return __collection(this.getElementsByTagName('a').filter(e => e.hasAttribute('name'))); }
    get styleSheets() {
      return __collection(this.getElementsByTagName('style')
        .concat(this.getElementsByTagName('link').filter(e => /stylesheet/i.test(e.getAttribute('rel') || '')))
        .map(owner => ({ ownerNode: owner, href: owner.getAttribute('href') || null,
                         type: 'text/css', disabled: false, media: owner.getAttribute('media') || '',
                         title: owner.getAttribute('title') || null, cssRules: [], rules: [] })));
    }
    // Кодировка — объявленная, а не всегда UTF-8: страница без объявления
    // разбирается как windows-1252, и Chrome именно это и сообщает. Отвечать
    // «UTF-8» на документ, который ничего не объявил, — заметная разница.
    get characterSet() {
      if (this.__ptCharset) return this.__ptCharset;
      for (const m of this.getElementsByTagName('meta')) {
        const c = m.getAttribute('charset');
        if (c) return __normEncoding(c);
        if (/^content-type$/i.test(m.getAttribute('http-equiv') || '')) {
          const hit = /charset\s*=\s*"?([\w-]+)/i.exec(m.getAttribute('content') || '');
          if (hit) return __normEncoding(hit[1]);
        }
      }
      return 'windows-1252';
    }
    get charset() { return this.characterSet; }
    get inputEncoding() { return this.characterSet; }
    get contentType() { return 'text/html'; }
    // Страница без `<!DOCTYPE>` живёт в режиме совместимости, и браузер это
    // говорит: `BackCompat` и `doctype === null`. Мы отвечали «стандартный
    // режим» всегда и выдавали объект-заглушку вместо узла.
    get compatMode() { return this.__ptDoctype ? 'CSS1Compat' : 'BackCompat'; }
    get doctype() { return this.__ptDoctype || null; }
    get designMode() { return 'off'; }
    set designMode(v) {}
    // Формат браузера — MM/DD/YYYY HH:MM:SS, а не локализованная строка.
    get lastModified() {
      const d = new Date(), p2 = (n) => String(n).padStart(2, '0');
      return `${p2(d.getMonth() + 1)}/${p2(d.getDate())}/${d.getFullYear()} ` +
             `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
    }
    get webkitVisibilityState() { return this.visibilityState; }
    get adoptedStyleSheets() { return this.__ptAdopted || (this.__ptAdopted = []); }
    set adoptedStyleSheets(v) { this.__ptAdopted = v; }
    // В браузере у документа textContent равен null — узла-контейнера нет.
    get textContent() { return null; }
    set textContent(v) {}

    get referrer() { return this.__ptReferrer || ''; }
    set referrer(v) { this.__ptReferrer = String(v); }

    // `document.location` is `window.location` — the same object, not a copy. Its
    // absence is not a missing nicety: `document.location.hostname` is how a great
    // deal of code asks where it is, and against `undefined` that throws. It is
    // what stopped Cloudflare's full-page challenge here, inside its own timer,
    // where nothing surfaced the error.
    get location() { return globalThis.location; }
    set location(v) { try { globalThis.location.href = String(v); } catch (e) {} }
    get URL() { return (globalThis.location && globalThis.location.href) || 'about:blank'; }
    get documentURI() { return this.URL; }
    get baseURI() { return this.URL; }
    get domain() { return (globalThis.location && globalThis.location.hostname) || ''; }
    set domain(v) { /* only ever narrowed to a parent domain; nothing to do here */ }

    get cookie() { return this.__ptCookie; }
    set cookie(v) {
      const pair = String(v).split(';')[0];
      const eq = pair.indexOf('=');
      if (eq < 0) return;
      const name = pair.slice(0, eq).trim();
      const jar = this.__ptCookie ? this.__ptCookie.split('; ') : [];
      const kept = jar.filter(c => c.split('=')[0] !== name);
      kept.push(pair.trim());
      this.__ptCookie = kept.join('; ');
    }

    createElement(tag) {
      const C = __customs.get(String(tag).toLowerCase());
      const e = C ? new C() : new Element(tag);
      if (C) Object.defineProperty(e, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
      e.ownerDocument = this;
      return e;
    }
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
    __ptShallowClone() { return new Document(); }
  }

  // ---- Event ----------------------------------------------------------------
  // Event state lives in one hidden bag (`__ptE`) exposed through prototype
  // accessors: a real `new MouseEvent('click')` reports no own properties, so
  // assigning fields to the instance would be an obvious tell.
  const evtAccessors = (Ctor, names) => {
    for (const n of names) {
      const get = function () { return this.__ptE[n]; };
      const set = function (v) { this.__ptE[n] = v; };
      try { Object.defineProperty(get, 'name', { value: 'get ' + n, configurable: true }); } catch (e) {}
      try { Object.defineProperty(set, 'name', { value: 'set ' + n, configurable: true }); } catch (e) {}
      Object.defineProperty(Ctor.prototype, n, { get, set, configurable: true, enumerable: false });
    }
  };

  class Event {
    constructor(type, init) {
      init = init || {};
      this.__ptE = {
        type, bubbles: !!init.bubbles, cancelable: !!init.cancelable,
        defaultPrevented: false, target: null, currentTarget: null,
        // Событие, созданное страницей, не доверенное — доверенные приходят
        // только от движка (ввод, load, message), и он метит их __ptTrust.
        eventPhase: 0, timeStamp: (globalThis.performance && performance.now()) || 0, isTrusted: false,
      };
      this.__ptStop = false; this.__ptStopImm = false;
    }
    preventDefault() { if (this.cancelable) this.__ptE.defaultPrevented = true; }
    stopPropagation() { this.__ptStop = true; }
    stopImmediatePropagation() { this.__ptStop = true; this.__ptStopImm = true; }
    composedPath() { const p = []; for (let n = this.target; n; n = n.parentNode) p.push(n); return p; }
  }
  // Пометить событие как пришедшее от движка. Страница до этого не дотянется:
  // имя __pt-скрыто из любого перечисления, а слепок делается один раз.
  const __ptTrust = (ev) => { if (ev && ev.__ptE) ev.__ptE.isTrusted = true; return ev; };

  evtAccessors(Event, ['type', 'bubbles', 'cancelable', 'defaultPrevented', 'target',
    'currentTarget', 'eventPhase', 'timeStamp', 'isTrusted']);

  class CustomEvent extends Event {
    constructor(type, init) { super(type, init); this.__ptE.detail = (init && init.detail) || null; }
  }
  evtAccessors(CustomEvent, ['detail']);

  class UIEvent extends Event {
    constructor(type, init) {
      super(type, init); init = init || {};
      this.__ptE.detail = init.detail || 0;
      this.__ptE.view = globalThis;
    }
  }
  evtAccessors(UIEvent, ['detail', 'view']);

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
      });
    }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(MouseEvent, ['clientX', 'clientY', 'screenX', 'screenY', 'pageX', 'pageY',
    'offsetX', 'offsetY', 'button', 'buttons', 'relatedTarget'].concat(MODS));

  class PointerEvent extends MouseEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        pointerId: init.pointerId || 1,
        pointerType: init.pointerType || 'mouse',
        isPrimary: init.isPrimary !== false,
      });
    }
  }
  evtAccessors(PointerEvent, ['pointerId', 'pointerType', 'isPrimary']);

  class KeyboardEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        key: init.key || '', code: init.code || '',
        keyCode: init.keyCode || 0, which: init.keyCode || 0, charCode: init.charCode || 0,
        location: init.location || 0, repeat: !!init.repeat,
        ctrlKey: !!init.ctrlKey, shiftKey: !!init.shiftKey,
        altKey: !!init.altKey, metaKey: !!init.metaKey,
      });
    }
    getModifierState(k) { return modifierState.call(this, k); }
  }
  evtAccessors(KeyboardEvent, ['key', 'code', 'keyCode', 'which', 'charCode',
    'location', 'repeat'].concat(MODS));

  class InputEvent extends UIEvent {
    constructor(type, init) {
      super(type, init); init = init || {};
      Object.assign(this.__ptE, {
        data: init.data == null ? null : String(init.data),
        inputType: init.inputType || '', isComposing: false,
      });
    }
  }
  evtAccessors(InputEvent, ['data', 'inputType', 'isComposing']);

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
    }
  }
  evtAccessors(MessageEvent, ['data', 'origin', 'lastEventId', 'source', 'ports']);

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
  // Воркер — отдельный контекст V8, который строит движок: своя область, свои
  // прототипы, свой `self`. Здесь остаётся только порт: очередь операций наружу
  // и доставка сообщений обратно.
  const __workerOps = [];
  const __workers = new Map();
  let __nextWorkerId = 1;
  globalThis.__pt_drainWorkerQueue = () => __workerOps.splice(0);
  globalThis.__pt_workerMessage = (id, json) => {
    const W = __workers.get(id);
    if (!W || W.closed) return;
    let data = null;
    try { data = JSON.parse(json); } catch (e) {}
    const ev = new MessageEvent('message', { data });
    try { if (typeof W.onmessage === 'function') W.onmessage.call(W.worker, ev); } catch (e) {}
    for (const h of (W.listeners.message || [])) { try { h.call(W.worker, ev); } catch (e) {} }
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
      if (src.slice(0, 5) === 'blob:' || src.slice(0, 5) === 'data:') {
        try { body = globalThis.__pt_localSource ? __pt_localSource(src) : null; } catch (e) {}
      }
      __workerOps.push({ op: 'open', id, src, body, name: (options && options.name) || '' });
    }
    postMessage(data) {
      const W = this.__ptW;
      if (W.closed) return;
      let json = 'null';
      try { json = JSON.stringify(data === undefined ? null : data); } catch (e) {}
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
  // `Object.prototype.toString.call(new Worker(...))` — «[object Worker]», как у
  // всякого интерфейса; без тега объект называет себя простым Object.
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
      const c = globalThis.document ? globalThis.document.createElement('canvas') : null;
      if (c) { c.width = width | 0; c.height = height | 0; }
      Object.defineProperty(this, '__ptO', { value: { c, w: width | 0, h: height | 0 } });
    }
    get width() { return this.__ptO.w; }
    set width(v) { this.__ptO.w = v | 0; if (this.__ptO.c) this.__ptO.c.width = v | 0; }
    get height() { return this.__ptO.h; }
    set height(v) { this.__ptO.h = v | 0; if (this.__ptO.c) this.__ptO.c.height = v | 0; }
    getContext(type, attrs) { const c = this.__ptO.c; return c ? c.getContext(type, attrs) : null; }
    convertToBlob(opts) { return Promise.resolve(new Blob([], { type: (opts && opts.type) || 'image/png' })); }
    transferToImageBitmap() { return {}; }
  }

  globalThis.Worker = Worker;
  globalThis.SharedWorker = SharedWorker;
  globalThis.OffscreenCanvas = OffscreenCanvas;

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
      setProperty: (p, v) => { map.set(p, v); __markDirty(); },
      removeProperty: (p) => { map.delete(p); __markDirty(); },
      get cssText() { return [...map].map(([k, v]) => `${k}: ${v}`).join('; '); },
    }, {
      get: (t, p) => p in t ? t[p] : (map.get(dash(String(p))) || ''),
      set: (t, p, v) => { map.set(dash(String(p)), String(v)); __markDirty(); return true; },
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
    for (const c of node.__ptKids) {
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
    if (n.nodeType !== ELEMENT_NODE) return n.__ptKids.map(serializeNode).join('');
    const tag = n.localName;
    let attrs = '';
    for (const { name, value } of n.attributes) attrs += ` ${name}="${esc(value, true)}"`;
    if (VOID.has(tag)) return `<${tag}${attrs}>`;
    return `<${tag}${attrs}>${n.__ptKids.map(serializeNode).join('')}</${tag}>`;
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
    return root.__ptKids.slice();
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
    // A parser-built script is "already started": the engine runs the document's
    // scripts itself, in document order, so connecting the tree must not run them
    // a second time. Only what a page inserts later goes through `__ptRunScript`.
    if (spec.tag === 'script') {
      Object.defineProperty(el, '__ptRan', { value: true, configurable: true, enumerable: false });
    }
    for (const [name, value] of spec.attrs) el.setAttribute(name, value);
    for (const child of spec.children) el.appendChild(buildNode(doc, child));
    return el;
  }

  // ---- install globals ------------------------------------------------------
  const document = new Document();
  globalThis.document = document;
  // Standard Node type constants, on the constructor and the prototype — drivers
  // check `node.nodeType !== Node.ELEMENT_NODE` before acting on a node.
  const NODE_TYPES = {
    ELEMENT_NODE: 1, ATTRIBUTE_NODE: 2, TEXT_NODE: 3, CDATA_SECTION_NODE: 4,
    // Пятый и шестой типы давно не создаются, но константы у Node остались, и
    // их пересчитывают: у Chrome на `Node.prototype` ровно 48 имён.
    ENTITY_REFERENCE_NODE: 5, ENTITY_NODE: 6,
    PROCESSING_INSTRUCTION_NODE: 7, COMMENT_NODE: 8, DOCUMENT_NODE: 9,
    DOCUMENT_TYPE_NODE: 10, DOCUMENT_FRAGMENT_NODE: 11, NOTATION_NODE: 12,
    DOCUMENT_POSITION_DISCONNECTED: 1, DOCUMENT_POSITION_PRECEDING: 2,
    DOCUMENT_POSITION_FOLLOWING: 4, DOCUMENT_POSITION_CONTAINS: 8,
    DOCUMENT_POSITION_CONTAINED_BY: 16, DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC: 32,
  };
  Object.assign(Node, NODE_TYPES);
  Object.assign(Node.prototype, NODE_TYPES);

  // Члены Node, которых у нас не было вовсе или которые лежали этажом ниже, на
  // Element. В браузере они все здесь, и сборщик отпечатка считает именно этот
  // этаж.
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
            if (other.getAttribute(a[i].name) !== a[i].value) return false;
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
        return order.indexOf(this) < order.indexOf(other) ? 4 : 2;
      },
    },
    normalize: {
      value: function normalize() {
        const kids = this.childNodes;
        for (let i = kids.length - 1; i > 0; i--) {
          const cur = kids[i], prev = kids[i - 1];
          if (cur.nodeType === 3 && prev.nodeType === 3) { prev.data += cur.data; this.removeChild(cur); }
        }
        for (const c of this.childNodes) if (c.normalize) c.normalize();
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
  globalThis.HTMLElement = Element;
  // Concrete element interfaces alias the generic Element, so their `.prototype`
  // carries our accessors (notably `value`). Playwright's `fill` sets a field via
  // the *native* setter it looks up on `HTMLInputElement.prototype`, so that
  // descriptor must exist there.
  // A missing one is not a cosmetic gap: real bundles reference these directly
  // (Cloudflare's Turnstile loader dies on `HTMLScriptElement is not defined`
  // before it can draw its widget), and a fingerprinter can list them in a line.
  for (const n of ['HTMLInputElement', 'HTMLTextAreaElement', 'HTMLSelectElement',
    'HTMLButtonElement', 'HTMLAnchorElement', 'HTMLDivElement', 'HTMLSpanElement',
    'HTMLParagraphElement', 'HTMLFormElement', 'HTMLOptionElement', 'HTMLLabelElement',
    'HTMLScriptElement', 'HTMLIFrameElement', 'HTMLBodyElement', 'HTMLHeadElement',
    'HTMLHtmlElement', 'HTMLStyleElement', 'HTMLLinkElement', 'HTMLMetaElement',
    'HTMLTitleElement', 'HTMLTemplateElement', 'HTMLSlotElement', 'HTMLPictureElement',
    'HTMLSourceElement', 'HTMLMediaElement', 'HTMLVideoElement', 'HTMLAudioElement',
    'HTMLTableElement', 'HTMLTableRowElement', 'HTMLTableCellElement',
    'HTMLTableSectionElement', 'HTMLUListElement', 'HTMLOListElement', 'HTMLLIElement',
    'HTMLHeadingElement', 'HTMLPreElement', 'HTMLBRElement', 'HTMLHRElement',
    'HTMLFieldSetElement', 'HTMLLegendElement', 'HTMLOptGroupElement', 'HTMLDataListElement',
    'HTMLOutputElement', 'HTMLProgressElement', 'HTMLMeterElement', 'HTMLDetailsElement',
    'HTMLDialogElement', 'HTMLMapElement', 'HTMLAreaElement', 'HTMLQuoteElement',
    'HTMLTimeElement', 'HTMLModElement', 'HTMLObjectElement', 'HTMLEmbedElement',
    'HTMLUnknownElement']) {
    if (!globalThis[n]) globalThis[n] = Element;
  }
  globalThis.ShadowRoot = ShadowRoot;
  globalThis.Text = Text;
  globalThis.Comment = Comment;
  globalThis.Document = Document;
  globalThis.Event = Event;
  globalThis.CustomEvent = CustomEvent;
  globalThis.DocumentFragment = Node;
  document.__ptView = globalThis;

  // <script> nodes in document order, so the loader can point `currentScript` at
  // the one it is about to run (for document.write positioning).
  let scriptNodes = [];

  // Called by the loader with the Rust-parsed <html> tree.
  globalThis.__pt_installDocument = (tree, dt) => {
    document.__ptKids = [];
    document.documentElement = null;
    document.currentScript = null;
    // `<!DOCTYPE html>` — это узел документа, первый его ребёнок, а не флаг.
    document.__ptDoctype = null;
    if (dt) {
      // Узел обязан называть себя: `Object.prototype.toString.call(doctype)` —
      // `[object DocumentType]`, как у всякого интерфейса.
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
      document.appendChild(html);
      document.documentElement = html;
    }
    scriptNodes = document.getElementsByTagName('script') || [];
    // Пока идут собственные скрипты документа, браузер отвечает 'loading', и
    // код это читает: «если не loading — запускайся сразу, иначе жди
    // DOMContentLoaded». Мы отвечали 'interactive' с самого начала, то есть
    // всегда первую ветку.
    document.readyState = 'loading';
  };

  // The loader brackets each page script with these so `document.currentScript`
  // (and therefore document.write's insertion point) is correct while it runs.
  // The index matches the loader's document-order script list.
  globalThis.__pt_beginScript = (i) => { document.currentScript = scriptNodes[i] || null; };
  globalThis.__pt_endScript = () => { document.currentScript = null; };

  // Called after all page scripts have run: fire DOMContentLoaded then load.
  globalThis.__pt_finishLoad = () => {
    document.readyState = 'interactive';
    document.dispatchEvent(new Event('DOMContentLoaded', { bubbles: true }));
    document.readyState = 'complete';
    globalThis.dispatchEvent && globalThis.dispatchEvent(new Event('load'));
  };

  // window is an EventTarget too.
  if (!globalThis.addEventListener) {
    globalThis.__ptLis = Object.create(null);
    globalThis.addEventListener = Node.prototype.addEventListener.bind(globalThis);
    globalThis.removeEventListener = Node.prototype.removeEventListener.bind(globalThis);
    globalThis.dispatchEvent = (ev) => {
      const l = globalThis.__ptLis[ev.type]; if (l) for (const { fn } of l.slice()) { try { fn.call(globalThis, ev); } catch (_) {} }
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
      childNodeCount: (n.__ptKids || []).length, attributes: attrs
    };
  };
  // ---- synthetic layout + interaction (no real rendering) ------------------
  // There is no layout engine, so every rendered element is assigned a unique,
  // deterministic one-row box in document order. That is enough for the two
  // things drivers need: (a) a non-empty box + coordinates for visibility and
  // click-point computation, and (b) a reversible point→element mapping so an
  // Input mouse event at a computed coordinate hits the intended element.
  const LAYOUT = { W: 1280, H: 720, ROW: 20 };
  let __layoutSeq = 0;      // bumped on every DOM mutation
  let __layoutBuilt = -1;   // __layoutSeq the current boxes were built at
  let __rows = [];          // row index → element occupying it
  let __mouseDownEl = null;
  let __hoverEl = null; // element the pointer is currently over

  function __markDirty() { __layoutSeq++; }

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
      return !filter || filter.some(a => String(a).toLowerCase() === rec.attributeName);
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
      if (typeof cb !== 'function') throw new TypeError("Failed to construct 'MutationObserver': parameter 1 is not of type 'Function'.");
      const state = { cb, entries: [], records: [], api: this };
      __observers.push(state);
      Object.defineProperty(this, '__ptState', { value: state, enumerable: false });
    }
    observe(target, opts) {
      opts = opts || {};
      // The spec default: with neither childList nor attributes nor
      // characterData asked for, this is a TypeError, not a silent no-op.
      if (!opts.childList && !opts.attributes && !opts.characterData && !opts.attributeFilter) {
        throw new TypeError("Failed to execute 'observe' on 'MutationObserver': The options object must set at least one of 'attributes', 'characterData', or 'childList' to true.");
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
    unobserve(target) { const t = this.__ptState.targets; const i = t.indexOf(target); if (i >= 0) t.splice(i, 1); }
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

  // --- dynamically inserted <script src> -----------------------------------
  // The element cannot fetch; the engine can. Each insertion becomes an op the
  // driver picks up, fetches against the document's own base URL and cookies, and
  // evaluates in this context — then says how it went, so `onload`/`onerror` fire
  // where the page expects them.
  const __scriptEls = new Map();
  const __scriptOps = [];
  let __nextScriptId = 1;

  globalThis.__pt_drainScriptQueue = () => __scriptOps.splice(0);

  globalThis.__pt_scriptDone = (id, ok) => {
    const el = __scriptEls.get(id);
    if (!el) return;
    __scriptEls.delete(id);
    const ev = { type: ok ? 'load' : 'error', target: el, currentTarget: el, isTrusted: true };
    const handler = ok ? el.onload : el.onerror;
    try { if (typeof handler === 'function') handler.call(el, ev); } catch (e) {}
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
    postMessage: (data, targetOrigin) => {
      const op = { op: 'post', id, data: JSON.stringify(data === undefined ? null : data), toParent: false, targetOrigin: String(targetOrigin || '*') };
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

  globalThis.__pt_frameReady = (id, origin) => {
    const st = __frames.get(id);
    if (!st) return;
    st.ready = true;
    st.sameOrigin = !!(globalThis.location && origin === location.origin);
    for (const op of st.pending.splice(0)) __pushFrameOp(op);
    const ev = { type: 'load', target: st.el, currentTarget: st.el, isTrusted: true };
    try { if (typeof st.el.onload === 'function') st.el.onload(ev); } catch (e) {}
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
  };

  globalThis.__pt_frameFailed = (id) => {
    const st = __frames.get(id);
    if (!st) return;
    __frames.delete(id);
    const ev = { type: 'error', target: st.el, currentTarget: st.el, isTrusted: true };
    try { if (typeof st.el.onerror === 'function') st.el.onerror(ev); } catch (e) {}
    try { st.el.dispatchEvent && st.el.dispatchEvent(ev); } catch (e) {}
  };

  // A `message` event arriving from the other side of a frame boundary.
  globalThis.__pt_deliverMessage = (data, origin, fromFrameId) => {
    const source = fromFrameId ? (__frames.get(fromFrameId) || {}).win || null : (globalThis.parent === globalThis ? null : globalThis.parent);
    const ev = {
      type: 'message', data, origin: String(origin || ''), lastEventId: '',
      source, ports: [], isTrusted: true, target: globalThis, currentTarget: globalThis,
    };
    try { globalThis.dispatchEvent && globalThis.dispatchEvent(ev); } catch (e) {}
  };

  // Inside a frame, `parent`/`top` are the embedder, and `postMessage` on them
  // goes back up. The engine calls this right after creating the child context
  // and before its document exists — a context cannot know it is a frame while
  // its own bootstrap is still running.
  globalThis.__pt_markAsFrame = (id) => {
    globalThis.__pt_frameId = id;
    const up = {
      postMessage: (data) => {
        __pushFrameOp({ op: 'post', data: JSON.stringify(data === undefined ? null : data), toParent: true });
      },
      get closed() { return false; },
      get frames() { return up; },
      get length() { return 0; },
      get self() { return up; },
      get window() { return up; },
    };
    try {
      Object.defineProperty(globalThis, 'parent', { value: up, configurable: true });
      Object.defineProperty(globalThis, 'top', { value: up, configurable: true });
    } catch (e) {}
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
      const list = from === 0 ? kids : kids.slice().reverse();
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
  globalThis.MutationObserver = MutationObserver;
  globalThis.ResizeObserver = ResizeObserver;

  // Каждый элемент называет свой интерфейс: в браузере `<canvas>` — это
  // `[object HTMLCanvasElement]`, а не `[object Object]`. Классов на тег у нас
  // нет, поэтому имя выводится из тега — этого хватает и для toString, и для
  // проверок, которые на нём построены.
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
    // Имя с дефисом — пользовательский элемент (HTMLElement); неизвестный
    // одиночный тег браузер считает HTMLUnknownElement.
    if (local.indexOf('-') > 0) return 'HTMLElement';
    return /^(abbr|address|article|aside|b|bdi|bdo|cite|code|dd|dfn|dt|em|figcaption|figure|footer|h1|h2|h3|h4|h5|h6|header|hgroup|i|ins|del|kbd|main|mark|nav|noscript|rp|rt|ruby|s|samp|section|small|strong|sub|summary|sup|time|u|var|wbr|details|blockquote|caption|colgroup|col)$/.test(local)
      ? 'HTMLElement' : 'HTMLUnknownElement';
  };
  for (const [C, name] of [[Node, null], [Element, null], [Text, 'Text'], [Comment, 'Comment'],
    [Document, 'HTMLDocument'], [DocumentFragment, 'DocumentFragment']]) {
    if (!C) continue;
    try {
      Object.defineProperty(C.prototype, Symbol.toStringTag, name
        ? { value: name, configurable: true }
        : { get: function () { return this.nodeType === ELEMENT_NODE ? __tagFor(this) : 'Node'; }, configurable: true });
    } catch (e) {}
  }

  for (const C of [Element, Text, Comment]) {
    Object.defineProperty(C.prototype, 'remove', { value: __removeSelf, writable: true, configurable: true });
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

  // Теги, которые не рисуют ничего: занимать место в раскладке они не вправе.
  // Пока занимали, содержимое фрейма съезжало на их высоту, и точка попадала
  // в <style> вместо кнопки.
  const __UNRENDERED = new Set(['HEAD', 'META', 'STYLE', 'SCRIPT', 'LINK', 'TITLE',
    'BASE', 'NOSCRIPT', 'TEMPLATE', 'PARAM', 'SOURCE', 'TRACK']);

  function __isHiddenEl(el) {
    if (__UNRENDERED.has(el.tagName)) return true;
    if (__hiddenBySheet.has(el)) return true;
    if (el.hasAttribute && el.hasAttribute('hidden')) return true;
    // Скрытое поле формы ничего не занимает — и строки тоже.
    if (el.tagName === 'INPUT' && /^hidden$/i.test(el.getAttribute('type') || '')) return true;
    const s = el.style;
    if (s) {
      const d = String(s.display || '').toLowerCase();
      const v = String(s.visibility || '').toLowerCase();
      if (d === 'none' || v === 'hidden' || v === 'collapse') return true;
    }
    return false;
  }

  // Минимальный CSS: из таблиц берём только правила, которые прячут. Полного
  // каскада у нас нет, но `display:none` игнорировать нельзя — спрятанный
  // классом блок занимал строку, и содержимое виджета выходило втрое выше
  // настоящего, а точка клика уезжала мимо.
  const __HIDE_RE = /(?:^|[;{])\s*(?:display\s*:\s*none|visibility\s*:\s*(?:hidden|collapse))\s*(?:;|$)/i;
  let __hiddenBySheet = new WeakSet();
  function __collectHidden() {
    __hiddenBySheet = new WeakSet();
    const sheets = [];
    const scan = (node, root) => {
      for (const n of (node.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if (n.tagName === 'STYLE') sheets.push([root, n.textContent || '']);
        if (n.__ptShadow) scan(n.__ptShadow, n.__ptShadow);
        scan(n, root);
      }
    };
    const doc = globalThis.document;
    if (!doc || !doc.documentElement) return;
    scan(doc.documentElement, doc.documentElement);
    for (const [root, css] of sheets) {
      for (const chunk of String(css).split('}')) {
        const brace = chunk.indexOf('{');
        if (brace < 0) continue;
        const sel = chunk.slice(0, brace).trim();
        // `@media` и прочие блочные правила пропускаем целиком: применить их
        // мы не умеем, а «не спрятано» — безопасная сторона ошибки.
        if (!sel || sel.charCodeAt(0) === 64) continue;
        if (!__HIDE_RE.test(chunk.slice(brace + 1))) continue;
        try { for (const el of query(root, sel)) __hiddenBySheet.add(el); } catch (e) {}
      }
    }
  }

  function __relayout() {
    if (__layoutBuilt === __layoutSeq) return;
    __layoutBuilt = __layoutSeq;
    __collectHidden();
    __rows = [];
    let row = 0;
    // Строку занимает лист — то, что действительно что-то рисует. Контейнер
    // охватывает своих детей, а не встаёт над ними отдельной полосой: в
    // браузере вложенные обёртки лежат друг на друге, и точка внутри виджета
    // попадает в самый глубокий элемент, а не в его обёртку. Пока строки
    // раздавались всем подряд, iframe виджета оказывался ниже рамки своего
    // хоста — кликнуть по нему было нечем.
    const walk = (el) => {
      if (!el || el.nodeType !== ELEMENT_NODE) return;
      if (__isHiddenEl(el)) return;               // display:none hides the subtree
      const kids = [];
      if (el.__ptShadow) for (const c of el.__ptShadow.__ptKids) kids.push(c);
      for (const c of el.__ptKids) kids.push(c);
      const boxed = kids.some((c) => c.nodeType === ELEMENT_NODE && !__isHiddenEl(c));
      // An element that states its own size gets it. The row layout is a stand-in
      // for what we do not compute, not a licence to contradict the page: a widget
      // sized 300x65 reported back as 1280x20 reads as clipped, and code that
      // measures before deciding whether it is visible — Cloudflare's loader
      // measures its widget's iframe exactly this way — decides wrong.
      const sized = __declaredSize(el);
      const start = row;
      if (boxed) {
        for (const c of kids) walk(c);
      } else {
        __rows[row] = el;
        row++;
      }
      const span = Math.max(row - start, 1) * LAYOUT.ROW;
      el.__ptBox = {
        x: 0, y: start * LAYOUT.ROW,
        w: sized.w != null ? sized.w : LAYOUT.W,
        h: sized.h != null ? sized.h : span,
      };
      el.__ptBoxV = __layoutBuilt;
    };
    const de = globalThis.document && globalThis.document.documentElement;
    if (de) walk(de);
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
    if (out.w == null && el.getAttribute) out.w = px(el.getAttribute('width'));
    if (out.h == null && el.getAttribute) out.h = px(el.getAttribute('height'));
    return out;
  }

  function __boxOf(el) {
    if (!el || el.nodeType !== ELEMENT_NODE) return null;
    __relayout();
    return el.__ptBoxV === __layoutBuilt ? el.__ptBox : null; // detached/hidden → no box
  }

  function __rectFromBox(b) {
    if (!b) return { x: 0, y: 0, left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 };
    return { x: b.x, y: b.y, left: b.x, top: b.y, right: b.x + b.w, bottom: b.y + b.h, width: b.w, height: b.h };
  }

  function __elementFromPoint(x, y) {
    __relayout();
    if (y == null || y < 0) return null;
    const el = __rows[Math.floor(y / LAYOUT.ROW)];
    return el || null;
  }

  function __focusableAncestor(el) {
    for (let e = el; e && e.nodeType === ELEMENT_NODE; e = e.parentNode) {
      const t = e.tagName;
      if (t === 'INPUT' || t === 'TEXTAREA' || t === 'SELECT' || t === 'BUTTON') return e;
      if (t === 'A' && e.hasAttribute('href')) return e;
      if (e.hasAttribute('tabindex')) return e;
      if (e.isContentEditable) return e;
    }
    return null;
  }

  const __quad = (b) => [b.x, b.y, b.x + b.w, b.y, b.x + b.w, b.y + b.h, b.x, b.y + b.h];

  // Visible text of an element: skip hidden subtrees, gather text nodes, collapse
  // runs of whitespace. Not a full innerText (no per-block newlines) but enough
  // for reading rendered text.
  const __INNERTEXT_SKIP = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'HEAD', 'TITLE']);
  function __innerText(el) {
    if (!el || el.nodeType !== ELEMENT_NODE || __isHiddenEl(el)) return '';
    // `innerText` renders only visible content — the text inside <script>/<style>
    // etc. is not rendered, so it must not leak into it (`textContent` includes it).
    if (__INNERTEXT_SKIP.has(el.tagName)) return '';
    let s = '';
    for (const c of el.__ptKids) {
      if (c.nodeType === TEXT_NODE) s += c.data;
      else if (c.nodeType === ELEMENT_NODE && !__isHiddenEl(c)) s += ' ' + __innerText(c);
    }
    return s.replace(/\s+/g, ' ').trim();
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
  // Точка попала во фрейм? Тогда клик принадлежит не нам: движок спустится в
  // его контекст и повторит попадание уже в координатах фрейма. Виджет
  // Turnstile живёт ровно так — iframe в закрытой тени хоста, — и без этого
  // спуска нажать его нечем.
  // Первый видимый управляющий элемент документа — чекбокс, переключатель или
  // кнопка, — вместе с точкой, куда по нему бьют. Ищет и в теневых деревьях:
  // виджеты держат свой UI именно там, и обычный querySelector их не находит.
  // Знания о конкретной капче здесь нет и быть не должно — есть «нажимаемое».
  // `widgetOnly` — искать только внутри теневых деревьев: собственная форма
  // страницы виджету не принадлежит, и нажимать её кнопку «отправить» нельзя ни
  // при каких обстоятельствах. Во фрейме виджета ограничение снимается: там всё
  // содержимое и есть виджет.
  globalThis.__pt_findControl = (widgetOnly) => {
    __relayout();
    const seen = [];
    const scan = (root, shadowed) => {
      for (const n of (root.__ptKids || [])) {
        if (n.nodeType !== ELEMENT_NODE) continue;
        if (!__isHiddenEl(n)) {
          const role = (n.getAttribute && n.getAttribute('role')) || '';
          const type = (n.getAttribute && n.getAttribute('type')) || '';
          const control = (n.tagName === 'INPUT' && /^(checkbox|radio|submit|button)$/i.test(type))
            || n.tagName === 'BUTTON'
            || role === 'checkbox' || role === 'button' || role === 'switch';
          if (control && (shadowed || !widgetOnly)) {
            const r = n.getBoundingClientRect();
            if (r.width > 0 && r.height > 0) {
              seen.push({ tag: n.tagName, type: type || role,
                          x: r.x + Math.min(r.width, 24) / 2,
                          y: r.y + Math.min(r.height, 24) / 2,
                          at: Math.round(r.y),
                          label: (n.getAttribute && n.getAttribute('aria-label')) || '' });
            }
          }
          if (n.__ptShadow) scan(n.__ptShadow, true);
          scan(n, shadowed);
        }
      }
    };
    const de = globalThis.document && globalThis.document.documentElement;
    if (de) scan(de, false);
    return JSON.stringify(seen.slice(0, 8));
  };

  globalThis.__pt_hitFrame = (x, y) => {
    for (let el = __elementFromPoint(x, y); el && el.nodeType === ELEMENT_NODE; el = el.parentNode) {
      if (el.__ptLocal === 'iframe' && el.__ptFrameId) {
        const r = el.getBoundingClientRect();
        // Один к одному, как в настоящем окне: фрейм не сжимает содержимое под
        // свою рамку, он показывает его верх, а остальное уходит под обрез.
        // Точка внутри рамки — та же точка в координатах фрейма.
        return JSON.stringify({ frame: el.__ptFrameId, x: x - r.x, y: y - r.y });
      }
    }
    return '';
  };


  globalThis.__pt_mouse = (type, x, y, button, clickCount) => {
    const el = __elementFromPoint(x, y) || (globalThis.document && globalThis.document.body);
    if (!el) return false;
    const b = button === 'right' ? 2 : button === 'middle' ? 1 : (button | 0);
    const base = { bubbles: true, cancelable: true, composed: true,
                   clientX: x, clientY: y, screenX: x, screenY: y,
                   button: b, detail: clickCount || 1 };
    // Ввод от движка — доверенный: настоящий клик несёт isTrusted=true, и
    // виджеты, которые ждут нажатия человека, только такой и принимают.
    const send = (ev) => el.dispatchEvent(__ptTrust(ev));
    if (type === 'mousePressed') {
      if (__hoverEl !== el) {
        __hoverEl = el;
        send(new PointerEvent('pointerover', base));
        send(new MouseEvent('mouseover', base));
      }
      send(new PointerEvent('pointerdown', { ...base, buttons: 1 }));
      send(new MouseEvent('mousedown', { ...base, buttons: 1 }));
      const f = __focusableAncestor(el);
      if (f) f.focus(); else if (globalThis.document) { const a = globalThis.document.activeElement; if (a && a.blur) a.blur(); }
      __mouseDownEl = el;
    } else if (type === 'mouseReleased') {
      send(new PointerEvent('pointerup', base));
      send(new MouseEvent('mouseup', base));
      if (__mouseDownEl === el) {
        // Нажатие на чекбокс/радио переключает его до того, как всплывёт click,
        // — обработчик читает уже новое состояние.
        if (el.tagName === 'INPUT' && /^(checkbox|radio)$/i.test(el.getAttribute('type') || '')) {
          el.checked = el.getAttribute('type').toLowerCase() === 'radio' ? true : !el.checked;
          el.dispatchEvent(__ptTrust(new Event('input', { bubbles: true })));
          el.dispatchEvent(__ptTrust(new Event('change', { bubbles: true })));
        }
        send(new MouseEvent('click', base));
      }
      __mouseDownEl = null;
    } else if (type === 'mouseMoved') {
      if (__hoverEl !== el) {
        __hoverEl = el;
        send(new PointerEvent('pointerover', base));
        send(new MouseEvent('mouseover', base));
      }
      send(new PointerEvent('pointermove', base));
      send(new MouseEvent('mousemove', base));
    }
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
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') el.value = String(el.value || '').slice(0, -1);
        else el.textContent = String(el.textContent || '').slice(0, -1);
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
