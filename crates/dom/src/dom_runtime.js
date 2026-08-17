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
  // Снимок JSON, снятый до единой строки страницы. Движок сериализует свои
  // очереди сам, и если делать это через `JSON.stringify` страницы, то страница,
  // подменив его, увидит внутренности эмулятора — трафика такого вида в браузере
  // нет вовсе, и это улика не хуже отсутствующего свойства.
  const __ptJSON = globalThis.__ptJSON || { stringify: JSON.stringify, parse: JSON.parse };
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
    __link('HTMLCollection', __collectionProto);
    const list = Object.create(__collectionProto);
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // `querySelectorAll` отдаёт NodeList — не живой, как у childNodes, а слепок;
  // это разные вещи в браузере и разные ответы на `Object.prototype.toString`.
  function __staticNodeList(arr) {
    __link('NodeList', __nodeListProto);
    const list = Object.create(__nodeListProto);
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }
  // childNodes отдаёт NodeList, а не массив: `Array.isArray(node.childNodes)`
  // на платформе ложен, и сборщик отпечатков Turnstile метит массив отдельной
  // категорией. Список живой и тождественный самому себе — виджеты сравнивают
  // `a.childNodes === a.childNodes`, — поэтому он кэшируется на узле, а индексы
  // пересобираются при каждом обращении.
  function __nodeList(node) {
    __link('NodeList', __nodeListProto);
    let list = node.__ptList;
    if (!list) {
      list = Object.create(__nodeListProto);
      Object.defineProperty(node, '__ptList', { value: list, enumerable: false, writable: true });
    }
    const kids = node.__ptKids, prev = list.__ptLen | 0;
    for (let i = 0; i < kids.length; i++) list[i] = kids[i];
    for (let i = kids.length; i < prev; i++) delete list[i];
    Object.defineProperty(list, '__ptLen', { value: kids.length, enumerable: false, configurable: true });
    return list;
  }
  // Прототип связывается со своим интерфейсом при первом обращении: интерфейсы
  // объявляются позже этого файла, а список создаётся уже на странице. Члены
  // переезжают на `Iface.prototype`, а наш объект становится его наследником —
  // так `list instanceof NodeList` истинно, и `constructor` тот, что нужно.
  const __link = (name, proto) => {
    const I = globalThis[name];
    if (!I || proto.__ptLinked) return;
    proto.__ptLinked = true;
    for (const k of Reflect.ownKeys(proto)) {
      if (k === '__ptLinked') continue;
      Object.defineProperty(I.prototype, k, Object.getOwnPropertyDescriptor(proto, k));
    }
    Object.setPrototypeOf(proto, I.prototype);
    for (const k of Reflect.ownKeys(proto)) {
      if (k !== '__ptLinked') delete proto[k];
    }
  };
  const __nodeListProto = {
    get [Symbol.toStringTag]() { return 'NodeList'; },
    // `length` у браузера на прототипе: собственные свойства списка — индексы
    // и только они, и это видно первым же getOwnPropertyNames.
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    forEach(fn, thisArg) { for (let i = 0; i < this.length; i++) fn.call(thisArg, this[i], i, this); },
    *entries() { for (let i = 0; i < this.length; i++) yield [i, this[i]]; },
    *keys() { for (let i = 0; i < this.length; i++) yield i; },
    *values() { for (let i = 0; i < this.length; i++) yield this[i]; },
    [Symbol.iterator]() { return this.values(); },
  };

  const __collectionProto = {
    get [Symbol.toStringTag]() { return 'HTMLCollection'; },
    get length() { return this.__ptLen | 0; },
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

  // `el.attributes` — NamedNodeMap из Attr, а не массив объектов: сборщик
  // отпечатка читает и `Object.prototype.toString`, и цепочку прототипов, и
  // массив там виден сразу.
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
    __link('Attr', __attrProto);
    const a = Object.create(__attrProto);
    Object.defineProperty(a, '__ptName', { value: name });
    Object.defineProperty(a, '__ptValue', { value: value });
    Object.defineProperty(a, '__ptOwner', { value: el });
    return a;
  }
  const __namedNodeMapProto = {
    get [Symbol.toStringTag]() { return 'NamedNodeMap'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    getNamedItem(n) { const k = String(n).toLowerCase();
      for (let i = 0; i < this.length; i++) if (this[i].name === k) return this[i];
      return null; },
    getNamedItemNS(_ns, n) { return this.getNamedItem(n); },
    setNamedItem(a) { if (a && this.__ptOwner) this.__ptOwner.setAttribute(a.name, a.value); return null; },
    setNamedItemNS(a) { return this.setNamedItem(a); },
    removeNamedItem(n) { const a = this.getNamedItem(n);
      if (!a) throw new Error("Failed to execute 'removeNamedItem' on 'NamedNodeMap': No item with name '" + n + "' was found.");
      this.__ptOwner.removeAttribute(a.name); return a; },
    removeNamedItemNS(_ns, n) { return this.removeNamedItem(n); },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __namedNodeMap(el) {
    __link('NamedNodeMap', __namedNodeMapProto);
    const map = Object.create(__namedNodeMapProto);
    let i = 0;
    for (const [name, value] of el.__ptAttrs) map[i++] = __attr(el, name, value);
    Object.defineProperty(map, '__ptLen', { value: i, enumerable: false, configurable: true });
    Object.defineProperty(map, '__ptOwner', { value: el });
    return map;
  }

  // `classList` — DOMTokenList: живой, пишет обратно в атрибут, и это интерфейс,
  // а не литерал с методами.
  const __tokenListProto = {
    get [Symbol.toStringTag]() { return 'DOMTokenList'; },
    get value() { return this.__ptEl.getAttribute('class') || ''; },
    set value(v) { this.__ptEl.setAttribute('class', String(v)); },
    get length() { return this.__ptTokens().length; },
    item(i) { const t = this.__ptTokens(); return i >= 0 && i < t.length ? t[i] : null; },
    contains(c) { return this.__ptTokens().includes(String(c)); },
    add(...cs) { const t = this.__ptTokens();
      for (const c of cs) if (!t.includes(String(c))) t.push(String(c));
      this.__ptEl.setAttribute('class', t.join(' ')); },
    remove(...cs) { const drop = cs.map(String);
      this.__ptEl.setAttribute('class', this.__ptTokens().filter((c) => !drop.includes(c)).join(' ')); },
    toggle(c, force) { const t = this.__ptTokens(), has = t.includes(String(c));
      if (force === true || (force === undefined && !has)) {
        if (!has) t.push(String(c));
        this.__ptEl.setAttribute('class', t.join(' '));
        return true;
      }
      this.__ptEl.setAttribute('class', t.filter((x) => x !== String(c)).join(' '));
      return false; },
    replace(from, to) { const t = this.__ptTokens(), i = t.indexOf(String(from));
      if (i < 0) return false;
      t[i] = String(to); this.__ptEl.setAttribute('class', t.join(' ')); return true; },
    supports() { throw new TypeError("Failed to execute 'supports' on 'DOMTokenList': DOMTokenList has no supported tokens."); },
    forEach(fn, thisArg) { this.__ptTokens().forEach((v, i) => fn.call(thisArg, v, i, this)); },
    *entries() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield [i, t[i]]; },
    *keys() { const t = this.__ptTokens(); for (let i = 0; i < t.length; i++) yield i; },
    *values() { yield* this.__ptTokens(); },
    [Symbol.iterator]() { return this.values(); },
    toString() { return this.value; },
  };
  function __tokenList(el) {
    __link('DOMTokenList', __tokenListProto);
    let list = el.__ptTokenList;
    if (!list) {
      list = Object.create(__tokenListProto);
      Object.defineProperty(list, '__ptEl', { value: el });
      Object.defineProperty(list, '__ptTokens', {
        value: () => (el.getAttribute('class') || '').split(/\s+/).filter(Boolean),
      });
      Object.defineProperty(el, '__ptTokenList', { value: list, enumerable: false, writable: true });
    }
    // Индексы — собственные свойства, как у браузера: `list[0]` работает.
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
      if (deep && this.__ptLocal === 'template' && this.__ptContent) {
        const into = __templateContent(c);
        for (const ch of this.__ptContent.__ptKids) into.appendChild(ch.cloneNode(true));
      }
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
          try { fn.call(node, event); } catch (e) { __pt_reportError(e, 'listener ' + event.type); }
        }
      };
      for (let i = path.length - 1; i >= 1; i--) { if (event.__ptStop) break; if (path[i].__ptLis && path[i].__ptLis[event.type]) { event.eventPhase = 1; fireCapture(path[i], event); } }
      event.eventPhase = 2;
      if (!event.__ptStop) fire(this);
      // Обработчик-свойство (`onclick`, `onload`, `onmessage`) — такой же
      // слушатель цели, и вызывает его тот же dispatch, а не вызывающий код.
      if (!event.__ptStopImm) {
        const on = this['on' + event.type];
        if (typeof on === 'function') { event.currentTarget = this; try { on.call(this, event); } catch (e) { __pt_reportError(e, 'on' + event.type); } }
      }
      if (event.bubbles) for (let i = 1; i < path.length; i++) { if (event.__ptStop) break; event.eventPhase = 3; fire(path[i]); }
      return !event.defaultPrevented;
    }
  }
  // Исключение из обработчика в браузере не пропадает: оно уходит в
  // `window.onerror`, поднимает событие `error` на окне и печатается в консоль.
  // Мы его молча глотали — из-за чего страница, у которой обработчик падает,
  // выглядела как страница, которая просто чего-то ждёт.
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
    for (const e of l.slice()) { if (!e.cap) continue; if (event.__ptStopImm) break; event.currentTarget = node; try { e.fn.call(node, event); } catch (x) { __pt_reportError(x, 'capture ' + event.type); } }
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
  // DocumentFragment — свой интерфейс, а не псевдоним Node: у браузера на нём
  // ровно одиннадцать членов, и `t.content.querySelector(...)` работает именно
  // благодаря им. У нас фрагмент был голым Node, и запрос по нему падал.
  class DocumentFragment extends Node {
    constructor() { super(DOCUMENT_FRAGMENT_NODE); }
    get [Symbol.toStringTag]() { return 'DocumentFragment'; }
    get children() { return __collection(this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE).length; }
    get firstElementChild() { return this.__ptKids.find((n) => n.nodeType === ELEMENT_NODE) || null; }
    get lastElementChild() {
      const k = this.__ptKids.filter((n) => n.nodeType === ELEMENT_NODE);
      return k.length ? k[k.length - 1] : null;
    }
    getElementById(id) { return firstMatch(this, (e) => e.getAttribute('id') === String(id)); }
    querySelector(sel) { return query(this, sel)[0] || null; }
    querySelectorAll(sel) { return __staticNodeList(query(this, sel)); }
    append(...nodes) { for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...nodes) {
      const first = this.__ptKids[0] || null;
      for (const n of nodes) this.insertBefore(typeof n === 'string' ? new Text(n) : n, first);
    }
    replaceChildren(...nodes) {
      this.__ptKids = [];
      for (const n of nodes) this.appendChild(typeof n === 'string' ? new Text(n) : n);
    }
    moveBefore(node, child) { return this.insertBefore(node, child); }
  }

  class ShadowRoot extends DocumentFragment {
    constructor(host, mode) {
      super();
      this.__ptHost = host;
      this.__ptMode = mode;
      this.ownerDocument = host.ownerDocument;
    }
    get [Symbol.toStringTag]() { return 'ShadowRoot'; }
    get host() { return this.__ptHost; }
    get mode() { return this.__ptMode; }
    get nodeName() { return '#document-fragment'; }
    get nodeValue() { return null; }
    get textContent() { return this.__ptKids.map(n => n.textContent).join(''); }
    set textContent(v) { this.__ptKids = []; if (v !== '') this.appendChild(new Text(String(v))); }
    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      // Разметка шаблона разбирается в его содержимое — таков разбор у него.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      host.__ptKids = [];
      for (const n of parseFragment(String(html))) host.appendChild(n);
    }
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
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = String(c).split(/\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = (e.__ptAttrs.get('class') || '').split(/\s+/);
        return cs.every((x) => own.indexOf(x) >= 0);
      }));
    }
    querySelector(sel) { return query(this, sel)[0] || null; }
    querySelectorAll(sel) { return __staticNodeList(query(this, sel)); }
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
      // `new MyElement()` не передаёт имя тега — его знает реестр, по классу,
      // от которого элемент произошёл. Так работает и настоящий HTMLElement.
      if (tag === undefined && new.target) tag = __customName(new.target) || 'unknown';
      this.__ptTag = String(tag).toUpperCase();
      this.__ptLocal = String(tag).toLowerCase();
      this.__ptAttrs = new Map();
      this.__ptStyle = makeStyle(this);
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
    get attributes() { return __namedNodeMap(this); }

    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }
    get classList() { return __tokenList(this); }
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
    // `script.text` — тот же текст, что и textContent, и присвоение ему
    // запускает скрипт. Мы его молча проглатывали: у нас это было обычное
    // свойство, а `s.text = <исходник>; head.appendChild(s)` — как раз то, чем
    // челлендж объявляет свои функции верхнего уровня. Одна такая пропажа
    // роняла его интерпретатор на вызове несуществующей глобали.
    get text() {
      const t = this.tagName;
      if (t === 'SCRIPT' || t === 'TITLE' || t === 'OPTION' || t === 'A') return this.textContent || '';
      return this.getAttribute('text');
    }
    set text(v) {
      this.textContent = String(v);
      if (this.__ptLocal === 'script' && this.isConnected && this.__ptRunScript) this.__ptRunScript();
    }
    // `srcdoc` — документ, написанный прямо в атрибуте: у него нет адреса, и
    // отражается он как есть. Присвоение после вставки в документ означает
    // новый документ в этом окне, как навигация.
    get srcdoc() { const v = this.getAttribute('srcdoc'); return v === null ? '' : v; }
    set srcdoc(v) {
      this.setAttribute('srcdoc', v);
      if (this.__ptLocal !== 'iframe') return;
      try {
        const w = this.__ptRealm || (this.isConnected ? this.__ptRealmWindow() : null);
        if (w && typeof w.__pt_writeDocument === 'function') w.__pt_writeDocument(String(v));
      } catch (e) {}
    }
    get sandbox() { return this.getAttribute('sandbox') || ''; }
    set sandbox(v) { this.setAttribute('sandbox', v); }
    get allow() { return this.getAttribute('allow') || ''; }
    set allow(v) { this.setAttribute('allow', v); }
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

    get children() { return __collection(this.__ptKids.filter(n => n.nodeType === ELEMENT_NODE)); }
    get childElementCount() { return this.children.length; }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get nextElementSibling() { let n = this.nextSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.nextSibling; return n; }
    get previousElementSibling() { let n = this.previousSibling; while (n && n.nodeType !== ELEMENT_NODE) n = n.previousSibling; return n; }

    append(...ns) { for (const n of ns) this.appendChild(typeof n === 'string' ? new Text(n) : n); }
    prepend(...ns) { for (const n of ns.reverse()) this.insertBefore(typeof n === 'string' ? new Text(n) : n, this.firstChild); }

    // Queries (scoped to this subtree)
    getElementById(id) { return firstMatch(this, e => e.id === id); }
    getElementsByTagName(t) { return __collection(__tags(this, t)); }
    getElementsByClassName(c) {
      const cs = String(c).split(/\s+/).filter(Boolean);
      return __collection(collect(this, (e) => {
        const own = (e.__ptAttrs.get('class') || '').split(/\s+/);
        return cs.every((x) => own.indexOf(x) >= 0);
      }));
    }
    querySelector(sel) { return query(this, sel)[0] || null; }
    querySelectorAll(sel) { return __staticNodeList(query(this, sel)); }
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
      // Пустое окно — не пустой документ: у браузера там html/head/body, и
      // страница туда пишет. `srcdoc` кладётся тем же путём.
      try {
        const markup = this.getAttribute('srcdoc');
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
      try { (0, eval)(code); } catch (e) { __pt_reportError(e, 'inline script'); }
    }

    __ptConnectFrame() {
      if (this.__ptFrameId || this.__ptLocal !== 'iframe') return;
      const src = this.getAttribute('src');
      // `about:blank` — не адрес, за которым идут в сеть: у браузера это тот же
      // начальный пустой документ, что и у кадра без src, и реалм в нём готов
      // сразу. Отличать их — значит ронять `f.src='about:blank';
      // body.appendChild(f); f.contentWindow.eval(…)`, а это штатный способ
      // взять нетронутые встроенные функции, которым челленджи и пользуются.
      const blank = !src || /^about:blank(\?|#|$)/.test(src.trim());
      if (blank) {
        // Кадр с `srcdoc` грузится сам, как только попал в документ, — ждать,
        // пока кто-нибудь прочитает `contentWindow`, браузер не заставляет.
        if (src || this.getAttribute('srcdoc') !== null) { try { this.__ptRealmWindow(); } catch (e) {} }
        return;
      }
      const id = __nextFrameId++;
      Object.defineProperty(this, '__ptFrameId', { value: id, configurable: true, enumerable: false });
      // Размер элемента едет вместе с запросом: контекст кадра должен знать своё
      // окно до того, как в нём выполнится первая строка. Спрашивать раскладку
      // здесь нельзя — вставка идёт посреди разбора, и построенная в этот момент
      // раскладка застынет недостроенной; берём заявленный размер.
      const box = __ptJSON.parse(globalThis.__pt_frameBoxOf ? __pt_frameBoxOf(this) : '[300,150]');
      const st = { el: this, ready: false, sameOrigin: false, win: null, doc: null, pending: [] };
      st.win = __frameWindow(id, st);
      __frames.set(id, st);
      __frameOps.push({ op: 'open', id, src, w: box[0] || 300, h: box[1] || 150 });
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

    get innerHTML() {
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      return host.__ptKids.map(serializeNode).join('');
    }
    set innerHTML(html) {
      // Разметка шаблона разбирается в его содержимое — таков разбор у него.
      const host = this.__ptLocal === 'template' ? __templateContent(this) : this;
      host.__ptKids = [];
      for (const n of parseFragment(String(html))) host.appendChild(n);
    }
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

    __ptShallowClone() {
      const e = new Element(this.localName);
      e.__ptAttrs = new Map(this.__ptAttrs);
      // Клон стоит на той же ступени лестницы интерфейсов, что и оригинал:
      // копия `<template>` — тоже HTMLTemplateElement, а копия `<div>` —
      // HTMLDivElement. Без этого клон был просто Element, и всё, что живёт на
      // его интерфейсе, у копии пропадало.
      try {
        if (this.__ptNS && globalThis.__pt_svgProto) {
          const p = __pt_svgProto(this.localName);
          if (p) { Object.setPrototypeOf(e, p); e.__ptNS = this.__ptNS; }
        } else if (globalThis.__pt_elementProto) {
          Object.setPrototypeOf(e, __pt_elementProto(this.localName));
        }
      } catch (x) {}
      e.ownerDocument = this.ownerDocument;
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
    get head() { return this.documentElement && __tags(this.documentElement, 'head')[0] || null; }
    get body() { return this.documentElement && __tags(this.documentElement, 'body')[0] || null; }
    get title() { const t = this.documentElement ? __tags(this.documentElement, 'title')[0] : null; return t ? t.textContent.trim() : ''; }
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
    // Коллекции документа — это HTMLCollection, а не массив: `Array.isArray`
    // на них ложен, а сборщик отпечатка кладёт массив в корзину по его
    // строковому значению, из-за чего пустой список выглядел как пустая строка.
    get scripts() { return __collection(__docTags(this, 'script')); }
    get forms() { return __collection(__docTags(this, 'form')); }
    get images() { return __collection(__docTags(this, 'img')); }
    get embeds() { return __collection(__docTags(this, 'embed')); }
    get plugins() { return __collection(__docTags(this, 'embed')); }
    // `links` is `<a>`/`<area>` *with an href*, and `anchors` is `<a>` with a name.
    get links() {
      return __collection(__docTags(this, 'a').concat(__docTags(this, 'area'))
        .filter(e => e.hasAttribute('href')));
    }
    get anchors() { return __collection(__docTags(this, 'a').filter(e => e.hasAttribute('name'))); }
    get styleSheets() {
      return __styleSheetList(__docTags(this, 'style')
        .concat(__docTags(this, 'link').filter((e) => /stylesheet/i.test(e.getAttribute('rel') || ''))));
    }
    // Кодировка — объявленная, а не всегда UTF-8: страница без объявления
    // разбирается как windows-1252, и Chrome именно это и сообщает. Отвечать
    // «UTF-8» на документ, который ничего не объявил, — заметная разница.
    get characterSet() {
      if (this.__ptCharset) return this.__ptCharset;
      for (const m of __docTags(this, 'meta')) {
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
      if (globalThis.__pt_setPendingTag) __pt_setPendingTag(tag);
      const e = C ? new C() : new Element(tag);
      if (C) Object.defineProperty(e, '__ptUpgraded', { value: true, configurable: true, enumerable: false });
      // Элемент стоит на своей ступени лестницы интерфейсов: `<canvas>` — на
      // HTMLCanvasElement, неизвестный тег — на HTMLUnknownElement.
      if (!C && globalThis.__pt_elementProto) {
        try { Object.setPrototypeOf(e, __pt_elementProto(tag)); } catch (x) {}
      }
      e.ownerDocument = this;
      return e;
    }
    createElementNS(ns, tag) {
      const e = this.createElement(tag);
      if (String(ns) === 'http://www.w3.org/2000/svg' && globalThis.__pt_svgProto) {
        const proto = __pt_svgProto(String(tag));
        // Имя тега в SVG регистрозависимо: `clipPath`, не `clippath`.
        if (proto) { try { Object.setPrototypeOf(e, proto); e.__ptNS = String(ns); e.__ptLocal = String(tag); } catch (x) {} }
      }
      return e;
    }
    createTextNode(t) { const n = new Text(t); n.ownerDocument = this; return n; }
    createComment(t) { const n = new Comment(t); n.ownerDocument = this; return n; }
    createDocumentFragment() { const f = new DocumentFragment(); f.ownerDocument = this; return f; }
    createEvent() { return new Event(''); }

    getElementById(id) { return this.documentElement ? this.documentElement.getElementById(id) : null; }
    getElementsByTagName(t) { return __collection(this.documentElement ? __tags(this.documentElement, t) : []); }
    getElementsByClassName(c) { return this.documentElement ? this.documentElement.getElementsByClassName(c) : []; }
    querySelector(s) { return this.documentElement ? this.documentElement.querySelector(s) : null; }
    querySelectorAll(s) { return __staticNodeList(this.documentElement ? query(this.documentElement, s) : []); }

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
  const __ptTrust = (ev) => {
    if (ev && ev.__ptE) ev.__ptE.isTrusted = true;
    else if (ev) { try { Object.defineProperty(ev, 'isTrusted', { value: true, configurable: true }); } catch (e) {} }
    return ev;
  };
  // Воркерная область объявляется отдельным скриптом и метит свои доставки этим.
  try { Object.defineProperty(globalThis, '__pt_trustEvent', { value: __ptTrust, enumerable: false, configurable: true }); } catch (e) {}

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
    try { data = __ptJSON.parse(json); } catch (e) {}
    const ev = __ptTrust(new MessageEvent('message', { data, origin: '', source: null }));
    try { ev.target = W.worker; ev.currentTarget = W.worker; } catch (e) {}
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
      try { json = __ptJSON.stringify(data === undefined ? null : data); } catch (e) {}
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
      let c = globalThis.document ? globalThis.document.createElement('canvas') : null;
      // В воркере документа нет вовсе, а OffscreenCanvas там есть и рисует —
      // ради него он в воркере и существует. Холст без документа: методы те же,
      // что у элемента, размеры свои. Без этого `getContext('2d')` в воркере
      // отдавал null, и сборщик, который снимает там отпечаток холста, молча
      // оставался ни с чем.
      if (!c) {
        const proto = globalThis.__pt_canvasProto;
        c = { localName: 'canvas', width: width | 0, height: height | 0 };
        if (proto) { c.getContext = proto.getContext; c.toDataURL = proto.toDataURL; }
      }
      c.width = width | 0; c.height = height | 0;
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
  // ---- CSSOM ---------------------------------------------------------------
  // Настоящие таблицы стилей: `document.styleSheets` был списком литералов с
  // пустым `cssRules`, а сборщик Cloudflare читает его сотнями обращений в
  // начале второй стадии — правила, селекторы, cssText. Формы интерфейсов и
  // сериализация сняты с Chrome 148.
  //
  // Значения приводятся так же, как приводит браузер там, где это видно
  // невооружённым глазом: `0` в свойстве длины становится `0px`, комбинаторы
  // селектора разделяются пробелами, после двоеточия в условии @media — пробел.
  const CSS_LENGTH_PROPS = new Set([
    'width', 'height', 'min-width', 'min-height', 'max-width', 'max-height',
    'top', 'right', 'bottom', 'left', 'margin', 'margin-top', 'margin-right',
    'margin-bottom', 'margin-left', 'padding', 'padding-top', 'padding-right',
    'padding-bottom', 'padding-left', 'border-width', 'border-top-width',
    'border-right-width', 'border-bottom-width', 'border-left-width',
    'border-radius', 'font-size', 'letter-spacing', 'word-spacing', 'text-indent',
    'outline-width', 'column-gap', 'row-gap', 'gap', 'inset',
  ]);
  const __cssValue = (prop, value) => {
    const v = String(value).trim().replace(/\s+/g, ' ');
    if (!CSS_LENGTH_PROPS.has(prop)) return v;
    return v.replace(/(^|[\s(])(-?\d+(?:\.\d+)?)(?=$|[\s)])/g, (m, pre, num) => pre + num + 'px');
  };
  const __cssSelector = (sel) => String(sel).trim()
    .replace(/\s+/g, ' ')
    .replace(/\s*([>+~])\s*/g, ' $1 ')
    .replace(/\s*,\s*/g, ', ');
  const __cssPrelude = (p) => String(p).trim().replace(/\s+/g, ' ').replace(/:\s*/g, ': ');

  // Разбор: пролог до `{` или `;`, затем тело со счётом вложенности. Строки и
  // комментарии не считаются — иначе `content: "}"` рвёт правило пополам.
  function __cssParse(text) {
    const out = [];
    const n = text.length;
    let i = 0;
    while (i < n) {
      while (i < n && /\s/.test(text[i])) i++;
      if (i >= n) break;
      if (text.startsWith('/*', i)) { const e = text.indexOf('*/', i + 2); i = e < 0 ? n : e + 2; continue; }
      const start = i;
      let depth = 0, q = null;
      while (i < n) {
        const c = text[i];
        if (q) { if (c === q && text[i - 1] !== '\\') q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (depth === 0 && (c === '{' || c === ';')) break;
        i++;
      }
      const prelude = text.slice(start, i).trim();
      if (i >= n) { if (prelude) out.push({ prelude, statement: true }); break; }
      if (text[i] === ';') { i++; if (prelude) out.push({ prelude, statement: true }); continue; }
      i++;                                    // за '{'
      const bodyStart = i;
      let d = 1;
      q = null;
      while (i < n && d > 0) {
        const c = text[i];
        if (q) { if (c === q && text[i - 1] !== '\\') q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '{') d++;
        else if (c === '}') d--;
        i++;
      }
      out.push({ prelude, body: text.slice(bodyStart, d === 0 ? i - 1 : i) });
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
        if (q) { if (c === q && body[i - 1] !== '\\') q = null; i++; continue; }
        if (c === '"' || c === "'") { q = c; i++; continue; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
        else if (c === ';' && depth === 0) break;
        i++;
      }
      const decl = body.slice(start, i).trim();
      i++;
      if (!decl) continue;
      const colon = decl.indexOf(':');
      if (colon <= 0) continue;
      const prop = decl.slice(0, colon).trim().toLowerCase();
      if (prop) map.set(prop, __cssValue(prop, decl.slice(colon + 1)));
    }
    return map;
  }

  // Блок объявлений правила: тот же интерфейс, что у `el.style`, но за ним
  // стоит карта правила, а не атрибут элемента.
  function __cssDeclaration(map) {
    const dash = (p) => String(p).replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());
    const target = Object.assign(Object.create(__styleProto()), {
      getPropertyValue: (p) => map.get(String(p).toLowerCase()) || '',
      getPropertyPriority: () => '',
      setProperty: (p, v) => { map.set(dash(String(p)).toLowerCase(), __cssValue(dash(String(p)).toLowerCase(), v)); },
      removeProperty: (p) => { const k = dash(String(p)).toLowerCase(); const had = map.get(k) || ''; map.delete(k); return had; },
      item: (i) => [...map.keys()][i] || '',
      get length() { return map.size; },
      get cssText() { return [...map].map(([k, v]) => k + ': ' + v + ';').join(' '); },
      get parentRule() { return null; },
      [Symbol.iterator]: function* () { for (const k of map.keys()) yield k; },
    });
    return new Proxy(target, {
      get: (t, p) => {
        if (typeof p === 'string' && !(p in t)) return map.get(dash(p).toLowerCase()) || '';
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (typeof p === 'string' && !(p in t)) { const k = dash(p).toLowerCase(); map.set(k, __cssValue(k, v)); return true; }
        t[p] = v; return true;
      },
    });
  }

  const __ruleListProto = {
    get [Symbol.toStringTag]() { return 'CSSRuleList'; },
    get length() { return this.__ptLen | 0; },
    item(i) { return this[i] != null ? this[i] : null; },
    [Symbol.iterator]() { let i = 0; const self = this;
      return { next: () => i < self.length ? { value: self[i++], done: false } : { value: undefined, done: true } }; },
  };
  function __cssRuleList(arr) {
    __link('CSSRuleList', __ruleListProto);
    const list = Object.create(__ruleListProto);
    for (let i = 0; i < arr.length; i++) list[i] = arr[i];
    Object.defineProperty(list, '__ptLen', { value: arr.length, enumerable: false, configurable: true });
    return list;
  }

  const __mediaListProto = {
    get [Symbol.toStringTag]() { return 'MediaList'; },
    get mediaText() { return this.__ptMedia.join(', '); },
    set mediaText(v) { this.__ptMedia = String(v).split(',').map((s) => s.trim()).filter(Boolean); },
    get length() { return this.__ptMedia.length; },
    item(i) { return this.__ptMedia[i] != null ? this.__ptMedia[i] : null; },
    appendMedium(m) { if (!this.__ptMedia.includes(String(m))) this.__ptMedia.push(String(m)); },
    deleteMedium(m) { this.__ptMedia = this.__ptMedia.filter((x) => x !== String(m)); },
    toString() { return this.mediaText; },
  };
  function __mediaList(text) {
    __link('MediaList', __mediaListProto);
    const m = Object.create(__mediaListProto);
    Object.defineProperty(m, '__ptMedia', {
      value: String(text || '').split(',').map((s) => s.trim()).filter(Boolean),
      writable: true, enumerable: false,
    });
    return m;
  }

  // Правила. Числа типов — те же, что у CSSRule в браузере.
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
  function __makeRule(parsed, sheet, parent) {
    const prelude = parsed.prelude || '';
    const at = prelude.charCodeAt(0) === 64 ? prelude.split(/[\s({]/)[0].toLowerCase() : '';
    const own = (r, props) => { for (const k of Object.keys(props)) Object.defineProperty(r, k, { value: props[k], enumerable: true, configurable: true }); return r; };
    const common = (r, type) => own(r, {
      type, parentStyleSheet: sheet, parentRule: parent || null,
    });

    if (at === '@import') {
      const href = (/url\(\s*["']?([^"')]*)["']?\s*\)|["']([^"']*)["']/.exec(prelude) || [])
        .slice(1).find((x) => x !== undefined) || '';
      const r = common(Object.create(__ruleProto('CSSImportRule')), RULE_TYPE.import);
      return own(r, { href, layerName: null, supportsText: null, styleSheet: null,
                      media: __mediaList(''), cssText: '@import url("' + href + '");' });
    }
    if (at === '@media' || at === '@supports') {
      const name = at === '@media' ? 'CSSMediaRule' : 'CSSSupportsRule';
      const r = common(Object.create(__ruleProto(name)), at === '@media' ? RULE_TYPE.media : RULE_TYPE.supports);
      const cond = __cssPrelude(prelude.slice(at.length).trim());
      const kids = __cssParse(parsed.body || '').map((p) => __makeRule(p, sheet, r));
      own(r, { cssRules: __cssRuleList(kids), conditionText: cond });
      if (at === '@media') own(r, { media: __mediaList(cond) });
      return own(r, { cssText: at + ' ' + cond + ' { ' + kids.map((k) => k.cssText).join(' ') + ' }' });
    }
    if (at === '@keyframes' || at === '@-webkit-keyframes') {
      const r = common(Object.create(__ruleProto('CSSKeyframesRule')), RULE_TYPE.keyframes);
      const kids = __cssParse(parsed.body || '').map((p) => {
        const k = common(Object.create(__ruleProto('CSSKeyframeRule')), RULE_TYPE.keyframe);
        const decls = __cssDecls(p.body || '');
        return own(k, { keyText: __cssPrelude(p.prelude), style: __cssDeclaration(decls),
                        cssText: __cssPrelude(p.prelude) + ' { ' + [...decls].map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
      });
      const name = prelude.slice(at.length).trim();
      return own(r, { name, length: kids.length, cssRules: __cssRuleList(kids),
                      appendRule() {}, deleteRule() {}, findRule() { return null; },
                      cssText: '@keyframes ' + name + ' { ' + kids.map((k) => k.cssText).join(' ') + ' }' });
    }
    if (at === '@font-face') {
      const r = common(Object.create(__ruleProto('CSSFontFaceRule')), RULE_TYPE['font-face']);
      const decls = __cssDecls(parsed.body || '');
      return own(r, { style: __cssDeclaration(decls),
                      cssText: '@font-face { ' + [...decls].map(([a2, b2]) => a2 + ': ' + b2 + ';').join(' ') + ' }' });
    }
    if (at) {
      const r = common(Object.create(__ruleProto('CSSRule')), RULE_TYPE.charset);
      return own(r, { cssText: prelude + (parsed.statement ? ';' : ' { }') });
    }
    const r = common(Object.create(__ruleProto('CSSStyleRule')), RULE_TYPE.style);
    const decls = __cssDecls(parsed.body || '');
    const sel = __cssSelector(prelude);
    const body = [...decls].map(([k, v]) => k + ': ' + v + ';').join(' ');
    return own(r, { selectorText: sel, style: __cssDeclaration(decls),
                    cssRules: __cssRuleList([]), insertRule() { return 0; }, deleteRule() {},
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
      const rules = __cssParse(String(text)).map((p) => __makeRule(p, this, null));
      Object.defineProperty(this, 'cssRules', { value: __cssRuleList(rules), enumerable: true, configurable: true });
    },
    replace(text) { this.replaceSync(text); return Promise.resolve(this); },
  };
  // Таблица живёт на своём элементе: страницы сравнивают
  // `document.styleSheets[0] === document.styleSheets[0]`, и правила
  // пересобираются только когда сменился текст.
  globalThis.__pt_sheetFor = (owner) => __sheetFor(owner);
  function __sheetFor(owner) {
    __link('CSSStyleSheet', __sheetProto);
    const text = owner.__ptLocal === 'style' ? String(owner.textContent || '') : '';
    let sheet = owner.__ptSheet;
    if (!sheet) {
      sheet = Object.create(__sheetProto);
      Object.defineProperty(owner, '__ptSheet', { value: sheet, writable: true, enumerable: false });
      const href = owner.__ptLocal === 'link' ? (owner.href || null) : null;
      Object.defineProperty(sheet, 'ownerNode', { value: owner, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'href', { value: href, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'type', { value: 'text/css', enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'disabled', { value: false, writable: true, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'title', { value: owner.getAttribute('title'), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'media', { value: __mediaList(owner.getAttribute('media') || ''), enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'parentStyleSheet', { value: null, enumerable: true, configurable: true });
      Object.defineProperty(sheet, 'ownerRule', { value: null, enumerable: true, configurable: true });
    }
    if (sheet.__ptText !== text) {
      Object.defineProperty(sheet, '__ptText', { value: text, writable: true, enumerable: false, configurable: true });
      const rules = __cssParse(text).map((p) => __makeRule(p, sheet, null));
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
    __link('StyleSheetList', __sheetListProto);
    const list = Object.create(__sheetListProto);
    for (let i = 0; i < owners.length; i++) list[i] = __sheetFor(owners[i]);
    Object.defineProperty(list, '__ptLen', { value: owners.length, enumerable: false, configurable: true });
    return list;
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
  // `el.style` и атрибут `style` — два вида на одно и то же. У нас это были два
  // независимых хранилища: `setAttribute('style','width:300px')` не доходил до
  // `el.style.width`, а `el.style.width = …` не доходил до атрибута. Отсюда же
  // и кадр, который не знал своего размера: раскладка читает одно, страница
  // пишет другое.
  // Инлайновый стиль тоже CSSStyleDeclaration: `el.style` в браузере и
  // `getComputedStyle(el)` — один интерфейс, и сборщик читает его имя.
  const __styleProto = () => {
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    return proto;
  };
  function makeStyle(el) {
    let cachedText = null, cachedMap = new Map();
    const read = () => {
      const text = String((el && el.getAttribute && el.getAttribute('style')) || '');
      if (text === cachedText) return cachedMap;
      const m = new Map();
      for (const part of text.split(';')) {
        const i = part.indexOf(':');
        if (i < 0) continue;
        const k = part.slice(0, i).trim().toLowerCase();
        const v = part.slice(i + 1).trim();
        if (k) m.set(k, v);
      }
      cachedText = text; cachedMap = m;
      return m;
    };
    const write = (m) => {
      const text = [...m].map(([k, v]) => `${k}: ${v}`).join('; ');
      cachedText = text; cachedMap = m;
      if (el && el.setAttribute) el.setAttribute('style', text);
      __markDirty();
    };
    return new Proxy(Object.assign(Object.create(__styleProto()), {
      getPropertyValue: (p) => read().get(String(p).toLowerCase()) || '',
      getPropertyPriority: () => '',
      get parentRule() { return null; },
      get cssFloat() { return read().get('float') || ''; },
      set cssFloat(v) { const m = read(); m.set('float', String(v)); write(m); },
      setProperty: (p, v) => { const m = read(); m.set(String(p).toLowerCase(), String(v)); write(m); },
      removeProperty: (p) => { const m = read(); const had = m.get(String(p).toLowerCase()) || ''; m.delete(String(p).toLowerCase()); write(m); return had; },
      get cssText() { return [...read()].map(([k, v]) => `${k}: ${v}`).join('; '); },
      set cssText(v) { if (el && el.setAttribute) el.setAttribute('style', String(v)); cachedText = null; __markDirty(); },
      get length() { return read().size; },
      item: (i) => [...read().keys()][i] || '',
    }), {
      get: (t, p) => {
        if (typeof p === 'string' && !(p in t)) return read().get(dash(p)) || '';
        const v = t[p];
        return typeof v === 'function' ? v.bind(t) : v;
      },
      set: (t, p, v) => {
        if (p === 'cssText') { t.cssText = v; return true; }
        const m = read(); m.set(dash(String(p)), String(v)); write(m); return true;
      },
    });
  }

  // ---- tree walking ---------------------------------------------------------
  // Внутри движка нужен массив (concat/filter), наружу — коллекция.
  function __docTags(doc, t) { return doc.documentElement ? __tags(doc.documentElement, t) : []; }
  function __tags(root, t) {
    // По внутреннему имени, не через `tagName`: свой обход не должен ходить
    // через акцессоры, которые страница видит (и может подменить), — иначе
    // один `document.body` оставляет в её ленте десяток чужих чтений.
    const local = String(t).toLowerCase();
    return collect(root, (e) => t === '*' || e.__ptLocal === local);
  }
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
  // `<template>` держит разобранное содержимое не в себе, а в отдельном
  // DocumentFragment: `t.content`. У нас его не было вовсе, разобранные дети
  // терялись, и код, который строит узлы через шаблон — а так делает и
  // челлендж Cloudflare — получал undefined там, где ждал фрагмент.
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
    const el = doc.createElement(spec.tag);
    // A parser-built script is "already started": the engine runs the document's
    // scripts itself, in document order, so connecting the tree must not run them
    // a second time. Only what a page inserts later goes through `__ptRunScript`.
    if (spec.tag === 'script') {
      Object.defineProperty(el, '__ptRan', { value: true, configurable: true, enumerable: false });
    }
    for (const [name, value] of spec.attrs) el.setAttribute(name, value);
    // Разбор кладёт детей шаблона в его содержимое, а сам элемент оставляет
    // пустым — `t.childNodes.length === 0` и в браузере тоже.
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
  // В браузере интерфейсы элементов — лестница: Element → HTMLElement →
  // HTMLCanvasElement и так далее, и у каждой ступени свои члены. У нас все они
  // были **одним объектом**: `HTMLCanvasElement.prototype === HTMLDivElement
  // .prototype === Element.prototype`, поэтому `div instanceof HTMLCanvasElement`
  // отвечало true, а `constructor.name` любого элемента — `Element`. Строим
  // лестницу; сами члены пока живут на Element, их развес — следующим шагом.
  const __ifaceProto = new Map();
  let __pendingTag = 'div';
  const __mkIface = (name, parentProto) => {
    const C = function () {
      // `new HTMLElement()` в браузере бросает, но `super()` из класса
      // кастомного элемента обязан работать — это его штатный путь.
      if (new.target && new.target !== C) return Reflect.construct(Element, [__pendingTag], new.target);
      throw new TypeError("Illegal constructor");
    };
    try { Object.defineProperty(C, 'name', { value: name, configurable: true }); } catch (e) {}
    C.prototype = Object.create(parentProto);
    Object.defineProperty(C.prototype, 'constructor', { value: C, writable: true, configurable: true });
    try { Object.defineProperty(C.prototype, Symbol.toStringTag, { value: name, configurable: true }); } catch (e) {}
    globalThis[name] = globalThis.__pt_native ? __pt_native(C) : C;
    return C.prototype;
  };
  const __htmlProto = __mkIface('HTMLElement', Element.prototype);
  // Тег → интерфейс, снято с Chrome 148.
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
  // Теги без своего интерфейса, но известные HTML: у них HTMLElement.
  const PLAIN_TAGS = new Set(['abbr', 'address', 'article', 'aside', 'b', 'bdi', 'bdo',
    'cite', 'code', 'dd', 'dfn', 'dt', 'em', 'figcaption', 'figure', 'footer', 'header',
    'hgroup', 'i', 'kbd', 'main', 'mark', 'nav', 'noscript', 'rp', 'rt', 'ruby', 's',
    'samp', 'search', 'section', 'small', 'strong', 'sub', 'summary', 'sup', 'u', 'var',
    'wbr', 'center', 'font', 'big', 'strike', 'tt', 'nobr']);
  for (const name of new Set(Object.values(TAG_IFACE))) __ifaceProto.set(name, __mkIface(name, __htmlProto));
  // Мультимедиа наследует HTMLMediaElement, как в браузере.
  const __mediaProto = __mkIface('HTMLMediaElement', __htmlProto);
  for (const n of ['HTMLVideoElement', 'HTMLAudioElement']) {
    try { Object.setPrototypeOf(globalThis[n].prototype, __mediaProto); } catch (e) {}
  }
  __ifaceProto.set('HTMLUnknownElement', __mkIface('HTMLUnknownElement', __htmlProto));
  for (const n of ['HTMLFrameSetElement', 'HTMLFrameElement', 'HTMLMarqueeElement',
                   'HTMLDirectoryElement', 'HTMLFontElement', 'HTMLParamElement']) {
    if (!globalThis[n]) __mkIface(n, __htmlProto);
  }
  globalThis.__pt_elementProto = (tag) => {
    tag = String(tag).toLowerCase();
    const iface = TAG_IFACE[tag];
    if (iface) return __ifaceProto.get(iface) || __htmlProto;
    if (PLAIN_TAGS.has(tag)) return __htmlProto;
    // Всё, чего в HTML нет, — HTMLUnknownElement, как у браузера.
    return /^[a-z][a-z0-9]*(-[a-z0-9]+)+$/.test(tag) ? __htmlProto : __ifaceProto.get('HTMLUnknownElement');
  };
  globalThis.__pt_setPendingTag = (tag) => { __pendingTag = String(tag || 'div'); };
  // `sheet` — таблица стилей самого элемента, та же, что лежит в
  // `document.styleSheets`. Мы построили список, но с элементом его не связали,
  // а читают чаще именно так: `document.querySelector('style').sheet.cssRules`.
  for (const iface of ['HTMLStyleElement', 'HTMLLinkElement']) {
    const proto = globalThis[iface] && globalThis[iface].prototype;
    if (!proto) continue;
    Object.defineProperty(proto, 'sheet', {
      get() {
        if (this.__ptLocal === 'link' && !/stylesheet/i.test(this.getAttribute('rel') || '')) return null;
        if (!this.isConnected) return null;
        return globalThis.__pt_sheetFor ? __pt_sheetFor(this) : null;
      },
      enumerable: true, configurable: true,
    });
  }
  // `complete` у изображения ложен только пока загрузка в полёте. Мы за
  // картинками в сеть не ходим, значит попытка всегда уже завершена — как и у
  // браузера для картинки без src или с неудачной загрузкой.
  {
    const proto = globalThis.HTMLImageElement && HTMLImageElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'complete', {
        get() { return true; }, enumerable: true, configurable: true,
      });
    }
  }
  // Члены HTMLTemplateElement, снятые с Chrome 148. `content` — сам фрагмент,
  // остальные отражают атрибуты объявленного теневого корня.
  {
    const proto = globalThis.HTMLTemplateElement && HTMLTemplateElement.prototype;
    if (proto) {
      Object.defineProperty(proto, 'content', {
        get() { return globalThis.__pt_templateContent ? __pt_templateContent(this) : null; },
        enumerable: true, configurable: true,
      });
      const attr = (name, want) => Object.defineProperty(proto, name, {
        get() { const v = this.getAttribute(want); return v === null ? (want === 'shadowrootmode' ? '' : false) : (want === 'shadowrootmode' ? v : true); },
        set(v) { if (want === 'shadowrootmode') this.setAttribute(want, String(v)); else if (v) this.setAttribute(want, ''); else this.removeAttribute(want); },
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
  // Ссылка на прототип холста переживает обрезку глобалей воркерной области:
  // OffscreenCanvas берёт методы отсюда, когда документа нет.
  try {
    Object.defineProperty(globalThis, '__pt_canvasProto', {
      value: globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype,
      enumerable: false, configurable: true, writable: true,
    });
  } catch (e) {}
  // SVG — своя лестница, и она глубже HTML: `<path>` это SVGPathElement →
  // SVGGeometryElement → SVGGraphicsElement → SVGElement → Element. У нас любой
  // `createElementNS('…/svg', 'path')` был HTMLUnknownElement, и виджет, который
  // рисует свою галочку из path/line/circle, отдавал сборщику чужие имена.
  // Цепочки сняты с Chrome 148.
  const SVG_CHAIN = {"svg":["SVGSVGElement","SVGGraphicsElement","SVGElement"],"path":["SVGPathElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"line":["SVGLineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"circle":["SVGCircleElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"g":["SVGGElement","SVGGraphicsElement","SVGElement"],"rect":["SVGRectElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"text":["SVGTextElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"tspan":["SVGTSpanElement","SVGTextPositioningElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"defs":["SVGDefsElement","SVGGraphicsElement","SVGElement"],"use":["SVGUseElement","SVGGraphicsElement","SVGElement"],"polygon":["SVGPolygonElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"polyline":["SVGPolylineElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"ellipse":["SVGEllipseElement","SVGGeometryElement","SVGGraphicsElement","SVGElement"],"image":["SVGImageElement","SVGGraphicsElement","SVGElement"],"clipPath":["SVGClipPathElement","SVGElement"],"mask":["SVGMaskElement","SVGElement"],"pattern":["SVGPatternElement","SVGElement"],"filter":["SVGFilterElement","SVGElement"],"marker":["SVGMarkerElement","SVGElement"],"symbol":["SVGSymbolElement","SVGGraphicsElement","SVGElement"],"title":["SVGTitleElement","SVGElement"],"desc":["SVGDescElement","SVGElement"],"style":["SVGStyleElement","SVGElement"],"a":["SVGAElement","SVGGraphicsElement","SVGElement"],"foreignObject":["SVGForeignObjectElement","SVGGraphicsElement","SVGElement"],"linearGradient":["SVGLinearGradientElement","SVGGradientElement","SVGElement"],"radialGradient":["SVGRadialGradientElement","SVGGradientElement","SVGElement"],"stop":["SVGStopElement","SVGElement"],"animate":["SVGAnimateElement","SVGAnimationElement","SVGElement"],"textPath":["SVGTextPathElement","SVGTextContentElement","SVGGraphicsElement","SVGElement"],"switch":["SVGSwitchElement","SVGGraphicsElement","SVGElement"],"metadata":["SVGMetadataElement","SVGElement"],"view":["SVGViewElement","SVGElement"],"set":["SVGSetElement","SVGAnimationElement","SVGElement"],"script":["SVGScriptElement","SVGElement"]};
  {
    const svgProto = new Map();
    // Строим снизу вверх: каждая ступень наследует следующей за ней в цепочке.
    const protoFor = (chain, i) => {
      const name = chain[i];
      if (svgProto.has(name)) return svgProto.get(name);
      const parent = i + 1 < chain.length ? protoFor(chain, i + 1) : Element.prototype;
      const proto = __mkIface(name, parent);
      svgProto.set(name, proto);
      return proto;
    };
    for (const chain of Object.values(SVG_CHAIN)) protoFor(chain, 0);
    // Промежуточные интерфейсы, которых нет первым звеном ни у одного тега.
    for (const n of ['SVGGeometryElement', 'SVGGraphicsElement', 'SVGElement',
                     'SVGTextPositioningElement', 'SVGTextContentElement',
                     'SVGGradientElement', 'SVGAnimationElement', 'SVGComponentTransferFunctionElement']) {
      if (!svgProto.has(n)) svgProto.set(n, __mkIface(n, svgProto.get('SVGElement') || Element.prototype));
    }
    globalThis.__pt_svgProto = (tag) => svgProto.get((SVG_CHAIN[tag] || [])[0]) ||
                                        svgProto.get('SVGElement') || null;
  }


  // `hidden` — отражаемый атрибут HTMLElement: мы его читали внутри себя, но
  // наружу не отдавали вовсе, хотя в браузере он есть у каждого элемента.
  Object.defineProperty(__htmlProto, 'hidden', {
    get() { return this.hasAttribute('hidden'); },
    set(v) { if (v) this.setAttribute('hidden', ''); else this.removeAttribute('hidden'); },
    enumerable: true, configurable: true,
  });

  // Развес членов по ступеням — списки сняты с Chrome 148. Наши реализации
  // универсальны (читают атрибуты), поэтому член, который в браузере есть у
  // нескольких интерфейсов, кладётся на каждый из них тем же дескриптором.
const CHROME_ELEMENT = ["activeViewTransition","after","animate","append","ariaActiveDescendantElement","ariaAtomic","ariaAutoComplete","ariaBrailleLabel","ariaBrailleRoleDescription","ariaBusy","ariaChecked","ariaColCount","ariaColIndex","ariaColIndexText","ariaColSpan","ariaControlsElements","ariaCurrent","ariaDescribedByElements","ariaDescription","ariaDetailsElements","ariaDisabled","ariaErrorMessageElements","ariaExpanded","ariaFlowToElements","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLabelledByElements","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaNotify","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowIndexText","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","assignedSlot","attachShadow","attributes","before","checkVisibility","childElementCount","children","classList","className","clientHeight","clientLeft","clientTop","clientWidth","closest","computedStyleMap","currentCSSZoom","customElementRegistry","elementTiming","firstElementChild","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","id","innerHTML","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","lastElementChild","localName","matches","moveBefore","namespaceURI","nextElementSibling","onbeforecopy","onbeforecut","onbeforepaste","onfullscreenchange","onfullscreenerror","onsearch","onwebkitfullscreenchange","onwebkitfullscreenerror","outerHTML","part","prefix","prepend","previousElementSibling","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","role","scroll","scrollBy","scrollHeight","scrollIntoView","scrollIntoViewIfNeeded","scrollLeft","scrollTo","scrollTop","scrollWidth","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTML","setHTMLUnsafe","setPointerCapture","shadowRoot","slot","startViewTransition","tagName","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen"];
const CHROME_HTMLELEMENT = ["accessKey","attachInternals","attributeStyleMap","autocapitalize","autofocus","blur","click","contentEditable","dataset","dir","draggable","editContext","enterKeyHint","focus","hidden","hidePopover","inert","innerText","inputMode","isContentEditable","lang","nonce","offsetHeight","offsetLeft","offsetParent","offsetTop","offsetWidth","onabort","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeinput","onbeforematch","onbeforetoggle","onbeforexrselect","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncopy","oncuechange","oncut","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","ongotpointercapture","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onlostpointercapture","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpaste","onpause","onplay","onplaying","onpointercancel","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerover","onpointerrawupdate","onpointerup","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onscrollsnapchange","onscrollsnapchanging","onsecuritypolicyviolation","onseeked","onseeking","onselect","onselectionchange","onselectstart","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","ontransitioncancel","ontransitionend","ontransitionrun","ontransitionstart","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","outerText","popover","showPopover","spellcheck","style","tabIndex","title","togglePopover","translate","virtualKeyboardPolicy","writingSuggestions"];
const CHROME_IFACE_MEMBERS = {"HTMLAnchorElement":["attributionSrc","charset","coords","download","hash","host","hostname","href","hrefTranslate","hreflang","interestForElement","name","origin","password","pathname","ping","port","protocol","referrerPolicy","rel","relList","rev","search","shape","target","text","toString","type","username"],"HTMLBRElement":["clear"],"HTMLBodyElement":["aLink","background","bgColor","link","onafterprint","onbeforeprint","onbeforeunload","onblur","onerror","onfocus","ongamepadconnected","ongamepaddisconnected","onhashchange","onlanguagechange","onload","onmessage","onmessageerror","onoffline","ononline","onpagehide","onpageshow","onpopstate","onrejectionhandled","onresize","onscroll","onstorage","onunhandledrejection","onunload","text","vLink"],"HTMLButtonElement":["checkValidity","command","commandForElement","disabled","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","interestForElement","labels","name","popoverTargetAction","popoverTargetElement","reportValidity","setCustomValidity","type","validationMessage","validity","value","willValidate"],"HTMLCanvasElement":["captureStream","getContext","height","toBlob","toDataURL","transferControlToOffscreen","width"],"HTMLDivElement":["align"],"HTMLFormElement":["acceptCharset","action","autocomplete","checkValidity","elements","encoding","enctype","length","method","name","noValidate","rel","relList","reportValidity","requestSubmit","reset","submit","target"],"HTMLHeadingElement":["align"],"HTMLHtmlElement":["version"],"HTMLIFrameElement":["adAuctionHeaders","align","allow","allowFullscreen","allowPaymentRequest","browsingTopics","contentDocument","contentWindow","credentialless","csp","featurePolicy","frameBorder","getSVGDocument","height","loading","longDesc","marginHeight","marginWidth","name","privateToken","referrerPolicy","sandbox","scrolling","sharedStorageWritable","src","srcdoc","width"],"HTMLImageElement":["align","alt","attributionSrc","border","browsingTopics","complete","crossOrigin","currentSrc","decode","decoding","fetchPriority","height","hspace","isMap","loading","longDesc","lowsrc","name","naturalHeight","naturalWidth","referrerPolicy","sharedStorageWritable","sizes","src","srcset","useMap","vspace","width","x","y"],"HTMLInputElement":["accept","align","alt","autocomplete","checkValidity","checked","defaultChecked","defaultValue","dirName","disabled","files","form","formAction","formEnctype","formMethod","formNoValidate","formTarget","height","incremental","indeterminate","labels","list","max","maxLength","min","minLength","multiple","name","pattern","placeholder","popoverTargetAction","popoverTargetElement","readOnly","reportValidity","required","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","showPicker","size","src","step","stepDown","stepUp","type","useMap","validationMessage","validity","value","valueAsDate","valueAsNumber","webkitEntries","webkitdirectory","width","willValidate"],"HTMLLIElement":["type","value"],"HTMLLabelElement":["control","form","htmlFor"],"HTMLLinkElement":["as","blocking","charset","crossOrigin","disabled","fetchPriority","href","hreflang","imageSizes","imageSrcset","integrity","media","referrerPolicy","rel","relList","rev","sheet","sizes","target","type"],"HTMLMetaElement":["content","httpEquiv","media","name","scheme"],"HTMLOptionElement":["defaultSelected","disabled","form","index","label","selected","text","value"],"HTMLParagraphElement":["align"],"HTMLScriptElement":["async","attributionSrc","blocking","charset","crossOrigin","defer","event","fetchPriority","htmlFor","innerText","integrity","noModule","referrerPolicy","src","text","textContent","type"],"HTMLSelectElement":["add","autocomplete","checkValidity","disabled","form","item","labels","length","multiple","name","namedItem","options","remove","reportValidity","required","selectedIndex","selectedOptions","setCustomValidity","showPicker","size","type","validationMessage","validity","value","willValidate"],"HTMLStyleElement":["blocking","disabled","media","sheet","type"],"HTMLTableElement":["align","bgColor","border","caption","cellPadding","cellSpacing","createCaption","createTBody","createTFoot","createTHead","deleteCaption","deleteRow","deleteTFoot","deleteTHead","frame","insertRow","rows","rules","summary","tBodies","tFoot","tHead","width"],"HTMLTextAreaElement":["autocomplete","checkValidity","cols","defaultValue","dirName","disabled","form","labels","maxLength","minLength","name","placeholder","readOnly","reportValidity","required","rows","select","selectionDirection","selectionEnd","selectionStart","setCustomValidity","setRangeText","setSelectionRange","textLength","type","validationMessage","validity","value","willValidate","wrap"],"HTMLTitleElement":["text"],"HTMLUListElement":["compact","type"],"HTMLVideoElement":["cancelVideoFrameCallback","disablePictureInPicture","getVideoPlaybackQuality","height","onenterpictureinpicture","onleavepictureinpicture","playsInline","poster","requestPictureInPicture","requestVideoFrameCallback","videoHeight","videoWidth","webkitDecodedFrameCount","webkitDroppedFrameCount","width"]};
  {
    const onElement = new Set(CHROME_ELEMENT);
    const onHtml = new Set(CHROME_HTMLELEMENT);
    const owners = new Map();   // имя -> [прототипы интерфейсов]
    for (const [iface, members] of Object.entries(CHROME_IFACE_MEMBERS)) {
      const proto = __ifaceProto.get(iface);
      if (!proto) continue;
      for (const m of members) {
        if (!owners.has(m)) owners.set(m, []);
        owners.get(m).push(proto);
      }
    }
    for (const name of Object.getOwnPropertyNames(Element.prototype)) {
      if (name === 'constructor' || name.lastIndexOf('__pt', 0) === 0) continue;
      if (onElement.has(name)) continue;
      const d = Object.getOwnPropertyDescriptor(Element.prototype, name);
      if (!d || !d.configurable) continue;
      const targets = onHtml.has(name) ? [__htmlProto] : (owners.get(name) || []);
      if (!targets.length) continue;   // наше собственное — оставляем как есть
      for (const proto of targets) {
        if (Object.getOwnPropertyDescriptor(proto, name)) continue;
        try { Object.defineProperty(proto, name, d); } catch (e) {}
      }
      try { delete Element.prototype[name]; } catch (e) {}
    }
  }

  // Форма интерфейсов, снятая с Chrome 148: имя → категория → имена членов.
  // `Element.prototype` у нас нёс 47 имён против 151, `HTMLElement` — 16 против
  // 141, у SVGElement не было ни одного. Сборщик отпечатка идёт по цепочке
  // прототипов перечислимыми ключами, так что каждая недостающая ступень видна
  // ему сразу. Заполняем только то, чего нет: реализованное не трогаем.
  const CHROME_IFACE_SHAPE = {"AudioContext":{"N":["close","createMediaElementSource","createMediaStreamDestination","createMediaStreamSource","getOutputTimestamp","resume","suspend","setSinkId"],"x":["baseLatency","outputLatency","onerror","playbackStats","sinkId","onsinkchange"]},"BaseAudioContext":{"N":["createAnalyser","createBiquadFilter","createBuffer","createBufferSource","createChannelMerger","createChannelSplitter","createConstantSource","createConvolver","createDelay","createDynamicsCompressor","createGain","createIIRFilter","createOscillator","createPanner","createPeriodicWave","createScriptProcessor","createStereoPanner","createWaveShaper","decodeAudioData"],"x":["destination","sampleRate","currentTime","listener","state","onstatechange","audioWorklet"]},"CSSStyleDeclaration":{"#0":["length"],"N":["getPropertyPriority","getPropertyValue","item","removeProperty","setProperty"],"e":["cssText","cssFloat"],"x":["parentRule"]},"DOMTokenList":{"#2":["length"],"N":["entries","keys","values","forEach","add","contains","item","remove","replace","supports","toggle","toString"],"s:a b":["value"]},"Element":{"#0":["scrollTop","scrollLeft","clientTop","clientLeft"],"#1":["childElementCount","currentCSSZoom"],"#18":["scrollHeight","clientHeight"],"#764":["scrollWidth","clientWidth"],"N":["after","animate","append","attachShadow","before","checkVisibility","closest","computedStyleMap","getAnimations","getAttribute","getAttributeNS","getAttributeNames","getAttributeNode","getAttributeNodeNS","getBoundingClientRect","getClientRects","getElementsByClassName","getElementsByTagName","getElementsByTagNameNS","getHTML","hasAttribute","hasAttributeNS","hasAttributes","hasPointerCapture","insertAdjacentElement","insertAdjacentHTML","insertAdjacentText","matches","moveBefore","prepend","querySelector","querySelectorAll","releasePointerCapture","remove","removeAttribute","removeAttributeNS","removeAttributeNode","replaceChildren","replaceWith","requestFullscreen","requestPointerLock","scroll","scrollBy","scrollIntoView","scrollIntoViewIfNeeded","scrollTo","setAttribute","setAttributeNS","setAttributeNode","setAttributeNodeNS","setHTMLUnsafe","setPointerCapture","toggleAttribute","webkitMatchesSelector","webkitRequestFullScreen","webkitRequestFullscreen","ariaNotify","setHTML","startViewTransition"],"e":["slot","elementTiming"],"o":["classList","attributes","part","children","firstElementChild","lastElementChild","nextElementSibling","customElementRegistry"],"s:<div id=\"d\" class=\"a b\"><span>x</span></div>":["outerHTML"],"s:<span>x</span>":["innerHTML"],"s:DIV":["tagName"],"s:a b":["className"],"s:d":["id"],"s:div":["localName"],"s:http://www.w3.org/1999/xhtml":["namespaceURI"],"x":["prefix","shadowRoot","assignedSlot","onbeforecopy","onbeforecut","onbeforepaste","onsearch","onfullscreenchange","onfullscreenerror","onwebkitfullscreenchange","onwebkitfullscreenerror","role","ariaAtomic","ariaAutoComplete","ariaBusy","ariaBrailleLabel","ariaBrailleRoleDescription","ariaChecked","ariaColCount","ariaColIndex","ariaColSpan","ariaCurrent","ariaDescription","ariaDisabled","ariaExpanded","ariaHasPopup","ariaHidden","ariaInvalid","ariaKeyShortcuts","ariaLabel","ariaLevel","ariaLive","ariaModal","ariaMultiLine","ariaMultiSelectable","ariaOrientation","ariaPlaceholder","ariaPosInSet","ariaPressed","ariaReadOnly","ariaRelevant","ariaRequired","ariaRoleDescription","ariaRowCount","ariaRowIndex","ariaRowSpan","ariaSelected","ariaSetSize","ariaSort","ariaValueMax","ariaValueMin","ariaValueNow","ariaValueText","previousElementSibling","activeViewTransition","ariaColIndexText","ariaRowIndexText","ariaActiveDescendantElement","ariaControlsElements","ariaDescribedByElements","ariaDetailsElements","ariaErrorMessageElements","ariaFlowToElements","ariaLabelledByElements"]},"HTMLCanvasElement":{"#150":["height"],"#300":["width"],"N":["captureStream","getContext","toBlob","toDataURL","transferControlToOffscreen"]},"HTMLCollection":{"#1":["length"],"N":["item","namedItem"]},"HTMLElement":{"#-1":["tabIndex"],"#18":["offsetHeight"],"#764":["offsetWidth"],"#8":["offsetTop","offsetLeft"],"F":["hidden","inert","draggable","isContentEditable","autofocus"],"N":["attachInternals","blur","click","focus","hidePopover","showPopover","togglePopover"],"T":["translate","spellcheck"],"e":["title","lang","dir","accessKey","autocapitalize","enterKeyHint","inputMode","virtualKeyboardPolicy","nonce"],"o":["offsetParent","dataset","style","attributeStyleMap"],"s:inherit":["contentEditable"],"s:true":["writingSuggestions"],"s:x":["innerText","outerText"],"x":["editContext","popover","onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"NamedNodeMap":{"#2":["length"],"N":["getNamedItem","getNamedItemNS","item","removeNamedItem","removeNamedItemNS","setNamedItem","setNamedItemNS"]},"NodeList":{"#1":["length"],"N":["entries","keys","values","forEach","item"]},"OfflineAudioContext":{"N":["resume","startRendering","suspend"],"x":["oncomplete","length"]},"Performance":{"#0":["interactionCount"],"#1786865974979.1":["timeOrigin"],"N":["clearMarks","clearMeasures","clearResourceTimings","getEntries","getEntriesByName","getEntriesByType","mark","measure","setResourceTimingBufferSize","toJSON","now"],"o":["timing","navigation","memory","eventCounts"],"x":["onresourcetimingbufferfull"]},"SVGAnimatedLength":{"x":["baseVal","animVal"]},"SVGAnimatedRect":{"x":["baseVal","animVal"]},"SVGAnimatedString":{"x":["baseVal","animVal"]},"SVGAnimatedTransformList":{"x":["baseVal","animVal"]},"SVGCircleElement":{"o":["cx","cy","r"]},"SVGElement":{"#-1":["tabIndex"],"F":["autofocus"],"N":["blur","focus"],"e":["nonce"],"o":["className","ownerSVGElement","viewportElement","dataset","style","attributeStyleMap"],"x":["onabort","onbeforeinput","onbeforematch","onbeforetoggle","onblur","oncancel","oncanplay","oncanplaythrough","onchange","onclick","onclose","oncommand","oncontentvisibilityautostatechange","oncontextlost","oncontextmenu","oncontextrestored","oncuechange","ondblclick","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","ondurationchange","onemptied","onended","onerror","onfocus","onformdata","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadstart","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onmousewheel","onpause","onplay","onplaying","onprogress","onratechange","onreset","onresize","onscroll","onscrollend","onsecuritypolicyviolation","onseeked","onseeking","onselect","onslotchange","onstalled","onsubmit","onsuspend","ontimeupdate","ontoggle","onvolumechange","onwaiting","onwebkitanimationend","onwebkitanimationiteration","onwebkitanimationstart","onwebkittransitionend","onwheel","onauxclick","ongotpointercapture","onlostpointercapture","onpointerdown","onpointermove","onpointerup","onpointercancel","onpointerover","onpointerout","onpointerenter","onpointerleave","onselectstart","onselectionchange","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","ontransitionrun","ontransitionstart","ontransitionend","ontransitioncancel","onbeforexrselect","oncopy","oncut","onpaste","onscrollsnapchange","onscrollsnapchanging","onpointerrawupdate"]},"SVGGeometryElement":{"N":["getPointAtLength","getTotalLength","isPointInFill","isPointInStroke"],"o":["pathLength"]},"SVGGraphicsElement":{"N":["getBBox","getCTM","getScreenCTM"],"o":["transform","nearestViewportElement","farthestViewportElement","requiredExtensions","systemLanguage"]},"SVGLength":{"N":["convertToSpecifiedUnits","newValueSpecifiedUnits"],"u":["SVG_LENGTHTYPE_UNKNOWN","SVG_LENGTHTYPE_NUMBER","SVG_LENGTHTYPE_PERCENTAGE","SVG_LENGTHTYPE_EMS","SVG_LENGTHTYPE_EXS","SVG_LENGTHTYPE_PX","SVG_LENGTHTYPE_CM","SVG_LENGTHTYPE_MM","SVG_LENGTHTYPE_IN","SVG_LENGTHTYPE_PT","SVG_LENGTHTYPE_PC"],"x":["unitType","value","valueInSpecifiedUnits","valueAsString"]},"SVGLineElement":{"o":["x1","y1","x2","y2"]},"SVGMatrix":{"N":["flipX","flipY","inverse","multiply","rotate","rotateFromVector","scale","scaleNonUniform","skewX","skewY","translate"],"x":["a","b","c","d","e","f"]},"SVGPoint":{"N":["matrixTransform"],"x":["x","y"]},"SVGPointList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGRect":{"x":["x","y","width","height"]},"SVGRectElement":{"o":["x","y","width","height","rx","ry"]},"SVGSVGElement":{"#0":["SVG_ZOOMANDPAN_UNKNOWN"],"#1":["currentScale","SVG_ZOOMANDPAN_DISABLE"],"#2":["zoomAndPan","SVG_ZOOMANDPAN_MAGNIFY"],"N":["animationsPaused","checkEnclosure","checkIntersection","createSVGAngle","createSVGLength","createSVGMatrix","createSVGNumber","createSVGPoint","createSVGRect","createSVGTransform","createSVGTransformFromMatrix","deselectAll","forceRedraw","getCurrentTime","getElementById","getEnclosureList","getIntersectionList","pauseAnimations","setCurrentTime","suspendRedraw","unpauseAnimations","unsuspendRedraw","unsuspendRedrawAll"],"o":["x","y","width","height","currentTranslate","viewBox","preserveAspectRatio"]},"SVGStringList":{"N":["appendItem","clear","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"SVGTransformList":{"N":["appendItem","clear","consolidate","createSVGTransformFromMatrix","getItem","initialize","insertItemBefore","removeItem","replaceItem"],"x":["length","numberOfItems"]},"ShadowRoot":{"F":["delegatesFocus","serializable","clonable"],"N":["elementFromPoint","elementsFromPoint","getAnimations","getHTML","getSelection","setHTMLUnsafe","setHTML"],"a":["adoptedStyleSheets"],"e":["innerHTML"],"o":["host","styleSheets","customElementRegistry"],"s:named":["slotAssignment"],"s:open":["mode"],"x":["onslotchange","activeElement","pointerLockElement","fullscreenElement","pictureInPictureElement"]},"SpeechSynthesis":{"F":["pending","speaking","paused"],"N":["cancel","getVoices","pause","resume","speak"],"x":["onvoiceschanged"]},"Storage":{"#0":["length"],"N":["clear","getItem","key","removeItem","setItem"]}};
  globalThis.__pt_fillShapes = () => {
    const native = globalThis.__pt_native || ((f) => f);
    const stub = (name, cat) => {
      if (cat === 'N') {
        const f = function () {};
        try { Object.defineProperty(f, 'name', { value: name, configurable: true }); } catch (e) {}
        return native(f);
      }
      if (cat === 'x') return null;
      if (cat === 'u') return undefined;
      if (cat === 'T') return true;
      if (cat === 'F') return false;
      if (cat === 'e') return '';
      if (cat === 'o') return {};
      if (cat === 'a') return [];
      if (cat === 'p') { const q = Promise.resolve(); q.catch(() => {}); return q; }
      if (cat.charCodeAt(0) === 35) return Number(cat.slice(1));      // '#12' → 12
      if (cat.charCodeAt(0) === 115 && cat[1] === ':') return cat.slice(2);   // 's:auto'
      return undefined;
    };
    for (const iface of Object.keys(CHROME_IFACE_SHAPE)) {
      const C = globalThis[iface];
      const proto = C && C.prototype;
      if (!proto) continue;
      // "Уже есть" — значит есть на самом интерфейсе или ниже по цепочке DOM,
      // а не унаследовано от Object.prototype.
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

  globalThis.ShadowRoot = ShadowRoot;
  globalThis.Text = Text;
  globalThis.Comment = Comment;
  globalThis.Document = Document;
  globalThis.Event = Event;
  globalThis.CustomEvent = CustomEvent;
  globalThis.DocumentFragment = DocumentFragment;
  document.__ptView = globalThis;

  // <script> nodes in document order, so the loader can point `currentScript` at
  // the one it is about to run (for document.write positioning).
  let scriptNodes = [];

  // Called by the loader with the Rust-parsed <html> tree.
  // Документ дочернего окна, построенный на месте — без сети и без движка.
  // Пустой iframe в браузере получает `<html><head></head><body></body></html>`,
  // а `srcdoc` — разобранную разметку; и в обоих случаях скрипты внутри
  // исполняются в этом окне. У нас документ реалма был пуст, поэтому и
  // `contentDocument.body` был null, и класть туда было некуда.
  globalThis.__pt_writeDocument = (html) => {
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
      // Всё, что разметка положила мимо head, — содержимое тела.
      const head = __tags(root, 'head')[0];
      for (const n of root.childNodes.slice ? root.childNodes.slice() : Array.from(root.childNodes)) {
        if (n !== head) { root.removeChild(n); body.appendChild(n); }
      }
      root.appendChild(body);
    }
    document.__ptKids = [];
    document.documentElement = null;
    document.appendChild(root);
    document.documentElement = root;
    document.readyState = 'complete';
    // Скрипты разметки исполняются здесь и сейчас, в этом окне.
    for (const el of __tags(root, 'script')) {
      try { el.__ptRunScript(); } catch (e) {}
    }
    return document;
  };

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
    scriptNodes = __docTags(document, 'script');
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
      try { return { type: t === 'function' ? 'object' : t, value: __ptJSON.parse(__ptJSON.stringify(v)) }; }
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
  // Окно кадра — это его собственный `<iframe>`, а не страница: у виджета
  // Turnstile внутри 300×65, и он этот размер читает. Движок сообщает его сюда
  // сразу после создания контекста.
  globalThis.__pt_setViewport = (w, h) => {
    w = Math.max(0, Math.round(Number(w) || 0));
    h = Math.max(0, Math.round(Number(h) || 0));
    if (!w || !h) return;
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
    __layoutBuilt = -1;   // пересчитать коробки под новый размер
  };
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
  // Коробка элемента кадра на момент запроса: при вставке раскладки ещё нет, а
  // движок спрашивает уже после разбора документа.
  globalThis.__pt_frameBoxOf = (el) => {
    // Заданный размер важнее посчитанного: у виджета он стоит в стиле или в
    // атрибутах, а раскладка к моменту вопроса может быть ещё прошлой.
    const px = (v) => { const n = parseFloat(v); return Number.isFinite(n) && n > 0 ? Math.round(n) : 0; };
    let w = 0, h = 0;
    try { w = px(el.style && el.style.width) || px(el.getAttribute('width')); } catch (e) {}
    try { h = px(el.style && el.style.height) || px(el.getAttribute('height')); } catch (e) {}
    // Только заявленный размер: спросить раскладку значит построить её прямо
    // сейчас, посреди загрузки, и заморозить в недостроенном виде — страница
    // потом получала нулевые коробки. Не заявлен — размер по умолчанию, как у
    // браузера для кадра без размеров.
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
      const op = { op: 'post', id, data: __ptJSON.stringify(data === undefined ? null : data), toParent: false, targetOrigin: String(targetOrigin || '*') };
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
        __pushFrameOp({ op: 'post', data: __ptJSON.stringify(data === undefined ? null : data), toParent: true });
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

  // getComputedStyle: у браузера это 456 свойств с разрешёнными значениями, у
  // нас была заглушка с двумя. Загрузчик Cloudflare меряет свой виджет именно
  // так — `getComputedStyle(iframe)` — и пустой ответ читается как «элемента не
  // видно». Таблицы сняты с Chrome 148: порядок имён, значения по умолчанию для
  // блочного элемента и дельты для строчного и заменяемого.
const CS_ORDER = ["accent-color","align-content","align-items","align-self","alignment-baseline","anchor-name","anchor-scope","animation-composition","animation-delay","animation-direction","animation-duration","animation-fill-mode","animation-iteration-count","animation-name","animation-play-state","animation-range-end","animation-range-start","animation-timeline","animation-timing-function","animation-trigger","app-region","appearance","aspect-ratio","backdrop-filter","backface-visibility","background-attachment","background-blend-mode","background-clip","background-color","background-image","background-origin","background-position","background-repeat","background-size","baseline-shift","baseline-source","block-size","border-block-end-color","border-block-end-style","border-block-end-width","border-block-start-color","border-block-start-style","border-block-start-width","border-bottom-color","border-bottom-left-radius","border-bottom-right-radius","border-bottom-style","border-bottom-width","border-collapse","border-end-end-radius","border-end-start-radius","border-image-outset","border-image-repeat","border-image-slice","border-image-source","border-image-width","border-inline-end-color","border-inline-end-style","border-inline-end-width","border-inline-start-color","border-inline-start-style","border-inline-start-width","border-left-color","border-left-style","border-left-width","border-right-color","border-right-style","border-right-width","border-shape","border-start-end-radius","border-start-start-radius","border-top-color","border-top-left-radius","border-top-right-radius","border-top-style","border-top-width","bottom","box-decoration-break","box-shadow","box-sizing","break-after","break-before","break-inside","buffered-rendering","caption-side","caret-animation","caret-color","caret-shape","clear","clip","clip-path","clip-rule","color","color-interpolation","color-interpolation-filters","color-rendering","color-scheme","column-count","column-fill","column-gap","column-height","column-rule-color","column-rule-style","column-rule-width","column-span","column-width","column-wrap","contain","contain-intrinsic-block-size","contain-intrinsic-height","contain-intrinsic-inline-size","contain-intrinsic-size","contain-intrinsic-width","container-name","container-type","content","content-visibility","corner-bottom-left-shape","corner-bottom-right-shape","corner-end-end-shape","corner-end-start-shape","corner-start-end-shape","corner-start-start-shape","corner-top-left-shape","corner-top-right-shape","counter-increment","counter-reset","counter-set","cursor","cx","cy","d","direction","display","dominant-baseline","dynamic-range-limit","empty-cells","field-sizing","fill","fill-opacity","fill-rule","filter","flex-basis","flex-direction","flex-grow","flex-shrink","flex-wrap","float","flood-color","flood-opacity","font-family","font-feature-settings","font-kerning","font-language-override","font-optical-sizing","font-palette","font-size","font-size-adjust","font-stretch","font-style","font-synthesis-small-caps","font-synthesis-style","font-synthesis-weight","font-variant","font-variant-alternates","font-variant-caps","font-variant-east-asian","font-variant-emoji","font-variant-ligatures","font-variant-numeric","font-variant-position","font-variation-settings","font-weight","forced-color-adjust","grid-auto-columns","grid-auto-flow","grid-auto-rows","grid-column-end","grid-column-start","grid-row-end","grid-row-start","grid-template-areas","grid-template-columns","grid-template-rows","height","hyphenate-character","hyphenate-limit-chars","hyphens","image-orientation","image-rendering","initial-letter","inline-size","inset-block-end","inset-block-start","inset-inline-end","inset-inline-start","interactivity","interest-delay-end","interest-delay-start","interpolate-size","isolation","justify-content","justify-items","justify-self","left","letter-spacing","lighting-color","line-break","line-height","list-style-image","list-style-position","list-style-type","margin-block-end","margin-block-start","margin-bottom","margin-inline-end","margin-inline-start","margin-left","margin-right","margin-top","marker-end","marker-mid","marker-start","mask-clip","mask-composite","mask-image","mask-mode","mask-origin","mask-position","mask-repeat","mask-size","mask-type","math-depth","math-shift","math-style","max-block-size","max-height","max-inline-size","max-width","min-block-size","min-height","min-inline-size","min-width","mix-blend-mode","object-fit","object-position","object-view-box","offset-anchor","offset-distance","offset-path","offset-position","offset-rotate","opacity","order","orphans","outline-color","outline-offset","outline-style","outline-width","overflow-anchor","overflow-block","overflow-clip-margin","overflow-inline","overflow-wrap","overflow-x","overflow-y","overlay","overscroll-behavior-block","overscroll-behavior-inline","overscroll-behavior-x","overscroll-behavior-y","padding-block-end","padding-block-start","padding-bottom","padding-inline-end","padding-inline-start","padding-left","padding-right","padding-top","paint-order","perspective","perspective-origin","pointer-events","position","position-anchor","position-area","position-try-fallbacks","position-try-order","position-visibility","print-color-adjust","quotes","r","reading-flow","reading-order","resize","right","rotate","row-gap","ruby-align","ruby-position","rx","ry","scale","scroll-behavior","scroll-initial-target","scroll-margin-block-end","scroll-margin-block-start","scroll-margin-bottom","scroll-margin-inline-end","scroll-margin-inline-start","scroll-margin-left","scroll-margin-right","scroll-margin-top","scroll-marker-group","scroll-padding-block-end","scroll-padding-block-start","scroll-padding-bottom","scroll-padding-inline-end","scroll-padding-inline-start","scroll-padding-left","scroll-padding-right","scroll-padding-top","scroll-snap-align","scroll-snap-stop","scroll-snap-type","scroll-target-group","scroll-timeline-axis","scroll-timeline-name","scrollbar-color","scrollbar-gutter","scrollbar-width","shape-image-threshold","shape-margin","shape-outside","shape-rendering","speak","stop-color","stop-opacity","stroke","stroke-dasharray","stroke-dashoffset","stroke-linecap","stroke-linejoin","stroke-miterlimit","stroke-opacity","stroke-width","tab-size","table-layout","text-align","text-align-last","text-anchor","text-autospace","text-box-edge","text-box-trim","text-combine-upright","text-decoration","text-decoration-color","text-decoration-line","text-decoration-skip-ink","text-decoration-style","text-decoration-thickness","text-emphasis-color","text-emphasis-position","text-emphasis-style","text-indent","text-justify","text-orientation","text-overflow","text-rendering","text-shadow","text-size-adjust","text-spacing-trim","text-transform","text-underline-offset","text-underline-position","text-wrap-mode","text-wrap-style","timeline-scope","timeline-trigger-activation-range-end","timeline-trigger-activation-range-start","timeline-trigger-active-range-end","timeline-trigger-active-range-start","timeline-trigger-name","timeline-trigger-source","top","touch-action","transform","transform-box","transform-origin","transform-style","transition-behavior","transition-delay","transition-duration","transition-property","transition-timing-function","translate","trigger-scope","unicode-bidi","user-select","vector-effect","vertical-align","view-timeline-axis","view-timeline-inset","view-timeline-name","view-transition-class","view-transition-group","view-transition-name","view-transition-scope","visibility","white-space-collapse","widows","width","will-change","word-break","word-spacing","writing-mode","x","y","z-index","zoom","-webkit-border-horizontal-spacing","-webkit-border-image","-webkit-border-vertical-spacing","-webkit-box-align","-webkit-box-decoration-break","-webkit-box-direction","-webkit-box-flex","-webkit-box-ordinal-group","-webkit-box-orient","-webkit-box-pack","-webkit-box-reflect","-webkit-font-smoothing","-webkit-line-break","-webkit-line-clamp","-webkit-locale","-webkit-mask-box-image","-webkit-mask-box-image-outset","-webkit-mask-box-image-repeat","-webkit-mask-box-image-slice","-webkit-mask-box-image-source","-webkit-mask-box-image-width","-webkit-mask-position-x","-webkit-mask-position-y","-webkit-rtl-ordering","-webkit-ruby-position","-webkit-tap-highlight-color","-webkit-text-combine","-webkit-text-decorations-in-effect","-webkit-text-fill-color","-webkit-text-orientation","-webkit-text-security","-webkit-text-stroke-color","-webkit-text-stroke-width","-webkit-user-drag","-webkit-user-modify","-webkit-writing-mode"];
const CS_BASE = {"accent-color":"auto","align-content":"normal","align-items":"normal","align-self":"auto","alignment-baseline":"auto","anchor-name":"none","anchor-scope":"none","animation-composition":"replace","animation-delay":"0s","animation-direction":"normal","animation-duration":"0s","animation-fill-mode":"none","animation-iteration-count":"1","animation-name":"none","animation-play-state":"running","animation-range-end":"normal","animation-range-start":"normal","animation-timeline":"auto","animation-timing-function":"ease","animation-trigger":"none","app-region":"none","appearance":"none","aspect-ratio":"auto","backdrop-filter":"none","backface-visibility":"visible","background-attachment":"scroll","background-blend-mode":"normal","background-clip":"border-box","background-color":"rgba(0, 0, 0, 0)","background-image":"none","background-origin":"padding-box","background-position":"0% 0%","background-repeat":"repeat","background-size":"auto","baseline-shift":"0px","baseline-source":"auto","block-size":"18px","border-block-end-color":"rgb(0, 0, 0)","border-block-end-style":"none","border-block-end-width":"0px","border-block-start-color":"rgb(0, 0, 0)","border-block-start-style":"none","border-block-start-width":"0px","border-bottom-color":"rgb(0, 0, 0)","border-bottom-left-radius":"0px","border-bottom-right-radius":"0px","border-bottom-style":"none","border-bottom-width":"0px","border-collapse":"separate","border-end-end-radius":"0px","border-end-start-radius":"0px","border-image-outset":"0","border-image-repeat":"stretch","border-image-slice":"100%","border-image-source":"none","border-image-width":"1","border-inline-end-color":"rgb(0, 0, 0)","border-inline-end-style":"none","border-inline-end-width":"0px","border-inline-start-color":"rgb(0, 0, 0)","border-inline-start-style":"none","border-inline-start-width":"0px","border-left-color":"rgb(0, 0, 0)","border-left-style":"none","border-left-width":"0px","border-right-color":"rgb(0, 0, 0)","border-right-style":"none","border-right-width":"0px","border-shape":"none","border-start-end-radius":"0px","border-start-start-radius":"0px","border-top-color":"rgb(0, 0, 0)","border-top-left-radius":"0px","border-top-right-radius":"0px","border-top-style":"none","border-top-width":"0px","bottom":"auto","box-decoration-break":"slice","box-shadow":"none","box-sizing":"content-box","break-after":"auto","break-before":"auto","break-inside":"auto","buffered-rendering":"auto","caption-side":"top","caret-animation":"auto","caret-color":"rgb(0, 0, 0)","caret-shape":"auto","clear":"none","clip":"auto","clip-path":"none","clip-rule":"nonzero","color":"rgb(0, 0, 0)","color-interpolation":"srgb","color-interpolation-filters":"linearrgb","color-rendering":"auto","color-scheme":"normal","column-count":"auto","column-fill":"balance","column-gap":"normal","column-height":"auto","column-rule-color":"rgb(0, 0, 0)","column-rule-style":"none","column-rule-width":"3px","column-span":"none","column-width":"auto","column-wrap":"auto","contain":"none","contain-intrinsic-block-size":"none","contain-intrinsic-height":"none","contain-intrinsic-inline-size":"none","contain-intrinsic-size":"none","contain-intrinsic-width":"none","container-name":"none","container-type":"normal","content":"normal","content-visibility":"visible","corner-bottom-left-shape":"round","corner-bottom-right-shape":"round","corner-end-end-shape":"round","corner-end-start-shape":"round","corner-start-end-shape":"round","corner-start-start-shape":"round","corner-top-left-shape":"round","corner-top-right-shape":"round","counter-increment":"none","counter-reset":"none","counter-set":"none","cursor":"auto","cx":"0px","cy":"0px","d":"none","direction":"ltr","display":"block","dominant-baseline":"auto","dynamic-range-limit":"no-limit","empty-cells":"show","field-sizing":"fixed","fill":"rgb(0, 0, 0)","fill-opacity":"1","fill-rule":"nonzero","filter":"none","flex-basis":"auto","flex-direction":"row","flex-grow":"0","flex-shrink":"1","flex-wrap":"nowrap","float":"none","flood-color":"rgb(0, 0, 0)","flood-opacity":"1","font-family":"\"Times New Roman\"","font-feature-settings":"normal","font-kerning":"auto","font-language-override":"normal","font-optical-sizing":"auto","font-palette":"normal","font-size":"16px","font-size-adjust":"none","font-stretch":"100%","font-style":"normal","font-synthesis-small-caps":"auto","font-synthesis-style":"auto","font-synthesis-weight":"auto","font-variant":"normal","font-variant-alternates":"normal","font-variant-caps":"normal","font-variant-east-asian":"normal","font-variant-emoji":"normal","font-variant-ligatures":"normal","font-variant-numeric":"normal","font-variant-position":"normal","font-variation-settings":"normal","font-weight":"400","forced-color-adjust":"auto","grid-auto-columns":"auto","grid-auto-flow":"row","grid-auto-rows":"auto","grid-column-end":"auto","grid-column-start":"auto","grid-row-end":"auto","grid-row-start":"auto","grid-template-areas":"none","grid-template-columns":"none","grid-template-rows":"none","height":"18px","hyphenate-character":"auto","hyphenate-limit-chars":"auto","hyphens":"manual","image-orientation":"from-image","image-rendering":"auto","initial-letter":"normal","inline-size":"284px","inset-block-end":"auto","inset-block-start":"auto","inset-inline-end":"auto","inset-inline-start":"auto","interactivity":"auto","interest-delay-end":"normal","interest-delay-start":"normal","interpolate-size":"numeric-only","isolation":"auto","justify-content":"normal","justify-items":"normal","justify-self":"auto","left":"auto","letter-spacing":"normal","lighting-color":"rgb(255, 255, 255)","line-break":"auto","line-height":"normal","list-style-image":"none","list-style-position":"outside","list-style-type":"disc","margin-block-end":"0px","margin-block-start":"0px","margin-bottom":"0px","margin-inline-end":"0px","margin-inline-start":"0px","margin-left":"0px","margin-right":"0px","margin-top":"0px","marker-end":"none","marker-mid":"none","marker-start":"none","mask-clip":"border-box","mask-composite":"add","mask-image":"none","mask-mode":"match-source","mask-origin":"border-box","mask-position":"0% 0%","mask-repeat":"repeat","mask-size":"auto","mask-type":"luminance","math-depth":"0","math-shift":"normal","math-style":"normal","max-block-size":"none","max-height":"none","max-inline-size":"none","max-width":"none","min-block-size":"0px","min-height":"0px","min-inline-size":"0px","min-width":"0px","mix-blend-mode":"normal","object-fit":"fill","object-position":"50% 50%","object-view-box":"none","offset-anchor":"auto","offset-distance":"0px","offset-path":"none","offset-position":"normal","offset-rotate":"auto 0deg","opacity":"1","order":"0","orphans":"2","outline-color":"rgb(0, 0, 0)","outline-offset":"0px","outline-style":"none","outline-width":"3px","overflow-anchor":"auto","overflow-block":"visible","overflow-clip-margin":"0px","overflow-inline":"visible","overflow-wrap":"normal","overflow-x":"visible","overflow-y":"visible","overlay":"none","overscroll-behavior-block":"auto","overscroll-behavior-inline":"auto","overscroll-behavior-x":"auto","overscroll-behavior-y":"auto","padding-block-end":"0px","padding-block-start":"0px","padding-bottom":"0px","padding-inline-end":"0px","padding-inline-start":"0px","padding-left":"0px","padding-right":"0px","padding-top":"0px","paint-order":"normal","perspective":"none","perspective-origin":"142px 9px","pointer-events":"auto","position":"static","position-anchor":"none","position-area":"none","position-try-fallbacks":"none","position-try-order":"normal","position-visibility":"anchors-visible","print-color-adjust":"economy","quotes":"auto","r":"0px","reading-flow":"normal","reading-order":"0","resize":"none","right":"auto","rotate":"none","row-gap":"normal","ruby-align":"space-around","ruby-position":"over","rx":"auto","ry":"auto","scale":"none","scroll-behavior":"auto","scroll-initial-target":"none","scroll-margin-block-end":"0px","scroll-margin-block-start":"0px","scroll-margin-bottom":"0px","scroll-margin-inline-end":"0px","scroll-margin-inline-start":"0px","scroll-margin-left":"0px","scroll-margin-right":"0px","scroll-margin-top":"0px","scroll-marker-group":"none","scroll-padding-block-end":"auto","scroll-padding-block-start":"auto","scroll-padding-bottom":"auto","scroll-padding-inline-end":"auto","scroll-padding-inline-start":"auto","scroll-padding-left":"auto","scroll-padding-right":"auto","scroll-padding-top":"auto","scroll-snap-align":"none","scroll-snap-stop":"normal","scroll-snap-type":"none","scroll-target-group":"none","scroll-timeline-axis":"block","scroll-timeline-name":"none","scrollbar-color":"auto","scrollbar-gutter":"auto","scrollbar-width":"auto","shape-image-threshold":"0","shape-margin":"0px","shape-outside":"none","shape-rendering":"auto","speak":"normal","stop-color":"rgb(0, 0, 0)","stop-opacity":"1","stroke":"none","stroke-dasharray":"none","stroke-dashoffset":"0px","stroke-linecap":"butt","stroke-linejoin":"miter","stroke-miterlimit":"4","stroke-opacity":"1","stroke-width":"1px","tab-size":"8","table-layout":"auto","text-align":"start","text-align-last":"auto","text-anchor":"start","text-autospace":"no-autospace","text-box-edge":"auto","text-box-trim":"none","text-combine-upright":"none","text-decoration":"none","text-decoration-color":"rgb(0, 0, 0)","text-decoration-line":"none","text-decoration-skip-ink":"auto","text-decoration-style":"solid","text-decoration-thickness":"auto","text-emphasis-color":"rgb(0, 0, 0)","text-emphasis-position":"over","text-emphasis-style":"none","text-indent":"0px","text-justify":"auto","text-orientation":"mixed","text-overflow":"clip","text-rendering":"auto","text-shadow":"none","text-size-adjust":"auto","text-spacing-trim":"normal","text-transform":"none","text-underline-offset":"auto","text-underline-position":"auto","text-wrap-mode":"wrap","text-wrap-style":"auto","timeline-scope":"none","timeline-trigger-activation-range-end":"normal","timeline-trigger-activation-range-start":"normal","timeline-trigger-active-range-end":"auto","timeline-trigger-active-range-start":"auto","timeline-trigger-name":"none","timeline-trigger-source":"auto","top":"auto","touch-action":"auto","transform":"none","transform-box":"view-box","transform-origin":"142px 9px","transform-style":"flat","transition-behavior":"normal","transition-delay":"0s","transition-duration":"0s","transition-property":"all","transition-timing-function":"ease","translate":"none","trigger-scope":"none","unicode-bidi":"isolate","user-select":"auto","vector-effect":"none","vertical-align":"baseline","view-timeline-axis":"block","view-timeline-inset":"auto","view-timeline-name":"none","view-transition-class":"none","view-transition-group":"normal","view-transition-name":"none","view-transition-scope":"none","visibility":"visible","white-space-collapse":"collapse","widows":"2","width":"284px","will-change":"auto","word-break":"normal","word-spacing":"0px","writing-mode":"horizontal-tb","x":"0px","y":"0px","z-index":"auto","zoom":"1","-webkit-border-horizontal-spacing":"0px","-webkit-border-image":"none","-webkit-border-vertical-spacing":"0px","-webkit-box-align":"stretch","-webkit-box-decoration-break":"slice","-webkit-box-direction":"normal","-webkit-box-flex":"0","-webkit-box-ordinal-group":"1","-webkit-box-orient":"horizontal","-webkit-box-pack":"start","-webkit-box-reflect":"none","-webkit-font-smoothing":"auto","-webkit-line-break":"auto","-webkit-line-clamp":"none","-webkit-locale":"auto","-webkit-mask-box-image":"none","-webkit-mask-box-image-outset":"0","-webkit-mask-box-image-repeat":"stretch","-webkit-mask-box-image-slice":"0 fill","-webkit-mask-box-image-source":"none","-webkit-mask-box-image-width":"auto","-webkit-mask-position-x":"0%","-webkit-mask-position-y":"0%","-webkit-rtl-ordering":"logical","-webkit-ruby-position":"before","-webkit-tap-highlight-color":"rgba(0, 0, 0, 0.18)","-webkit-text-combine":"none","-webkit-text-decorations-in-effect":"none","-webkit-text-fill-color":"rgb(0, 0, 0)","-webkit-text-orientation":"vertical-right","-webkit-text-security":"none","-webkit-text-stroke-color":"rgb(0, 0, 0)","-webkit-text-stroke-width":"0px","-webkit-user-drag":"auto","-webkit-user-modify":"read-only","-webkit-writing-mode":"horizontal-tb"};
const CS_INLINE = {"block-size":"auto","display":"inline","height":"auto","inline-size":"auto","perspective-origin":"0px 0px","transform-origin":"0px 0px","unicode-bidi":"normal","width":"auto"};
const CS_REPLACED = {"block-size":"65px","border-block-end-style":"inset","border-block-end-width":"2px","border-block-start-style":"inset","border-block-start-width":"2px","border-bottom-style":"inset","border-bottom-width":"2px","border-inline-end-style":"inset","border-inline-end-width":"2px","border-inline-start-style":"inset","border-inline-start-width":"2px","border-left-style":"inset","border-left-width":"2px","border-right-style":"inset","border-right-width":"2px","border-top-style":"inset","border-top-width":"2px","display":"inline","height":"65px","inline-size":"300px","overflow-block":"clip","overflow-clip-margin":"content-box","overflow-inline":"clip","overflow-x":"clip","overflow-y":"clip","perspective-origin":"152px 34.5px","transform-origin":"152px 34.5px","unicode-bidi":"normal","width":"300px"};
  const CS_DISPLAY = {
    span: 'inline', a: 'inline', b: 'inline', i: 'inline', em: 'inline', strong: 'inline',
    small: 'inline', code: 'inline', label: 'inline', abbr: 'inline', cite: 'inline',
    q: 'inline', s: 'inline', u: 'inline', sub: 'inline', sup: 'inline', mark: 'inline',
    time: 'inline', var: 'inline', samp: 'inline', kbd: 'inline', bdi: 'inline', bdo: 'inline',
    img: 'inline', iframe: 'inline', canvas: 'inline', video: 'inline', audio: 'inline',
    object: 'inline', embed: 'inline', svg: 'inline', input: 'inline-block',
    button: 'inline-block', select: 'inline-block', textarea: 'inline-block',
    meter: 'inline-block', progress: 'inline-block', li: 'list-item', table: 'table',
    thead: 'table-header-group', tbody: 'table-row-group', tfoot: 'table-footer-group',
    tr: 'table-row', td: 'table-cell', th: 'table-cell', caption: 'table-caption',
    head: 'none', style: 'none', script: 'none', link: 'none', meta: 'none',
    title: 'none', template: 'none', base: 'none', param: 'none', source: 'none',
    track: 'none', option: 'block', optgroup: 'block',
  };
  const CS_REPLACED_TAGS = new Set(['iframe', 'img', 'canvas', 'video', 'audio', 'object', 'embed']);
  const CS_CAMEL = (n) => n.replace(/-([a-z])/g, (_, c) => c.toUpperCase());

  globalThis.getComputedStyle = (el, pseudo) => {
    const map = new Map();
    for (const k of CS_ORDER) map.set(k, CS_BASE[k]);
    const tag = (el && el.localName) || 'div';
    if (CS_DISPLAY[tag] === 'inline' || CS_INLINE) {
      const inlineish = CS_DISPLAY[tag] === 'inline';
      if (inlineish) for (const [k, v] of Object.entries(CS_INLINE)) map.set(k, v);
    }
    if (CS_REPLACED_TAGS.has(tag)) for (const [k, v] of Object.entries(CS_REPLACED)) map.set(k, v);
    if (CS_DISPLAY[tag]) map.set('display', CS_DISPLAY[tag]);
    // Заявленное автором поверх умолчаний, потом — использованные размеры.
    try {
      const own = el && el.style;
      if (own) for (let i = 0; i < own.length; i++) {
        const n = own.item(i), v = own.getPropertyValue(n);
        map.set(n, v);
        // Сокращённые свойства браузер раскрывает в длинные, и меряют обычно
        // именно длинные: `border: 0` — это и `border-top-width: 0px`.
        const sides = ['top', 'right', 'bottom', 'left'];
        if (n === 'border' || n === 'border-width') {
          const w = /^0$|^0px$|^none$/.test(v.trim()) ? '0px' : (v.match(/(\d+(?:\.\d+)?px)/) || [, v])[1];
          for (const side of sides) map.set('border-' + side + '-width', w);
          if (/^0$|^none$/.test(v.trim())) for (const side of sides) map.set('border-' + side + '-style', 'none');
        } else if (n === 'margin' || n === 'padding') {
          const parts = v.trim().split(/\s+/);
          const pick = (i) => parts[[0, 1, 2, 3].map((k) => Math.min(k, parts.length - 1))[i]] || '0px';
          sides.forEach((side, i) => map.set(n + '-' + side, pick(i)));
        }
      }
    } catch (e) {}
    try {
      if (el && el.nodeType === ELEMENT_NODE) {
        if (__isHiddenEl(el)) map.set('display', 'none');
        const b = __boxOf(el);
        if (b) {
          map.set('width', b.w + 'px'); map.set('height', b.h + 'px');
          map.set('inline-size', b.w + 'px'); map.set('block-size', b.h + 'px');
          map.set('perspective-origin', (b.w / 2) + 'px ' + (b.h / 2) + 'px');
          map.set('transform-origin', (b.w / 2) + 'px ' + (b.h / 2) + 'px');
        }
      }
    } catch (e) {}
    const names = [...map.keys()];
    // Объект называет себя как в браузере: `[object CSSStyleDeclaration]`.
    const proto = (globalThis.CSSStyleDeclaration && CSSStyleDeclaration.prototype) || Object.prototype;
    // Заглушка интерфейса могла приехать без своего имени — тогда ставим его.
    try {
      if (proto !== Object.prototype && !Object.getOwnPropertyDescriptor(proto, Symbol.toStringTag)) {
        Object.defineProperty(proto, Symbol.toStringTag, { value: 'CSSStyleDeclaration', configurable: true });
      }
    } catch (e) {}
    const decl = Object.assign(Object.create(proto), {
      getPropertyValue: (n) => map.get(String(n).toLowerCase()) || '',
      getPropertyPriority: () => '',
      item: (i) => names[i] || '',
      get length() { return names.length; },
      get cssText() { return ''; },   // как в браузере: у вычисленного стиля он пуст
      setProperty() { throw new TypeError("Cannot modify computed style"); },
      removeProperty() { throw new TypeError("Cannot modify computed style"); },
      [Symbol.iterator]: function* () { for (const n of names) yield n; },
    });
    for (const n of names) {
      const camel = CS_CAMEL(n);
      const value = map.get(n);
      Object.defineProperty(decl, n, { get: () => value, enumerable: false, configurable: true });
      if (camel !== n) Object.defineProperty(decl, camel, { get: () => value, enumerable: false, configurable: true });
    }
    return decl;
  };

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
    return __ptJSON.stringify(seen.slice(0, 8));
  };

  globalThis.__pt_hitFrame = (x, y) => {
    for (let el = __elementFromPoint(x, y); el && el.nodeType === ELEMENT_NODE; el = el.parentNode) {
      if (el.__ptLocal === 'iframe' && el.__ptFrameId) {
        const r = el.getBoundingClientRect();
        // Один к одному, как в настоящем окне: фрейм не сжимает содержимое под
        // свою рамку, он показывает его верх, а остальное уходит под обрез.
        // Точка внутри рамки — та же точка в координатах фрейма.
        return __ptJSON.stringify({ frame: el.__ptFrameId, x: x - r.x, y: y - r.y });
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
