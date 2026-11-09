//! HTML parsing (Phase 3) and the pure-JS DOM runtime (Phase 4).
//!
//! We parse HTML in Rust with `html5ever` into a compact JSON tree, then build
//! the actual DOM as a JavaScript object graph *inside the V8 context* (see
//! [`runtime_js`]). This sidesteps the lifetime hazards of exposing Rust-owned
//! nodes to V8's GC via native bindings: the DOM lives entirely in JS, and the
//! only Rust↔JS contract is "here is the parsed tree as data".
//!
//! The trade-off is that the DOM is a minimal, hand-written implementation
//! rather than a full spec engine — enough for typical page and fingerprint
//! scripts (`document`, `Element`, `querySelector`, events, `innerHTML`), not
//! layout or rendering (which this engine never does).

use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use serde_json::{json, Value};

/// A `<script>` found in the document, in document order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Script {
    /// Inline script: the JS source text.
    Inline(String),
    /// External script: the (possibly relative) `src` URL to fetch.
    External(String),
    /// `<script type="module">`, inline. It has its own parse goal — `import`
    /// only means anything inside one — so it cannot be run as a classic script.
    InlineModule(String),
    /// `<script type="module" src=…>`: the whole of a modern site is usually
    /// this one line.
    ExternalModule(String),
    /// A `<script nomodule>`: the fallback bundle for a browser from before
    /// modules. One that has them skips it, and must — a Vite site ships both
    /// halves, and running both loads the app twice.
    ///
    /// The element is still counted so the numbering stays the document's own:
    /// `__pt_beginScript(i)` indexes every `<script>` the parser saw.
    Skipped,
    /// `<script type="importmap">`, inline: the map module specifiers resolve through.
    ImportMap(String),
}

/// When a script runs. A browser runs a classic script during parsing,
/// `defer` scripts and modules after parsing in document order, and `async`
/// ones as soon as they arrive. A deferred module must not see the document
/// before `DOMContentLoaded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptMode {
    /// During parsing.
    Blocking,
    /// After parsing, in document order.
    Defer,
    /// On arrival, unordered.
    Async,
}

/// The result of parsing an HTML document.
#[derive(Debug, Clone)]
pub struct ParsedPage {
    /// The `<html>` element serialized as a JSON tree (see module docs for the
    /// shape). Consumed by `__pt_installDocument` in [`runtime_js`].
    pub root: String,
    /// Scripts to execute, in document order.
    pub scripts: Vec<Script>,
    /// When to run each of [`Self::scripts`], index for index.
    pub script_modes: Vec<ScriptMode>,
    /// The document's `<!DOCTYPE …>`, if it had one: name, public id, system id.
    /// A page without one is in quirks mode and its `document.doctype` is null —
    /// both of which a fingerprint reads, so the difference has to survive the
    /// parse instead of being dropped with the node.
    pub doctype: Option<(String, String, String)>,
    /// The source markup: inline script line numbers count from the start of
    /// the document (stack traces and CSP reports do).
    pub markup: String,
    /// The mode the doctype set: `quirks`, `limited` or `no`
    /// (`document.compatMode`).
    pub mode: &'static str,
    /// The document's other children before and after the root, as JSON
    /// arrays: the doctype where it stood, comments, processing
    /// instructions (`document.childNodes` lists them in Chrome).
    pub before: String,
    pub after: String,
    /// The `href` of the document's first `<base>` that has one, as written:
    /// the base its markup's scripts resolve against.
    pub base_href: Option<String>,
    /// What a preload scanner would request before the tree is built: each
    /// `<link>` the document loads as a stylesheet (`rel` exactly
    /// `stylesheet` or `preload` with `as=style`), its `href` as written and
    /// its resource type, first occurrence per address, in document order.
    pub early_links: Vec<(String, &'static str)>,
    /// A `<meta http-equiv>` names client hints (`accept-ch`, `delegate-ch`):
    /// requests made before it is read would go without them.
    pub meta_hints: bool,
}

impl ParsedPage {
    /// The JS statement that installs this page's tree as `document`.
    pub fn install_script(&self) -> String {
        let dt = match &self.doctype {
            Some((name, public, system)) => json!({
                "name": name, "publicId": public, "systemId": system
            }),
            None => Value::Null,
        };
        format!(
            "globalThis.__pt_installDocument({}, {}, {}, {}, {}, {});",
            self.root,
            dt,
            Value::String(self.markup.clone()),
            Value::String(self.mode.to_string()),
            self.before,
            self.after
        )
    }
}

/// The first HTML `<base href>` in tree order, stopping there. No stack
/// frame per level: trees can be thousands deep.
fn first_base_href(root: &Handle) -> Option<String> {
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        if let NodeData::Element { name, attrs, .. } = &node.data {
            if &*name.local == "base" && (name.ns.is_empty() || &*name.ns == "http://www.w3.org/1999/xhtml") {
                if let Some(a) = attrs.borrow().iter().find(|a| &*a.name.local == "href") {
                    return Some(a.value.to_string());
                }
            }
        }
        for c in node.children.borrow().iter().rev() {
            stack.push(c.clone());
        }
    }
    None
}

/// The stylesheet links and the client-hint meta of the document's tree, in
/// tree order (template contents are not children). No stack frame per level.
fn early_links(root: &Handle) -> (Vec<(String, &'static str)>, bool) {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut hints = false;
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        if let NodeData::Element { name, attrs, .. } = &node.data {
            let html = &*name.ns == "http://www.w3.org/1999/xhtml";
            let attrs = attrs.borrow();
            let get = |n: &str| attrs.iter().find(|a| &*a.name.local == n).map(|a| a.value.to_string());
            if html && &*name.local == "meta" {
                if let Some(e) = get("http-equiv") {
                    let e = e.trim().to_ascii_lowercase();
                    if e == "accept-ch" || e == "delegate-ch" {
                        hints = true;
                    }
                }
            } else if html && &*name.local == "link" {
                // As the runtime reads it: the whole `rel` lowercased, no trimming.
                let rel = get("rel").unwrap_or_default().to_ascii_lowercase();
                let kind = match rel.as_str() {
                    "stylesheet" => Some("stylesheet"),
                    "preload" if get("as").unwrap_or_default().eq_ignore_ascii_case("style") => Some("link-style"),
                    _ => None,
                };
                if let (Some(kind), Some(href)) = (kind, get("href")) {
                    if !href.is_empty() && !out.iter().any(|(h, _)| *h == href) {
                        out.push((href, kind));
                    }
                }
            }
        }
        for c in node.children.borrow().iter().rev() {
            stack.push(c.clone());
        }
    }
    (out, hints)
}

/// Parse an HTML document into a JSON tree plus its ordered script list.
pub fn parse(html: &str) -> ParsedPage {
    let dom = html5ever::parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut html.as_bytes())
        .unwrap_or_else(|_| RcDom::default());

    let mut scripts = Vec::new();
    let mut script_modes = Vec::new();
    // The document's children are the doctype and the root <html> element.
    let doctype = dom.document.children.borrow().iter().find_map(|c| match &c.data {
        NodeData::Doctype {
            name,
            public_id,
            system_id,
        } => Some((
            name.to_string(),
            public_id.to_string(),
            system_id.to_string(),
        )),
        _ => None,
    });
    let mut root = String::with_capacity(html.len() + html.len() / 2);
    let mut before = String::from("[");
    let mut after = String::from("[");
    let mut seen_root = false;
    for c in dom.document.children.borrow().iter() {
        if !seen_root && matches!(c.data, NodeData::Element { .. }) {
            seen_root = true;
            serialize(c, &mut root, &mut scripts, &mut script_modes);
            continue;
        }
        let side = if seen_root { &mut after } else { &mut before };
        let mark = side.len();
        if side.len() > 1 {
            side.push(',');
        }
        if !serialize(c, side, &mut scripts, &mut script_modes) {
            side.truncate(mark);
        }
    }
    if !seen_root {
        root.push_str("null");
    }
    before.push(']');
    after.push(']');

    let (early_links, meta_hints) = early_links(&dom.document);
    ParsedPage {
        early_links,
        meta_hints,
        root,
        scripts,
        script_modes,
        doctype,
        markup: html.to_string(),
        mode: quirks_name(dom.quirks_mode.get()),
        before,
        after,
        base_href: first_base_href(&dom.document),
    }
}

/// A string as a JSON string literal.
fn push_json_str(out: &mut String, s: &str) {
    out.push('"');
    let bytes = s.as_bytes();
    let mut from = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc: &str = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0..=0x1f => "",
            _ => continue,
        };
        out.push_str(&s[from..i]);
        if esc.is_empty() {
            out.push_str(&format!("\\u{:04x}", b));
        } else {
            out.push_str(esc);
        }
        from = i + 1;
    }
    out.push_str(&s[from..]);
    out.push('"');
}

/// Write one node as JSON, recording any scripts encountered. Written
/// straight into the string: building a `serde_json::Value` tree first cost
/// 300 ms on a 1.2 MB article, six times the parse.
fn serialize(node: &Handle, out: &mut String, scripts: &mut Vec<Script>, modes: &mut Vec<ScriptMode>) -> bool {
    match &node.data {
        NodeData::Element {
            name,
            attrs,
            template_contents,
            ..
        } => {
            let tag = name.local.to_string();
            if tag == "script" {
                let attr = |name: &str| {
                    attrs
                        .borrow()
                        .iter()
                        .find(|a| &*a.name.local == name)
                        .map(|a| a.value.to_string())
                };
                let module = attr("type")
                    .map(|t| t.trim().eq_ignore_ascii_case("module"))
                    .unwrap_or(false);
                let nomodule = attrs.borrow().iter().any(|a| &*a.name.local == "nomodule");
                let has = |name: &str| attrs.borrow().iter().any(|a| &*a.name.local == name);
                let has_src = attr("src").map(|s| !s.is_empty()).unwrap_or(false);
                // `async`/`defer` only matter on a classic script with `src`;
                // a module is always deferred, and `async` makes it run on arrival.
                let mode = if module {
                    if has("async") { ScriptMode::Async } else { ScriptMode::Defer }
                } else if has_src && has("async") {
                    ScriptMode::Async
                } else if has_src && has("defer") {
                    ScriptMode::Defer
                } else {
                    ScriptMode::Blocking
                };
                let before = scripts.len();
                // A `<script>` whose type is not JavaScript is a data block, not
                // code: an import map, structured data, a template, a pile of
                // JSON the page reads back out of `textContent`. A browser never
                // runs one. We ran them all, and every real page carries at least
                // one — chess.com's `application/ld+json` threw a SyntaxError on
                // its first colon, which is what a page's own error handler then
                // reports as ours.
                let executable = match attr("type") {
                    None => true,
                    Some(t) => {
                        let t = t.trim().to_ascii_lowercase();
                        let t = t.split(';').next().unwrap_or("").trim().to_string();
                        t.is_empty() || t == "module" || is_javascript_type(&t)
                    }
                };
                let import_map = attr("type").is_some_and(|t| t.trim().eq_ignore_ascii_case("importmap"));
                if import_map && attr("src").is_none() {
                    scripts.push(Script::ImportMap(text_content(node)));
                } else if !executable || (nomodule && !module) {
                    scripts.push(Script::Skipped);
                } else {
                    match attr("src") {
                    Some(src) if !src.is_empty() => scripts.push(if module {
                        Script::ExternalModule(src)
                    } else {
                        Script::External(src)
                    }),
                        _ => {
                            let code = text_content(node);
                            scripts.push(if module {
                                Script::InlineModule(code)
                            } else {
                                Script::Inline(code)
                            })
                        }
                    }
                }
                for _ in before..scripts.len() {
                    modes.push(mode);
                }
            }

            out.push_str("{\"k\":\"e\",\"tag\":");
            push_json_str(out, &tag);
            // Namespace for foreign content (SVG, MathML); without it an
            // inline <svg> becomes HTMLUnknownElement.
            let ns: &str = &name.ns;
            if !(ns.is_empty() || ns == "http://www.w3.org/1999/xhtml") {
                out.push_str(",\"ns\":");
                push_json_str(out, ns);
            }
            out.push_str(",\"attrs\":[");
            for (i, a) in attrs.borrow().iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('[');
                // `xlink:href`, `xml:lang`: the qualified name, as Chrome
                // reports it (`xmlns` has an empty prefix, not one).
                match &a.name.prefix {
                    Some(p) if !p.is_empty() => push_json_str(out, &format!("{}:{}", p, a.name.local)),
                    _ => push_json_str(out, &a.name.local),
                }
                out.push(',');
                push_json_str(out, &a.value);
                // Its namespace, in foreign content.
                if !a.name.ns.is_empty() {
                    out.push(',');
                    push_json_str(out, &a.name.ns);
                }
                out.push(']');
            }
            out.push_str("],\"children\":[");
            // `<template>` keeps its parsed content apart from its children
            // (html5ever puts it in `template_contents`); without it
            // `t.content` is empty.
            let holder = template_contents.borrow();
            let source = match holder.as_ref() {
                Some(contents) => contents,
                None => node,
            };
            serialize_children(source, out, scripts, modes);
            out.push_str("]}");
            true
        }
        NodeData::Text { contents } => {
            out.push_str("{\"k\":\"t\",\"v\":");
            push_json_str(out, &contents.borrow());
            out.push('}');
            true
        }
        NodeData::Comment { contents } => {
            comment_json(out, contents);
            true
        }
        NodeData::Doctype {
            name,
            public_id,
            system_id,
        } => {
            out.push_str("{\"k\":\"d\",\"name\":");
            push_json_str(out, name);
            out.push_str(",\"publicId\":");
            push_json_str(out, public_id);
            out.push_str(",\"systemId\":");
            push_json_str(out, system_id);
            out.push('}');
            true
        }
        // Document: nothing.
        _ => false,
    }
}

/// A node's children, comma-separated.
fn serialize_children(node: &Handle, out: &mut String, scripts: &mut Vec<Script>, modes: &mut Vec<ScriptMode>) {
    let mut first = true;
    for c in node.children.borrow().iter() {
        let mark = out.len();
        if !first {
            out.push(',');
        }
        if serialize(c, out, scripts, modes) {
            first = false;
        } else {
            out.truncate(mark);
        }
    }
}

/// A comment, or the processing instruction the tokenizer handed over as one
/// (`\0target\0data`, see `vendor/html5ever`).
fn comment_json(out: &mut String, contents: &str) {
    if let Some(rest) = contents.strip_prefix('\0') {
        if let Some((target, data)) = rest.split_once('\0') {
            out.push_str("{\"k\":\"p\",\"t\":");
            push_json_str(out, target);
            out.push_str(",\"v\":");
            push_json_str(out, data);
            out.push('}');
            return;
        }
    }
    out.push_str("{\"k\":\"c\",\"v\":");
    push_json_str(out, contents);
    out.push('}');
}

fn quirks_name(mode: html5ever::tree_builder::QuirksMode) -> &'static str {
    match mode {
        html5ever::tree_builder::QuirksMode::Quirks => "quirks",
        html5ever::tree_builder::QuirksMode::LimitedQuirks => "limited",
        html5ever::tree_builder::QuirksMode::NoQuirks => "no",
    }
}

/// Parse markup as `innerHTML` does: the children it gives an element named
/// `context` in namespace `ns`, in a document in quirks mode or not. A JSON
/// array of node specs (see [`ParsedPage`]).
pub fn parse_fragment_json(html: &str, context: &str, ns: &str, quirks: &str) -> String {
    use html5ever::{tree_builder::QuirksMode, LocalName, Namespace, ParseOpts, QualName};
    let mut opts = ParseOpts::default();
    opts.tree_builder.quirks_mode = match quirks {
        "quirks" => QuirksMode::Quirks,
        "limited" => QuirksMode::LimitedQuirks,
        _ => QuirksMode::NoQuirks,
    };
    let name = QualName::new(None, Namespace::from(ns), LocalName::from(context));
    let dom = html5ever::parse_fragment(RcDom::default(), opts, name, Vec::new(), true).one(html);
    let mut scripts = Vec::new();
    let mut modes = Vec::new();
    let mut out = String::with_capacity(html.len() + html.len() / 2);
    out.push('[');
    // The fragment's nodes are the children of the `<html>` root the parser
    // makes for them.
    if let Some(root) = dom.document.children.borrow().first() {
        serialize_children(root, &mut out, &mut scripts, &mut modes);
    }
    out.push(']');
    out
}

/// Parse a whole document, as `DOMParser` does: its children (doctype,
/// comments and processing instructions around the root, the root) and its
/// mode.
pub fn parse_document_json(html: &str) -> String {
    let dom = html5ever::parse_document(RcDom::default(), Default::default()).one(html);
    let mut scripts = Vec::new();
    let mut modes = Vec::new();
    let mut out = String::with_capacity(html.len() + html.len() / 2);
    out.push_str("{\"children\":[");
    serialize_children(&dom.document, &mut out, &mut scripts, &mut modes);
    out.push_str("],\"mode\":");
    push_json_str(&mut out, quirks_name(dom.quirks_mode.get()));
    out.push('}');
    out
}

/// Concatenate the direct text children of a node (used for inline scripts).
/// Is this `type` one a browser will execute? The HTML spec fixes the list of
/// JavaScript MIME types; everything else — `application/json`, `importmap`,
/// `speculationrules`, `text/template`, `application/ld+json` — makes the
/// element a data block that only `textContent` ever reads.
fn is_javascript_type(t: &str) -> bool {
    matches!(
        t,
        "application/ecmascript"
            | "application/javascript"
            | "application/x-ecmascript"
            | "application/x-javascript"
            | "text/ecmascript"
            | "text/javascript"
            | "text/javascript1.0"
            | "text/javascript1.1"
            | "text/javascript1.2"
            | "text/javascript1.3"
            | "text/javascript1.4"
            | "text/javascript1.5"
            | "text/jscript"
            | "text/livescript"
            | "text/x-ecmascript"
            | "text/x-javascript"
    )
}

fn text_content(node: &Handle) -> String {
    let mut out = String::new();
    for child in node.children.borrow().iter() {
        if let NodeData::Text { contents } = &child.data {
            out.push_str(&contents.borrow());
        }
    }
    out
}

/// The JavaScript DOM runtime: defines `Node`, `Element`, `Text`, `Document`,
/// `Event`, the `document` global, and the `__pt_installDocument` /
/// `__pt_finishLoad` hooks the loader calls. Run once per context, after the
/// stealth environment bootstrap.
pub fn runtime_js() -> &'static str {
    include_str!("dom_runtime.js")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writing the parsed tree out costs less than parsing it: the JSON is
    /// written straight into a string, 1.6 times the bare parse here; through
    /// a `serde_json::Value` tree it was 4.2 times (and 300 ms against 50 on a
    /// 1.2 MB article). A ratio, not a time, so a busy machine does not fail it.
    #[test]
    fn writing_the_tree_costs_less_than_parsing_it() {
        let mut html = String::from("<!doctype html><html><body>");
        for i in 0..20000 {
            html.push_str(&format!(
                "<div class=\"c{}\" data-x=\"&amp;{}\"><a href=\"/p/{}\">link &hellip; {}</a><span>t&nbsp;x</span><!--n--></div>",
                i % 7, i, i, i
            ));
        }
        html.push_str("</body></html>");
        let best = |f: &dyn Fn()| {
            (0..3)
                .map(|_| {
                    let t = std::time::Instant::now();
                    f();
                    t.elapsed()
                })
                .min()
                .unwrap()
        };
        let parse = best(&|| {
            let _ = html5ever::parse_document(RcDom::default(), Default::default()).one(html.as_str());
        });
        let whole = best(&|| {
            let _ = parse_document_json(&html);
        });
        assert!(whole < parse * 3, "parse {parse:?}, parse and write {whole:?}");
    }

    #[test]
    fn parses_elements_attrs_and_text() {
        let page = parse(r#"<html><body><div id="main" class="a b">Hi</div></body></html>"#);
        // root is <html>; drill into body > div.
        let tree: Value = serde_json::from_str(&page.root).unwrap();
        let html = &tree;
        assert_eq!(html["tag"], "html");
        // Find the div somewhere in the tree via a quick recursive search.
        fn find<'a>(v: &'a Value, tag: &str) -> Option<&'a Value> {
            if v["tag"] == tag {
                return Some(v);
            }
            v["children"].as_array()?.iter().find_map(|c| find(c, tag))
        }
        let div = find(html, "div").expect("div present");
        assert_eq!(div["attrs"][0][0], "id");
        assert_eq!(div["attrs"][0][1], "main");
        assert_eq!(div["children"][0]["k"], "t");
        assert_eq!(div["children"][0]["v"], "Hi");
    }

    #[test]
    fn collects_scripts_in_order() {
        let page = parse(
            r#"<html><body>
                <script>var a = 1;</script>
                <script src="/app.js"></script>
                <script>var b = 2;</script>
            </body></html>"#,
        );
        assert_eq!(
            page.scripts,
            vec![
                Script::Inline("var a = 1;".into()),
                Script::External("/app.js".into()),
                Script::Inline("var b = 2;".into()),
            ]
        );
    }

    /// A Vite build ships both halves: the module bundle and a `nomodule`
    /// fallback for browsers without modules. A browser takes exactly one — and
    /// the element still counts, because `document.currentScript` is addressed
    /// by position among all the `<script>`s the parser saw.
    /// Every real page carries at least one `<script>` that is not code:
    /// structured data, an import map, a template. A browser reads them and runs
    /// none of them; we ran them all, and chess.com's `application/ld+json` threw
    /// a SyntaxError on its first colon.
    #[test]
    fn a_script_that_is_not_javascript_is_data_and_is_not_run() {
        let page = parse(
            r#"<html><head>
                <script type="application/ld+json">{"@context": "https://schema.org"}</script>
                <script type="importmap">{"imports": {}}</script>
                <script type="speculationrules">{"prerender": []}</script>
                <script type="text/template"><div>{{x}}</div></script>
                <script type="text/javascript; charset=utf-8">var a = 1</script>
                <script type="TEXT/JavaScript">var b = 2</script>
                <script>var c = 3</script>
                <script type="module">var d = 4</script>
            </head></html>"#,
        );
        assert_eq!(
            page.scripts,
            vec![
                Script::Skipped,
                Script::ImportMap(r#"{"imports": {}}"#.into()),
                Script::Skipped,
                Script::Skipped,
                Script::Inline("var a = 1".into()),
                Script::Inline("var b = 2".into()),
                Script::Inline("var c = 3".into()),
                Script::InlineModule("var d = 4".into()),
            ]
        );
    }

    #[test]
    fn a_nomodule_fallback_is_counted_but_not_run() {
        let page = parse(
            r#"<html><body>
                <script type="module" src="/app.js"></script>
                <script nomodule src="/legacy.js"></script>
                <script nomodule>System.import('/legacy-entry.js')</script>
                <script>var tail = 1;</script>
            </body></html>"#,
        );
        assert_eq!(
            page.scripts,
            vec![
                Script::ExternalModule("/app.js".into()),
                Script::Skipped,
                Script::Skipped,
                Script::Inline("var tail = 1;".into()),
            ]
        );
    }

    #[test]
    fn install_script_references_installer() {
        let page = parse("<html><body>x</body></html>");
        assert!(page
            .install_script()
            .starts_with("globalThis.__pt_installDocument("));
    }
}
