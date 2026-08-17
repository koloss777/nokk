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
}

/// The result of parsing an HTML document.
#[derive(Debug, Clone)]
pub struct ParsedPage {
    /// The `<html>` element serialized as a JSON tree (see module docs for the
    /// shape). Consumed by `__pt_installDocument` in [`runtime_js`].
    pub root: Value,
    /// Scripts to execute, in document order.
    pub scripts: Vec<Script>,
    /// The document's `<!DOCTYPE …>`, if it had one: name, public id, system id.
    /// A page without one is in quirks mode and its `document.doctype` is null —
    /// both of which a fingerprint reads, so the difference has to survive the
    /// parse instead of being dropped with the node.
    pub doctype: Option<(String, String, String)>,
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
        format!("globalThis.__pt_installDocument({}, {});", self.root, dt)
    }
}

/// Parse an HTML document into a JSON tree plus its ordered script list.
pub fn parse(html: &str) -> ParsedPage {
    let dom = html5ever::parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut html.as_bytes())
        .unwrap_or_else(|_| RcDom::default());

    let mut scripts = Vec::new();
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
    let root = dom
        .document
        .children
        .borrow()
        .iter()
        .find(|c| matches!(c.data, NodeData::Element { .. }))
        .map(|html| serialize(html, &mut scripts))
        .unwrap_or(Value::Null);

    ParsedPage {
        root,
        scripts,
        doctype,
    }
}

/// Serialize one node to JSON, recording any scripts encountered.
fn serialize(node: &Handle, scripts: &mut Vec<Script>) -> Value {
    match &node.data {
        NodeData::Element {
            name,
            attrs,
            template_contents,
            ..
        } => {
            let tag = name.local.to_string();
            let attrs_json: Vec<Value> = attrs
                .borrow()
                .iter()
                .map(|a| json!([a.name.local.to_string(), a.value.to_string()]))
                .collect();

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

            // `<template>` держит разобранное содержимое отдельно от детей —
            // так велит разбор, и html5ever кладёт его в `template_contents`.
            // Мы читали только `children` и теряли содержимое целиком: у
            // страницы `t.content` оказывался пуст, а код, который строит узлы
            // через шаблон, — ни с чем.
            let holder = template_contents.borrow();
            let source = match holder.as_ref() {
                Some(contents) => contents,
                None => node,
            };
            let children: Vec<Value> = source
                .children
                .borrow()
                .iter()
                .map(|c| serialize(c, scripts))
                .filter(|v| !v.is_null())
                .collect();

            json!({ "k": "e", "tag": tag, "attrs": attrs_json, "children": children })
        }
        NodeData::Text { contents } => json!({ "k": "t", "v": contents.borrow().to_string() }),
        NodeData::Comment { contents } => json!({ "k": "c", "v": contents.to_string() }),
        // Document, Doctype, ProcessingInstruction: skipped.
        _ => Value::Null,
    }
}

/// Concatenate the direct text children of a node (used for inline scripts).
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

    #[test]
    fn parses_elements_attrs_and_text() {
        let page = parse(r#"<html><body><div id="main" class="a b">Hi</div></body></html>"#);
        // root is <html>; drill into body > div.
        let html = &page.root;
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

    #[test]
    fn install_script_references_installer() {
        let page = parse("<html><body>x</body></html>");
        assert!(page
            .install_script()
            .starts_with("globalThis.__pt_installDocument("));
    }
}
