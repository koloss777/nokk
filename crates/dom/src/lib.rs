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
}

/// The result of parsing an HTML document.
#[derive(Debug, Clone)]
pub struct ParsedPage {
    /// The `<html>` element serialized as a JSON tree (see module docs for the
    /// shape). Consumed by `__pt_installDocument` in [`runtime_js`].
    pub root: Value,
    /// Scripts to execute, in document order.
    pub scripts: Vec<Script>,
}

impl ParsedPage {
    /// The JS statement that installs this page's tree as `document`.
    pub fn install_script(&self) -> String {
        format!("globalThis.__pt_installDocument({});", self.root)
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
    let root = dom
        .document
        .children
        .borrow()
        .iter()
        .find(|c| matches!(c.data, NodeData::Element { .. }))
        .map(|html| serialize(html, &mut scripts))
        .unwrap_or(Value::Null);

    ParsedPage { root, scripts }
}

/// Serialize one node to JSON, recording any scripts encountered.
fn serialize(node: &Handle, scripts: &mut Vec<Script>) -> Value {
    match &node.data {
        NodeData::Element { name, attrs, .. } => {
            let tag = name.local.to_string();
            let attrs_json: Vec<Value> = attrs
                .borrow()
                .iter()
                .map(|a| json!([a.name.local.to_string(), a.value.to_string()]))
                .collect();

            if tag == "script" {
                let src = attrs
                    .borrow()
                    .iter()
                    .find(|a| &*a.name.local == "src")
                    .map(|a| a.value.to_string());
                match src {
                    Some(src) if !src.is_empty() => scripts.push(Script::External(src)),
                    _ => scripts.push(Script::Inline(text_content(node))),
                }
            }

            let children: Vec<Value> = node
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
