//! Document parsing that keeps structure: every block of text knows its heading path.
//!
//! Formats: Markdown (ATX and setext headings, fenced code, lists, pipe tables), HTML (headings,
//! paragraphs, lists, tables, `pre`; scripts, styles and comments dropped; entities decoded) and
//! plain text (paragraphs, no headings). PDF is not parsed: no permissively licensed, pure-Rust
//! extractor is vendored, so PDFs must be converted upstream (see docs/rag.md).
//!
//! Heading paths are what make structure-aware chunks work: a chunk is embedded with the real
//! path of headings above it, which beat LLM-written chunk context and a shuffled-heading placebo
//! in a pre-registered ablation (arXiv 2610.10170, preprint), at zero LLM cost.

use serde::{Deserialize, Serialize};

/// What a document is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    Markdown,
    Html,
    Text,
}

impl ContentType {
    /// From a media type or a short name (`text/markdown`, `md`, `text/html`, `text/plain`, ...).
    /// PDF and other binary formats are refused with a reason.
    pub fn parse(s: &str) -> Result<Self, String> {
        let base = s.split(';').next().unwrap_or_default().trim().to_ascii_lowercase();
        match base.as_str() {
            "text/markdown" | "text/x-markdown" | "markdown" | "md" => Ok(Self::Markdown),
            "text/html" | "application/xhtml+xml" | "html" | "htm" => Ok(Self::Html),
            "text/plain" | "text" | "txt" | "plain" => Ok(Self::Text),
            "application/pdf" | "pdf" => Err("PDF is not supported yet: convert it to Markdown or text first".into()),
            other => Err(format!("content type '{other}' is not supported (markdown, html or text)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown",
            Self::Html => "text/html",
            Self::Text => "text/plain",
        }
    }
}

/// The kind of a block decides how an oversized block is split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    Paragraph,
    List,
    Code,
    Table,
}

/// A run of text under one heading path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub heading_path: Vec<String>,
    pub text: String,
    pub kind: BlockKind,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The document's own title (`<title>`, or the single top-level heading), when it has one.
    pub title: Option<String>,
    pub blocks: Vec<Block>,
}

pub fn parse(kind: ContentType, text: &str) -> Parsed {
    match kind {
        ContentType::Markdown => markdown(text),
        ContentType::Html => html(text),
        ContentType::Text => plain(text),
    }
}

/// The heading stack: `(level, text)` pairs; a heading pops every heading at its level or deeper.
#[derive(Default)]
struct Headings(Vec<(usize, String)>);

impl Headings {
    fn push(&mut self, level: usize, text: String) {
        while self.0.last().is_some_and(|(l, _)| *l >= level) {
            self.0.pop();
        }
        if !text.is_empty() {
            self.0.push((level, text));
        }
    }

    fn path(&self) -> Vec<String> {
        self.0.iter().map(|(_, t)| t.clone()).collect()
    }
}

struct Builder {
    headings: Headings,
    blocks: Vec<Block>,
    buf: Vec<String>,
    kind: BlockKind,
}

impl Builder {
    fn new() -> Self {
        Self { headings: Headings::default(), blocks: Vec::new(), buf: Vec::new(), kind: BlockKind::Paragraph }
    }

    fn flush(&mut self) {
        let joined = if self.kind == BlockKind::Code {
            self.buf.join("\n")
        } else {
            self.buf.iter().map(|l| l.trim()).collect::<Vec<_>>().join(if self.kind == BlockKind::Paragraph {
                " "
            } else {
                "\n"
            })
        };
        self.buf.clear();
        let text = joined.trim_matches('\n').to_owned();
        if !text.trim().is_empty() {
            self.blocks.push(Block { heading_path: self.headings.path(), text, kind: self.kind });
        }
        self.kind = BlockKind::Paragraph;
    }

    fn line(&mut self, kind: BlockKind, line: &str) {
        if self.kind != kind && !self.buf.is_empty() {
            self.flush();
        }
        self.kind = kind;
        self.buf.push(line.to_owned());
    }

    fn heading(&mut self, level: usize, text: &str) {
        self.flush();
        self.headings.push(level, clean_inline(text));
    }
}

/// Top-level title: a single level-1 heading that opens the document.
fn title_of(blocks: &[Block], first_heading: Option<(usize, String)>) -> Option<String> {
    let (level, text) = first_heading?;
    let ones = blocks.iter().filter(|b| b.heading_path.first() == Some(&text)).count();
    (level == 1 && (ones == blocks.len() || blocks.is_empty())).then_some(text)
}

fn atx(line: &str) -> Option<(usize, &str)> {
    let t = line.trim_start_matches(' ');
    if line.len() - t.len() > 3 {
        return None;
    }
    let level = t.bytes().take_while(|b| *b == b'#').count();
    if !(1..=6).contains(&level) {
        return None;
    }
    let rest = &t[level..];
    if !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')) {
        return None;
    }
    let rest = rest.trim();
    // A closing run of #s is not part of the heading.
    let rest = rest.trim_end_matches('#').trim_end();
    Some((level, rest))
}

fn list_item(line: &str) -> bool {
    let t = line.trim_start();
    if let Some(r) = t.strip_prefix(['-', '*', '+']) {
        return r.starts_with(' ');
    }
    let digits = t.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && digits < 10 && (t[digits..].starts_with(". ") || t[digits..].starts_with(") "))
}

/// Minimal inline cleanup for headings: emphasis markers and link targets go, the text stays.
fn clean_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' | '_' | '`' => {}
            ']' if chars.peek() == Some(&'(') => {
                for c in chars.by_ref() {
                    if c == ')' {
                        break;
                    }
                }
            }
            '[' | '!' if c == '[' || chars.peek() == Some(&'[') => {}
            _ => out.push(c),
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn markdown(text: &str) -> Parsed {
    let mut b = Builder::new();
    let mut first_heading = None;
    let mut fence: Option<String> = None;
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        if let Some(f) = &fence {
            if line.trim_start().starts_with(f.as_str()) && line.trim().trim_start_matches(f.as_str()).trim().is_empty()
            {
                b.flush();
                fence = None;
            } else {
                b.line(BlockKind::Code, line);
            }
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            b.flush();
            let marker: String = trimmed.chars().take_while(|c| *c == '`' || *c == '~').collect();
            fence = Some(marker);
            b.kind = BlockKind::Code;
            continue;
        }
        if let Some((level, h)) = atx(line) {
            if first_heading.is_none() {
                first_heading = Some((level, clean_inline(h)));
            }
            b.heading(level, h);
            continue;
        }
        // Setext: a one-line paragraph underlined with === or ---.
        let under = line.trim();
        let setext = !under.is_empty()
            && (under.bytes().all(|c| c == b'=') || (under.len() >= 2 && under.bytes().all(|c| c == b'-')));
        if setext && b.kind == BlockKind::Paragraph && b.buf.len() == 1 {
            let h = b.buf.pop().unwrap_or_default();
            let level = if under.starts_with('=') { 1 } else { 2 };
            if first_heading.is_none() {
                first_heading = Some((level, clean_inline(&h)));
            }
            b.heading(level, &h);
            continue;
        }
        if under.is_empty() {
            b.flush();
            continue;
        }
        // A thematic break.
        if under.len() >= 3
            && (under.bytes().all(|c| c == b'-' || c == b' ') || under.bytes().all(|c| c == b'*' || c == b' '))
        {
            b.flush();
            continue;
        }
        if trimmed.starts_with('|') {
            b.line(BlockKind::Table, line);
        } else if list_item(line) || (b.kind == BlockKind::List && line.starts_with(' ')) {
            b.line(BlockKind::List, line);
        } else {
            b.line(BlockKind::Paragraph, line);
        }
    }
    b.flush();
    let title = title_of(&b.blocks, first_heading);
    Parsed { title, blocks: b.blocks }
}

fn plain(text: &str) -> Parsed {
    let mut b = Builder::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            b.flush();
        } else {
            b.line(BlockKind::Paragraph, line);
        }
    }
    b.flush();
    Parsed { title: None, blocks: b.blocks }
}

// ───────────────────────────── HTML ─────────────────────────────

/// Decodes the common named entities and numeric references.
fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after.find(';').filter(|e| *e <= 10);
        let decoded = end.and_then(|e| {
            let name = &after[..e];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                "ndash" => Some('\u{2013}'),
                "mdash" => Some('\u{2014}'),
                "hellip" => Some('\u{2026}'),
                "copy" => Some('\u{a9}'),
                "reg" => Some('\u{ae}'),
                _ => {
                    let n = name.strip_prefix('#')?;
                    let code = match n.strip_prefix(['x', 'X']) {
                        Some(h) => u32::from_str_radix(h, 16).ok()?,
                        None => n.parse::<u32>().ok()?,
                    };
                    char::from_u32(code)
                }
            }?;
            Some((c, e))
        });
        match decoded {
            Some((c, e)) => {
                out.push(c);
                rest = &after[e + 1..];
            }
            None => {
                out.push('&');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// The next `<t` at or after `from` that opens element `t` (not a longer name such as `<header`).
fn find_tag(lower: &str, from: usize, t: &str) -> Option<usize> {
    let needle = format!("<{t}");
    let mut at = from;
    while let Some(o) = lower[at..].find(&needle) {
        let start = at + o;
        let boundary = lower.as_bytes().get(start + needle.len()).copied();
        if matches!(boundary, Some(b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/') | None) {
            return Some(start);
        }
        at = start + needle.len();
    }
    None
}

/// Removes `<tag ...> ... </tag>` for elements whose content is never text (case-insensitive).
fn strip_elements(s: &str, tags: &[&str]) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut pos = 0;
    while pos < s.len() {
        // The next comment or dropped element.
        let mut next: Option<(usize, usize)> = None;
        if let Some(c) = lower[pos..].find("<!--") {
            let start = pos + c;
            let end = lower[start..].find("-->").map_or(s.len(), |e| start + e + 3);
            next = Some((start, end));
        }
        for t in tags {
            if let Some(start) = find_tag(&lower, pos, t) {
                if next.is_some_and(|(s0, _)| s0 <= start) {
                    continue;
                }
                let close = format!("</{t}");
                let end = lower[start..]
                    .find(&close)
                    .map(|e| start + e)
                    .and_then(|e| lower[e..].find('>').map(|g| e + g + 1))
                    .unwrap_or(s.len());
                next = Some((start, end));
            }
        }
        match next {
            Some((start, end)) => {
                out.push_str(&s[pos..start]);
                out.push(' ');
                pos = end;
            }
            None => {
                out.push_str(&s[pos..]);
                break;
            }
        }
    }
    out
}

/// Text outside a list continues a list block, else a paragraph.
fn list_or_para(k: BlockKind) -> BlockKind {
    if k == BlockKind::List { BlockKind::List } else { BlockKind::Paragraph }
}

fn html(text: &str) -> Parsed {
    let doc_title = {
        let lower = text.to_ascii_lowercase();
        lower.find("<title").and_then(|s| {
            let open = s + lower[s..].find('>')? + 1;
            let close = open + lower[open..].find("</title")?;
            let t = decode_entities(&text[open..close]).split_whitespace().collect::<Vec<_>>().join(" ");
            (!t.is_empty()).then_some(t)
        })
    };
    let body = strip_elements(text, &["script", "style", "noscript", "template", "head", "svg", "iframe"]);
    let mut b = Builder::new();
    let mut first_heading: Option<(usize, String)> = None;
    let mut heading: Option<(usize, String)> = None;
    let mut pre = 0usize;
    let mut row: Vec<String> = Vec::new();
    let mut cell: Option<String> = None;
    let mut text_buf = String::new();
    let mut pos = 0;

    // Appends text to wherever it belongs now: a heading, a table cell, or the current block.
    fn emit(s: &str, heading: &mut Option<(usize, String)>, cell: &mut Option<String>, text_buf: &mut String) {
        if let Some((_, h)) = heading {
            h.push_str(s);
        } else if let Some(c) = cell {
            c.push_str(s);
        } else {
            text_buf.push_str(s);
        }
    }

    let flush_text = |b: &mut Builder, text_buf: &mut String, kind: BlockKind| {
        let t = if kind == BlockKind::Code {
            text_buf.trim_matches('\n').to_owned()
        } else {
            text_buf.split_whitespace().collect::<Vec<_>>().join(" ")
        };
        text_buf.clear();
        if !t.is_empty() {
            if kind == BlockKind::List {
                b.line(BlockKind::List, &format!("- {t}"));
            } else {
                b.line(kind, &t);
                if kind != BlockKind::Code {
                    b.flush();
                }
            }
        }
    };

    while pos < body.len() {
        let Some(lt) = body[pos..].find('<') else {
            emit(&decode_entities(&body[pos..]), &mut heading, &mut cell, &mut text_buf);
            break;
        };
        if lt > 0 {
            emit(&decode_entities(&body[pos..pos + lt]), &mut heading, &mut cell, &mut text_buf);
        }
        let start = pos + lt;
        let Some(gt) = body[start..].find('>') else {
            emit(&decode_entities(&body[start..]), &mut heading, &mut cell, &mut text_buf);
            break;
        };
        let tag = &body[start + 1..start + gt];
        pos = start + gt + 1;
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase();
        match name.as_str() {
            "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
                let level = usize::from(name.as_bytes()[1] - b'0');
                if closing {
                    if let Some((l, h)) = heading.take() {
                        let h = h.split_whitespace().collect::<Vec<_>>().join(" ");
                        if first_heading.is_none() && !h.is_empty() {
                            first_heading = Some((l, h.clone()));
                        }
                        b.heading(l, &h);
                    }
                } else {
                    let k = list_or_para(b.kind);
                    flush_text(&mut b, &mut text_buf, k);
                    b.flush();
                    heading = Some((level, String::new()));
                }
            }
            "pre" => {
                if closing {
                    pre = pre.saturating_sub(1);
                    flush_text(&mut b, &mut text_buf, BlockKind::Code);
                    b.flush();
                } else {
                    flush_text(&mut b, &mut text_buf, BlockKind::Paragraph);
                    pre += 1;
                }
            }
            "li" => {
                if closing {
                    flush_text(&mut b, &mut text_buf, BlockKind::List);
                } else {
                    let k = list_or_para(b.kind);
                    flush_text(&mut b, &mut text_buf, k);
                }
            }
            "ul" | "ol" | "dl" => {
                let k = list_or_para(b.kind);
                flush_text(&mut b, &mut text_buf, k);
                if closing {
                    b.flush();
                }
            }
            "td" | "th" => {
                if closing {
                    if let Some(c) = cell.take() {
                        row.push(c.split_whitespace().collect::<Vec<_>>().join(" "));
                    }
                } else {
                    if let Some(c) = cell.take() {
                        row.push(c.split_whitespace().collect::<Vec<_>>().join(" "));
                    }
                    cell = Some(String::new());
                }
            }
            "tr" => {
                if let Some(c) = cell.take() {
                    row.push(c.split_whitespace().collect::<Vec<_>>().join(" "));
                }
                if !row.is_empty() {
                    let line = format!("| {} |", row.join(" | "));
                    row.clear();
                    b.line(BlockKind::Table, &line);
                }
            }
            "table" => {
                flush_text(&mut b, &mut text_buf, BlockKind::Paragraph);
                if closing {
                    if let Some(c) = cell.take() {
                        row.push(c);
                    }
                    if !row.is_empty() {
                        let line = format!("| {} |", row.join(" | "));
                        row.clear();
                        b.line(BlockKind::Table, &line);
                    }
                    b.flush();
                }
            }
            "br" => {
                if pre > 0 {
                    text_buf.push('\n');
                } else {
                    emit(" ", &mut heading, &mut cell, &mut text_buf);
                }
            }
            "p" | "div" | "section" | "article" | "main" | "header" | "footer" | "blockquote" | "figcaption" | "dd"
            | "dt" | "aside" | "nav" | "body" | "html" => {
                if pre == 0 && heading.is_none() && cell.is_none() {
                    let k = list_or_para(b.kind);
                    flush_text(&mut b, &mut text_buf, k);
                }
            }
            _ => {
                // Inline elements: a separator keeps words apart where markup joined them.
                if matches!(
                    name.as_str(),
                    "span" | "a" | "em" | "strong" | "b" | "i" | "code" | "small" | "sup" | "sub"
                ) {
                    continue;
                }
                emit(" ", &mut heading, &mut cell, &mut text_buf);
            }
        }
    }
    let k = list_or_para(b.kind);
    flush_text(&mut b, &mut text_buf, k);
    b.flush();
    let title = doc_title.or_else(|| title_of(&b.blocks, first_heading));
    Parsed { title, blocks: b.blocks }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(p: &Parsed) -> Vec<(String, String)> {
        p.blocks.iter().map(|b| (b.heading_path.join(" > "), b.text.clone())).collect()
    }

    #[test]
    fn markdown_keeps_heading_paths() {
        let md = "# Handbook\n\nIntro text\nspans lines.\n\n## Leave\n\nAnnual leave is 25 days.\n\n### Carry over\n\n- up to 5 days\n- by March\n\n## Expenses\n\n```sh\nexpense submit --id 4471\n```\n\n| item | limit |\n|---|---|\n| meal | 40 |\n";
        let p = parse(ContentType::Markdown, md);
        assert_eq!(p.title.as_deref(), Some("Handbook"));
        let got = paths(&p);
        assert_eq!(got[0], ("Handbook".into(), "Intro text spans lines.".into()));
        assert_eq!(got[1], ("Handbook > Leave".into(), "Annual leave is 25 days.".into()));
        assert_eq!(got[2], ("Handbook > Leave > Carry over".into(), "- up to 5 days\n- by March".into()));
        assert_eq!(got[3], ("Handbook > Expenses".into(), "expense submit --id 4471".into()));
        assert_eq!(p.blocks[3].kind, BlockKind::Code);
        assert_eq!(p.blocks[4].kind, BlockKind::Table);
        assert!(got[4].1.contains("| meal | 40 |"));
    }

    #[test]
    fn setext_headings_and_breaks() {
        let md = "Guide\n=====\n\nFirst.\n\nPart two\n--------\nSecond.\n\n---\n\nThird.";
        let p = parse(ContentType::Markdown, md);
        let got = paths(&p);
        assert_eq!(got[0], ("Guide".into(), "First.".into()));
        assert_eq!(got[1], ("Guide > Part two".into(), "Second.".into()));
        assert_eq!(got[2], ("Guide > Part two".into(), "Third.".into()));
    }

    #[test]
    fn a_heading_pops_deeper_headings() {
        let md = "# A\n## B\n### C\ntext c\n## D\ntext d\n# E\ntext e";
        let got = paths(&parse(ContentType::Markdown, md));
        assert_eq!(
            got,
            vec![
                ("A > B > C".into(), "text c".into()),
                ("A > D".into(), "text d".into()),
                ("E".into(), "text e".into()),
            ]
        );
    }

    #[test]
    fn html_structure_and_entities() {
        let html = r#"<html><head><title>IT &amp; Security</title><style>p{}</style></head>
<body><script>alert("x")</script><h1>Access</h1><p>Use the <b>VPN</b> &mdash; always.</p>
<h2>Passwords</h2><ul><li>12 characters</li><li>rotate yearly</li></ul>
<!-- hidden note --><table><tr><th>System</th><th>Owner</th></tr><tr><td>CRM</td><td>Sales</td></tr></table>
<pre>ssh -J bastion host</pre></body></html>"#;
        let p = parse(ContentType::Html, html);
        assert_eq!(p.title.as_deref(), Some("IT & Security"));
        let got = paths(&p);
        assert_eq!(got[0], ("Access".into(), "Use the VPN \u{2014} always.".into()));
        assert_eq!(got[1], ("Access > Passwords".into(), "- 12 characters\n- rotate yearly".into()));
        assert_eq!(got[2], ("Access > Passwords".into(), "| System | Owner |\n| CRM | Sales |".into()));
        assert_eq!(got[3], ("Access > Passwords".into(), "ssh -J bastion host".into()));
        assert!(!got.iter().any(|(_, t)| t.contains("alert") || t.contains("hidden note")));
    }

    #[test]
    fn plain_text_paragraphs_and_types() {
        let p = parse(ContentType::Text, "one\ntwo\n\nthree");
        assert_eq!(paths(&p), vec![(String::new(), "one two".into()), (String::new(), "three".into())]);
        assert_eq!(ContentType::parse("text/markdown; charset=utf-8"), Ok(ContentType::Markdown));
        assert!(ContentType::parse("application/pdf").unwrap_err().contains("PDF"));
        assert_eq!(decode_entities("a &#65;&#x42; &bogus; &"), "a AB &bogus; &");
    }
}
