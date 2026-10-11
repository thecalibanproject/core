//! Structure-aware chunking (docs/research/06-rag-and-token-efficiency.md, "Chunk" and
//! "Contextualize").
//!
//! - A chunk never crosses a heading boundary: it holds blocks of one section, in order
//!   (structure-aligned chunks, arXiv 2610.10170).
//! - Within a section, blocks are packed up to `max_tokens` with **no overlap** (the Chroma
//!   chunking study found a ~200-token recursive splitter without overlap consistently strong; the
//!   note's default is 256 to 512 tokens). A block larger than that is split recursively:
//!   paragraphs and lists at sentence or line boundaries, code and tables at line boundaries, and a
//!   single over-long sentence by words. Embedding-based semantic chunking is not used (arXiv
//!   2410.13070: its cost is not justified by consistent gains).
//! - What is embedded and indexed is the chunk with its real heading path in front
//!   ([`ChunkDraft::indexed_text`]); naive two-stage section-then-chunk retrieval is not used
//!   (it hurt in the same ablation).
//!
//! Token counts are estimated (about four characters per token, the gateway's estimate) rather
//! than counted with the embedder's tokenizer, which the gateway does not have for every
//! provider. Counts are computed once at ingest and stored, so the query path never tokenizes.

use crate::parse::{BlockKind, Parsed};

/// Default largest chunk, in estimated tokens.
pub const DEFAULT_MAX_TOKENS: u32 = 384;
pub const MIN_MAX_TOKENS: u32 = 64;
pub const MAX_MAX_TOKENS: u32 = 2048;

/// Estimated tokens: about four characters per token, at least one per word.
pub fn est_tokens(s: &str) -> u32 {
    let chars = s.chars().count();
    let words = s.split_whitespace().count();
    u32::try_from(chars.div_ceil(4).max(words)).unwrap_or(u32::MAX)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkDraft {
    /// Position in the document (0-based): chunks of one document keep their reading order.
    pub index: u32,
    pub heading_path: Vec<String>,
    pub text: String,
    /// Estimated tokens of `text`.
    pub tokens: u32,
}

impl ChunkDraft {
    /// The text that is embedded and indexed: the document title and the heading path, then the
    /// chunk. The title is not repeated when it is already the first heading.
    pub fn indexed_text(&self, title: Option<&str>) -> String {
        let mut path: Vec<&str> = Vec::new();
        if let Some(t) = title.filter(|t| !t.is_empty())
            && self.heading_path.first().map(String::as_str) != Some(t)
        {
            path.push(t);
        }
        path.extend(self.heading_path.iter().map(String::as_str));
        if path.is_empty() { self.text.clone() } else { format!("{}\n\n{}", path.join(" > "), self.text) }
    }
}

/// Splits `text` into pieces of at most `max` estimated tokens, at the largest boundary that works.
fn split_block(text: &str, kind: BlockKind, max: u32) -> Vec<String> {
    if est_tokens(text) <= max {
        return vec![text.to_owned()];
    }
    let units: Vec<String> = match kind {
        BlockKind::Code | BlockKind::Table | BlockKind::List => text.lines().map(str::to_owned).collect(),
        BlockKind::Paragraph => sentences(text),
    };
    let units: Vec<String> = if units.len() <= 1 { words(text, max) } else { units };
    let sep = if matches!(kind, BlockKind::Paragraph) { " " } else { "\n" };
    let mut out = Vec::new();
    let mut cur = String::new();
    for u in units {
        let pieces = if est_tokens(&u) > max { words(&u, max) } else { vec![u] };
        for p in pieces {
            let candidate = if cur.is_empty() { p.clone() } else { format!("{cur}{sep}{p}") };
            if est_tokens(&candidate) > max && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                cur = p;
            } else {
                cur = candidate;
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Sentence boundaries: `.`, `!` or `?` followed by whitespace, or a line break.
fn sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    for (i, c) in text.char_indices() {
        let end = i + c.len_utf8();
        let boundary = matches!(c, '.' | '!' | '?') && bytes.get(end).is_none_or(|b| b.is_ascii_whitespace());
        if boundary || c == '\n' {
            let s = text[start..end].trim();
            if !s.is_empty() {
                out.push(s.to_owned());
            }
            start = end;
        }
    }
    let s = text[start..].trim();
    if !s.is_empty() {
        out.push(s.to_owned());
    }
    out
}

/// Word windows of at most `max` estimated tokens (a last resort for a single huge sentence).
fn words(text: &str, max: u32) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for w in text.split_whitespace() {
        // A single "word" longer than the limit (a hash, a URL) is cut by characters.
        let w: Vec<String> = if est_tokens(w) > max {
            let chars: Vec<char> = w.chars().collect();
            chars.chunks((max as usize * 4).max(1)).map(|c| c.iter().collect()).collect()
        } else {
            vec![w.to_owned()]
        };
        for w in w {
            let candidate = if cur.is_empty() { w.clone() } else { format!("{cur} {w}") };
            if est_tokens(&candidate) > max && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
                cur = w;
            } else {
                cur = candidate;
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Chunks a parsed document (see the module docs).
pub fn chunk(doc: &Parsed, max_tokens: u32) -> Vec<ChunkDraft> {
    let max = max_tokens.clamp(MIN_MAX_TOKENS, MAX_MAX_TOKENS);
    let mut out: Vec<ChunkDraft> = Vec::new();
    let mut cur: Option<ChunkDraft> = None;
    let push = |out: &mut Vec<ChunkDraft>, c: ChunkDraft| {
        let index = u32::try_from(out.len()).unwrap_or(u32::MAX);
        out.push(ChunkDraft { index, tokens: est_tokens(&c.text), ..c });
    };
    for block in &doc.blocks {
        for piece in split_block(&block.text, block.kind, max) {
            match cur.take() {
                Some(mut c) if c.heading_path == block.heading_path => {
                    let joined = format!("{}\n\n{piece}", c.text);
                    if est_tokens(&joined) <= max {
                        c.text = joined;
                        cur = Some(c);
                    } else {
                        push(&mut out, c);
                        cur = Some(ChunkDraft {
                            index: 0,
                            heading_path: block.heading_path.clone(),
                            text: piece,
                            tokens: 0,
                        });
                    }
                }
                prev => {
                    if let Some(c) = prev {
                        push(&mut out, c);
                    }
                    cur =
                        Some(ChunkDraft { index: 0, heading_path: block.heading_path.clone(), text: piece, tokens: 0 });
                }
            }
        }
    }
    if let Some(c) = cur {
        push(&mut out, c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{ContentType, parse};

    #[test]
    fn chunks_stay_inside_their_section_without_overlap() {
        let md = "# Guide\n\n## A\n\nalpha one.\n\nalpha two.\n\n## B\n\nbeta.";
        let c = chunk(&parse(ContentType::Markdown, md), 384);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].heading_path, vec!["Guide", "A"]);
        assert_eq!(c[0].text, "alpha one.\n\nalpha two.");
        assert_eq!((c[1].index, c[1].text.as_str()), (1, "beta."));
        assert_eq!(c[0].indexed_text(Some("Guide")), "Guide > A\n\nalpha one.\n\nalpha two.");
        assert_eq!(c[1].indexed_text(Some("Manual")), "Manual > Guide > B\n\nbeta.");
    }

    #[test]
    fn large_sections_split_at_sentences_then_words() {
        let sentence = "The quick brown fox jumps over the lazy dog near the river bank today. ";
        let md = format!("# T\n\n{}", sentence.repeat(60));
        let c = chunk(&parse(ContentType::Markdown, &md), 64);
        assert!(c.len() > 5, "{}", c.len());
        assert!(c.iter().all(|c| c.tokens <= 64), "{:?}", c.iter().map(|c| c.tokens).collect::<Vec<_>>());
        assert!(c.iter().all(|c| c.text.ends_with('.')), "split at sentence boundaries");
        // Nothing lost, nothing duplicated (no overlap).
        let words: usize = c.iter().map(|c| c.text.split_whitespace().count()).sum();
        assert_eq!(words, sentence.split_whitespace().count() * 60);
        let one_long = "word ".repeat(400);
        let w = chunk(&parse(ContentType::Text, &one_long), 64);
        assert!(w.len() >= 6 && w.iter().all(|c| c.tokens <= 64));
    }

    #[test]
    fn code_splits_on_lines() {
        let code = (0..200).map(|i| format!("let value_{i} = compute({i});")).collect::<Vec<_>>().join("\n");
        let md = format!("# Code\n\n```rust\n{code}\n```\n");
        let c = chunk(&parse(ContentType::Markdown, &md), 128);
        assert!(c.len() > 3);
        assert!(c.iter().all(|c| c.text.lines().all(|l| l.starts_with("let value_"))));
    }
}
