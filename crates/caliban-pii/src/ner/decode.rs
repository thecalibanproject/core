//! Model-free decoding for token-classification NER: label parsing, sliding-window planning,
//! overlap stitching, word aggregation, BIO/IOB2/BIOES decoding, and byte spans in the
//! original `&str`. Everything here is pure and unit-tested without a model.
//!
//! Data flow for one text (see `NerDetector::try_detect`):
//! 1. tokenize once (byte offsets), split the body tokens into windows ([`plan_windows`]);
//! 2. run each window, softmax its logits, feed them to a [`Stitcher`], which keeps for every
//!    token the prediction from the window where that token is most central (so tokens near a
//!    cut get full context and nothing is decoded twice);
//! 3. group tokens into units ([`units`], per token or per word), decode tags ([`decode`]);
//! 4. map to byte spans, snapped to char boundaries and trimmed ([`finalize`]).

use std::ops::Range;

/// Tag prefix. IOB2 (`B-`/`I-`), IOB1 (an `I-` may start an entity), BIOES/BILOU (`E-`/`L-`
/// end, `S-`/`U-` single) and plain IO labels (no prefix) are all accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prefix {
    Outside,
    Begin,
    Inside,
    End,
    Single,
}

/// The model's label space: per class id, its prefix and entity base (`"PER"`, `"GIVEN_NAME"`).
#[derive(Debug, Clone)]
pub struct LabelSet {
    tags: Vec<(Prefix, Option<usize>)>,
    bases: Vec<String>,
}

impl LabelSet {
    pub fn parse<S: AsRef<str>>(labels: &[S]) -> Self {
        let mut bases: Vec<String> = Vec::new();
        let mut tags = Vec::with_capacity(labels.len());
        for l in labels {
            let l = l.as_ref().trim();
            let (prefix, base) = split_label(l);
            let idx = base.map(|b| match bases.iter().position(|x| x == b) {
                Some(i) => i,
                None => {
                    bases.push(b.to_owned());
                    bases.len() - 1
                }
            });
            tags.push((if idx.is_none() { Prefix::Outside } else { prefix }, idx));
        }
        Self { tags, bases }
    }

    pub fn num_classes(&self) -> usize {
        self.tags.len()
    }

    /// Distinct entity bases, indexed by the `base` of [`RawEntity`].
    pub fn bases(&self) -> &[String] {
        &self.bases
    }

    pub fn tag(&self, class: usize) -> (Prefix, Option<usize>) {
        self.tags.get(class).copied().unwrap_or((Prefix::Outside, None))
    }
}

fn split_label(l: &str) -> (Prefix, Option<&str>) {
    if l.is_empty() || l.eq_ignore_ascii_case("O") {
        return (Prefix::Outside, None);
    }
    let b = l.as_bytes();
    if b.len() > 2 && (b[1] == b'-' || b[1] == b'_') {
        let p = match b[0].to_ascii_uppercase() {
            b'B' => Some(Prefix::Begin),
            b'I' => Some(Prefix::Inside),
            b'E' | b'L' => Some(Prefix::End),
            b'S' | b'U' => Some(Prefix::Single),
            _ => None,
        };
        if let Some(p) = p {
            return (p, Some(&l[2..]));
        }
    }
    // IO scheme: a bare entity name means "inside".
    (Prefix::Inside, Some(l))
}

/// Windows of at most `window` tokens over `n` tokens, consecutive windows sharing `overlap`
/// tokens. `overlap` is clamped to `window / 2` so the walk always advances.
pub fn plan_windows(n: usize, window: usize, overlap: usize) -> Vec<Range<usize>> {
    let window = window.max(1);
    let overlap = overlap.min(window / 2);
    let step = window - overlap;
    let mut out = Vec::new();
    let mut start = 0;
    while start < n {
        let end = (start + window).min(n);
        out.push(start..end);
        if end == n {
            break;
        }
        start += step;
    }
    out
}

/// In-place softmax over one token's logits.
pub fn softmax(v: &mut [f32]) {
    let max = v.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0;
    for x in v.iter_mut() {
        *x = (*x - max).exp();
        sum += *x;
    }
    if sum > 0.0 {
        for x in v.iter_mut() {
            *x /= sum;
        }
    }
}

/// Merges per-window probabilities into one row per token. For a token covered by several
/// windows, the window where it is most central wins (distance to the nearest *cut*; the real
/// start/end of the text is not a cut). Ties keep the earlier window. This is what removes
/// duplicate entities in the overlaps: every token is decoded exactly once.
pub struct Stitcher {
    n: usize,
    classes: usize,
    probs: Vec<f32>,
    centrality: Vec<i64>,
}

impl Stitcher {
    pub fn new(n_tokens: usize, classes: usize) -> Self {
        Self { n: n_tokens, classes, probs: vec![0.0; n_tokens * classes], centrality: vec![-1; n_tokens] }
    }

    /// `probs` holds `window.len() * classes` probabilities (row-major, one row per token).
    pub fn add(&mut self, window: Range<usize>, probs: &[f32]) {
        debug_assert_eq!(probs.len(), window.len() * self.classes);
        let (start, end) = (window.start, window.end);
        for (k, i) in window.enumerate() {
            let left = if start == 0 { i64::MAX } else { (i - start) as i64 };
            let right = if end == self.n { i64::MAX } else { (end - 1 - i) as i64 };
            let c = left.min(right);
            if c > self.centrality[i] {
                self.centrality[i] = c;
                let row = &probs[k * self.classes..(k + 1) * self.classes];
                self.probs[i * self.classes..(i + 1) * self.classes].copy_from_slice(row);
            }
        }
    }

    /// Row-major `[n_tokens * classes]` probabilities.
    pub fn finish(self) -> Vec<f32> {
        self.probs
    }
}

/// How sub-word tokens are grouped before decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregation {
    /// Every token is decoded on its own (right for models trained with a label on every token).
    Token,
    /// A word takes the prediction of its first token (models trained first-sub-word-only).
    First,
    /// A word takes the argmax of its tokens' averaged probabilities.
    Average,
    /// A word takes the prediction of its most confident token.
    Max,
}

/// A decoding unit: one token, or one word under word aggregation.
#[derive(Debug, Clone, PartialEq)]
pub struct Unit {
    /// Byte range in the original text.
    pub start: usize,
    pub end: usize,
    pub class: usize,
    pub score: f32,
}

fn argmax(row: &[f32]) -> (usize, f32) {
    row.iter().copied().enumerate().fold((0, f32::NEG_INFINITY), |b, (i, p)| if p > b.1 { (i, p) } else { b })
}

/// Groups token probabilities (`[offsets.len() * classes]`) into units. Tokens with an empty
/// offset range (e.g. a bare `▁` or special token) are dropped. Word ids come from the
/// tokenizer's pre-tokenizer; tokens without one form their own unit.
pub fn units(
    probs: &[f32],
    classes: usize,
    offsets: &[(usize, usize)],
    word_ids: &[Option<u32>],
    agg: Aggregation,
) -> Vec<Unit> {
    let n = offsets.len();
    let row = |i: usize| &probs[i * classes..(i + 1) * classes];
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        if agg != Aggregation::Token
            && let Some(w) = word_ids.get(i).copied().flatten()
        {
            while j < n && word_ids.get(j).copied().flatten() == Some(w) {
                j += 1;
            }
        }
        let toks: Vec<usize> = (i..j).filter(|&t| offsets[t].1 > offsets[t].0).collect();
        i = j;
        let (Some(&first), Some(&last)) = (toks.first(), toks.last()) else {
            continue;
        };
        let (class, score) = match agg {
            Aggregation::Token | Aggregation::First => argmax(row(first)),
            Aggregation::Max => {
                toks.iter().map(|&t| argmax(row(t))).fold((0, f32::NEG_INFINITY), |b, x| if x.1 > b.1 { x } else { b })
            }
            Aggregation::Average => {
                let mut avg = vec![0.0f32; classes];
                for &t in &toks {
                    for (a, p) in avg.iter_mut().zip(row(t)) {
                        *a += p;
                    }
                }
                let k = toks.len() as f32;
                avg.iter_mut().for_each(|a| *a /= k);
                argmax(&avg)
            }
        };
        out.push(Unit { start: offsets[first].0, end: offsets[last].1, class, score });
    }
    out
}

/// A decoded entity before label mapping and thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct RawEntity {
    /// Index into [`LabelSet::bases`].
    pub base: usize,
    pub start: usize,
    pub end: usize,
    /// Mean probability of the units' predicted tags.
    pub score: f32,
}

/// Tag decoding. `B`/`S` always open an entity; `I`/`E` continue an open entity of the same base
/// and otherwise open one (IOB1-tolerant: a model that skips the `B` still yields the entity);
/// `E`/`S` close it; `O` closes it.
pub fn decode(units: &[Unit], labels: &LabelSet) -> Vec<RawEntity> {
    struct Open {
        base: usize,
        start: usize,
        end: usize,
        sum: f32,
        n: u32,
    }
    let close = |o: Open| RawEntity { base: o.base, start: o.start, end: o.end, score: o.sum / o.n as f32 };
    let mut out = Vec::new();
    let mut cur: Option<Open> = None;
    for u in units {
        let (prefix, base) = labels.tag(u.class);
        let Some(base) = base else {
            out.extend(cur.take().map(close));
            continue;
        };
        let continues = matches!(prefix, Prefix::Inside | Prefix::End) && cur.as_ref().is_some_and(|c| c.base == base);
        if continues {
            let c = cur.as_mut().expect("checked");
            c.end = u.end;
            c.sum += u.score;
            c.n += 1;
        } else {
            out.extend(cur.take().map(close));
            cur = Some(Open { base, start: u.start, end: u.end, sum: u.score, n: 1 });
        }
        if matches!(prefix, Prefix::End | Prefix::Single) {
            out.extend(cur.take().map(close));
        }
    }
    out.extend(cur.take().map(close));
    out
}

const TRIM: &[char] =
    &[',', ';', ':', '!', '?', '.', '"', '\'', '«', '»', '“', '”', '‘', '’', '„', '、', '。', '，', '：', '；'];

/// Byte index of the bracket closing the one that opens `span`, if any.
fn matching_close(span: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in span.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

fn trim_edges(text: &str, mut s: usize, mut e: usize) -> (usize, usize) {
    loop {
        let span = &text[s..e];
        let Some(first) = span.chars().next() else { break };
        if first.is_whitespace() || TRIM.contains(&first) {
            s += first.len_utf8();
            continue;
        }
        if matches!(first, '(' | '[' | '{') {
            match matching_close(span) {
                // "(Acme Ltd)" → "Acme Ltd"
                Some(i) if i + 1 == span.len() && span.len() > 2 => {
                    s += 1;
                    e -= 1;
                    continue;
                }
                // unbalanced "(Acme"
                None => {
                    s += 1;
                    continue;
                }
                Some(_) => {}
            }
        }
        let last = span.chars().next_back().expect("non-empty");
        if last.is_whitespace() || TRIM.contains(&last) {
            e -= last.len_utf8();
            continue;
        }
        if matches!(last, ')' | ']' | '}') {
            let opens = span.chars().filter(|c| matches!(c, '(' | '[' | '{')).count();
            let closes = span.chars().filter(|c| matches!(c, ')' | ']' | '}')).count();
            if closes > opens {
                e -= 1;
                continue;
            }
        }
        break;
    }
    (s, e)
}

/// Clamps entity offsets to `text`, snaps them outward to UTF-8 char boundaries (byte-fallback
/// tokens can point inside a multi-byte char), trims surrounding whitespace and punctuation,
/// and drops entities that end up empty.
pub fn finalize(text: &str, entities: Vec<RawEntity>) -> Vec<RawEntity> {
    entities
        .into_iter()
        .filter_map(|mut ent| {
            let mut s = ent.start.min(text.len());
            let mut e = ent.end.min(text.len());
            while s > 0 && !text.is_char_boundary(s) {
                s -= 1;
            }
            while e < text.len() && !text.is_char_boundary(e) {
                e += 1;
            }
            if s >= e {
                return None;
            }
            (ent.start, ent.end) = trim_edges(text, s, e);
            (ent.start < ent.end).then_some(ent)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ls(labels: &[&str]) -> LabelSet {
        LabelSet::parse(labels)
    }

    /// One-hot unit for class `c` covering bytes `s..e`.
    fn u(s: usize, e: usize, c: usize) -> Unit {
        Unit { start: s, end: e, class: c, score: 0.9 }
    }

    const CONLL: &[&str] = &["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC", "B-MISC", "I-MISC"];

    #[test]
    fn parses_bio_bioes_and_io_labels() {
        let l = ls(&["O", "B-PER", "I-PER", "E-PER", "S-LOC", "U-LOC", "L-PER", "ORG", "B_CITY"]);
        assert_eq!(l.bases(), &["PER", "LOC", "ORG", "CITY"]);
        assert_eq!(l.tag(0), (Prefix::Outside, None));
        assert_eq!(l.tag(1), (Prefix::Begin, Some(0)));
        assert_eq!(l.tag(3), (Prefix::End, Some(0)));
        assert_eq!(l.tag(5), (Prefix::Single, Some(1)));
        assert_eq!(l.tag(6), (Prefix::End, Some(0)));
        assert_eq!(l.tag(7), (Prefix::Inside, Some(2)));
        assert_eq!(l.tag(8), (Prefix::Begin, Some(3)));
        assert_eq!(l.tag(99), (Prefix::Outside, None));
    }

    #[test]
    fn iob2_decoding() {
        // "John Smith works at Acme Corp in Paris"
        let l = ls(CONLL);
        let units = [
            u(0, 4, 1),
            u(5, 10, 2),
            u(11, 16, 0),
            u(17, 19, 0),
            u(20, 24, 3),
            u(25, 29, 4),
            u(30, 32, 0),
            u(33, 38, 5),
        ];
        let e = decode(&units, &l);
        let got: Vec<_> = e.iter().map(|e| (l.bases()[e.base].as_str(), e.start, e.end)).collect();
        assert_eq!(got, vec![("PER", 0, 10), ("ORG", 20, 29), ("LOC", 33, 38)]);
    }

    #[test]
    fn adjacent_b_tags_split_and_stray_i_starts_entity() {
        let l = ls(CONLL);
        // B-PER B-PER → two entities; O I-LOC I-LOC → one entity (IOB1 tolerance);
        // B-PER I-ORG → type change splits.
        let units = [u(0, 3, 1), u(4, 7, 1), u(8, 9, 0), u(10, 13, 6), u(14, 17, 6), u(18, 21, 1), u(22, 25, 4)];
        let got: Vec<_> = decode(&units, &l).iter().map(|e| (l.bases()[e.base].clone(), e.start, e.end)).collect();
        assert_eq!(
            got,
            vec![
                ("PER".into(), 0, 3),
                ("PER".into(), 4, 7),
                ("LOC".into(), 10, 17),
                ("PER".into(), 18, 21),
                ("ORG".into(), 22, 25)
            ]
        );
    }

    #[test]
    fn bioes_decoding() {
        let l = ls(&["O", "B-X", "I-X", "E-X", "S-X"]);
        let units = [u(0, 1, 1), u(2, 3, 2), u(4, 5, 3), u(6, 7, 3), u(8, 9, 4), u(10, 11, 4)];
        let got: Vec<_> = decode(&units, &l).iter().map(|e| (e.start, e.end)).collect();
        // E after a closed entity starts (and ends) a new one; S is always a single entity.
        assert_eq!(got, vec![(0, 5), (6, 7), (8, 9), (10, 11)]);
    }

    #[test]
    fn score_is_mean_of_unit_scores() {
        let l = ls(CONLL);
        let units = [Unit { start: 0, end: 1, class: 1, score: 0.6 }, Unit { start: 2, end: 3, class: 2, score: 1.0 }];
        let e = decode(&units, &l);
        assert!((e[0].score - 0.8).abs() < 1e-6);
    }

    #[test]
    fn windows_cover_everything_with_overlap() {
        assert!(plan_windows(0, 10, 2).is_empty());
        assert_eq!(plan_windows(5, 10, 2), vec![0..5]);
        assert_eq!(plan_windows(10, 4, 1), vec![0..4, 3..7, 6..10]);
        // Overlap clamped to window/2 so the walk always advances.
        assert_eq!(plan_windows(6, 2, 5), vec![0..2, 1..3, 2..4, 3..5, 4..6]);
        for (n, w, o) in [(1000, 510, 128), (511, 510, 128), (2048, 126, 64)] {
            let ws = plan_windows(n, w, o);
            assert_eq!(ws[0].start, 0);
            assert_eq!(ws.last().unwrap().end, n);
            for p in ws.windows(2) {
                assert!(p[1].start < p[0].end, "consecutive windows overlap");
                assert!(p[1].start > p[0].start);
            }
            assert!(ws.iter().all(|r| r.len() <= w));
        }
    }

    fn onehot(classes: usize, c: usize) -> Vec<f32> {
        let mut v = vec![0.0; classes];
        v[c] = 1.0;
        v
    }

    #[test]
    fn stitching_prefers_central_window_and_decodes_overlap_once() {
        // 10 tokens, windows 0..6 and 4..10 (overlap 4..6). Window A sees token 5 at its right
        // cut and calls it O; window B sees it in context and calls it B-PER. Token 4 is
        // equally central in both (tie → A).
        let classes = 3; // O, B-PER, I-PER
        let n = 10;
        let mut st = Stitcher::new(n, classes);
        let a: Vec<f32> = (0..6).flat_map(|i| onehot(classes, if i == 4 { 1 } else { 0 })).collect();
        let b: Vec<f32> = (4..10)
            .flat_map(|i| {
                onehot(
                    classes,
                    if i == 6 {
                        2
                    } else if i == 5 {
                        1
                    } else {
                        0
                    },
                )
            })
            .collect();
        st.add(0..6, &a);
        st.add(4..10, &b);
        let probs = st.finish();
        let cls: Vec<usize> = (0..n).map(|i| argmax(&probs[i * classes..(i + 1) * classes]).0).collect();
        // token 4: centrality A = min(∞, 1) = 1, B = min(0, 5) = 0 → A (B-PER).
        // token 5: A = min(∞, 0) = 0, B = min(1, 4) = 1 → B (B-PER).
        assert_eq!(cls, vec![0, 0, 0, 0, 1, 1, 2, 0, 0, 0]);
        let offsets: Vec<(usize, usize)> = (0..n).map(|i| (i * 2, i * 2 + 1)).collect();
        let l = ls(&["O", "B-PER", "I-PER"]);
        let ents = decode(&units(&probs, classes, &offsets, &[], Aggregation::Token), &l);
        // Two entities, each exactly once, no duplicate from the overlap.
        assert_eq!(ents.iter().map(|e| (e.start, e.end)).collect::<Vec<_>>(), vec![(8, 9), (10, 13)]);
    }

    #[test]
    fn same_entity_seen_by_two_windows_is_emitted_once() {
        let classes = 3;
        let n = 8;
        let mut st = Stitcher::new(n, classes);
        // Both windows agree that tokens 3..5 are one PER entity.
        let lab = |i: usize| {
            if i == 3 {
                1
            } else if i == 4 {
                2
            } else {
                0
            }
        };
        st.add(0..6, &(0..6).flat_map(|i| onehot(classes, lab(i))).collect::<Vec<_>>());
        st.add(2..8, &(2..8).flat_map(|i| onehot(classes, lab(i))).collect::<Vec<_>>());
        let probs = st.finish();
        let offsets: Vec<(usize, usize)> = (0..n).map(|i| (i, i + 1)).collect();
        let ents = decode(&units(&probs, classes, &offsets, &[], Aggregation::Token), &ls(&["O", "B-PER", "I-PER"]));
        assert_eq!(ents.len(), 1);
        assert_eq!((ents[0].start, ents[0].end), (3, 5));
    }

    #[test]
    fn word_aggregation() {
        let classes = 3; // O, B-PER, I-PER
        // "Johnson" = [Jo, ##hn, ##son] (word 0), "x" (word 1)
        let probs: Vec<f32> =
            [vec![0.2, 0.7, 0.1], vec![0.6, 0.1, 0.3], vec![0.6, 0.1, 0.3], vec![0.9, 0.05, 0.05]].concat();
        let offsets = [(0, 2), (2, 4), (4, 7), (8, 9)];
        let words = [Some(0), Some(0), Some(0), Some(1)];
        let first = units(&probs, classes, &offsets, &words, Aggregation::First);
        assert_eq!(
            first,
            vec![Unit { start: 0, end: 7, class: 1, score: 0.7 }, Unit { start: 8, end: 9, class: 0, score: 0.9 }]
        );
        let avg = units(&probs, classes, &offsets, &words, Aggregation::Average);
        assert_eq!(avg[0].class, 0, "average: O dominates");
        let max = units(&probs, classes, &offsets, &words, Aggregation::Max);
        assert_eq!(max[0].class, 1);
        let tok = units(&probs, classes, &offsets, &words, Aggregation::Token);
        assert_eq!(tok.len(), 4);
        // Empty-offset tokens are dropped.
        let none = units(&probs[..3], classes, &[(5, 5)], &[None], Aggregation::Token);
        assert!(none.is_empty());
    }

    #[test]
    fn byte_offsets_with_multibyte_text() {
        // "Ünal Çelik ✈ visited São Paulo, 東京." — offsets are bytes.
        let text = "Ünal Çelik ✈ visited São Paulo, 東京.";
        let ent = |s: &str| {
            let start = text.find(s).unwrap();
            RawEntity { base: 0, start, end: start + s.len(), score: 1.0 }
        };
        let out = finalize(text, vec![ent("Ünal Çelik"), ent("São Paulo,"), ent("東京.")]);
        let got: Vec<&str> = out.iter().map(|e| &text[e.start..e.end]).collect();
        assert_eq!(got, vec!["Ünal Çelik", "São Paulo", "東京"]);

        // Offsets that land inside a multi-byte char (byte-fallback tokens) snap outward.
        let s = text.find("東").unwrap();
        let out = finalize(text, vec![RawEntity { base: 0, start: s + 1, end: s + 4, score: 1.0 }]);
        assert_eq!(&text[out[0].start..out[0].end], "東京");
        // Out of range offsets are clamped; whitespace-only entities vanish.
        let sp = text.find(" visited").unwrap();
        let out = finalize(
            text,
            vec![
                RawEntity { base: 0, start: sp, end: sp + 1, score: 1.0 },
                RawEntity { base: 0, start: 30, end: 999, score: 1.0 },
            ],
        );
        assert_eq!(out.len(), 1);
        assert!(text.is_char_boundary(out[0].start) && text.is_char_boundary(out[0].end));
    }

    #[test]
    fn trimming_keeps_balanced_brackets() {
        let text = " (Acme (UK) Ltd), \"Bob\" (415) 555-2671 Smith)";
        let mk = |a: &str| {
            let s = text.find(a).unwrap();
            RawEntity { base: 0, start: s, end: s + a.len(), score: 1.0 }
        };
        let out = finalize(text, vec![mk(" (Acme (UK) Ltd),"), mk("\"Bob\" "), mk("(415) 555-2671"), mk("Smith)")]);
        let got: Vec<&str> = out.iter().map(|e| &text[e.start..e.end]).collect();
        assert_eq!(got, vec!["Acme (UK) Ltd", "Bob", "(415) 555-2671", "Smith"]);
    }

    #[test]
    fn softmax_normalizes() {
        let mut v = [1.0, 2.0, 3.0];
        softmax(&mut v);
        assert!((v.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!(v[2] > v[1] && v[1] > v[0]);
    }
}
