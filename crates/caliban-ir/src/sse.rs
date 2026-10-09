//! Minimal incremental SSE parser for upstream streams (OpenAI chunks and Anthropic events).

/// Position of the next `\n\n` at or after `from`. memchr for the `\n`s, instead of a
/// substring searcher set up per call.
fn find_blank_line(b: &[u8], mut from: usize) -> Option<usize> {
    while let Some(i) = memchr::memchr(b'\n', b.get(from..)?) {
        let at = from + i;
        if b.get(at + 1) == Some(&b'\n') {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

/// Accumulates bytes and yields complete `data:` payloads.
#[derive(Default)]
pub struct SseParser {
    buf: String,
    /// Bytes of an incomplete UTF-8 sequence split across reads.
    partial: Vec<u8>,
    /// Offset in `buf` before which no event boundary can start (already searched).
    searched: usize,
    /// Reused for events whose data spans several lines.
    scratch: String,
}

impl SseParser {
    /// Feeds bytes; returns the `data` payload of every complete event (multi-line data joined
    /// with `\n`). Comments and other fields (`event:`, `id:`) are ignored: both OpenAI and
    /// Anthropic put everything needed in `data`.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        self.push_each(bytes, |d| out.push(d.to_owned()));
        out
    }

    /// Like [`Self::push`], but calls `f` with each payload, borrowed from the parser's buffer
    /// instead of allocated: a single-line `data:` event is not copied at all.
    pub fn push_each(&mut self, bytes: &[u8], mut f: impl FnMut(&str)) {
        let appended_at = self.buf.len();
        self.append(bytes);
        // From one byte back: a `\r` that ended the previous read may pair with a `\n` now.
        if self.buf.as_bytes()[appended_at.saturating_sub(1)..].contains(&b'\r') {
            self.buf = self.buf.replace("\r\n", "\n");
            self.searched = 0;
        }
        // Scan with an offset and drop consumed bytes once: draining each event from the front
        // would move the rest of the buffer per event (quadratic when one read carries many).
        let mut start = 0;
        let mut from = self.searched;
        while let Some(end) = find_blank_line(self.buf.as_bytes(), from) {
            let block = &self.buf[start..end];
            match block.strip_prefix("data:") {
                // The common case: one `data:` line, no other fields.
                Some(d) if !d.contains('\n') => f(d.strip_prefix(' ').unwrap_or(d)),
                _ => {
                    self.scratch.clear();
                    let mut any = false;
                    for d in block.lines().filter_map(|l| l.strip_prefix("data:")) {
                        if any {
                            self.scratch.push('\n');
                        }
                        self.scratch.push_str(d.strip_prefix(' ').unwrap_or(d));
                        any = true;
                    }
                    if any {
                        f(&self.scratch);
                    }
                }
            }
            start = end + 2;
            from = start;
        }
        self.buf.drain(..start);
        // A boundary may straddle the next read: rescan the last character.
        let mut last = self.buf.len().saturating_sub(1);
        while !self.buf.is_char_boundary(last) {
            last -= 1;
        }
        self.searched = last;
    }

    /// Appends the valid UTF-8 prefix of `partial + bytes` to `buf`, keeping an incomplete
    /// trailing sequence for the next read. Invalid bytes become U+FFFD.
    fn append(&mut self, bytes: &[u8]) {
        if self.partial.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(s) => return self.buf.push_str(s),
                Err(e) if e.error_len().is_none() => {
                    let (valid, rest) = bytes.split_at(e.valid_up_to());
                    self.buf.push_str(std::str::from_utf8(valid).unwrap_or_default());
                    self.partial.extend_from_slice(rest);
                    return;
                }
                Err(_) => {}
            }
        }
        self.partial.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.partial) {
            Ok(_) => self.partial.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => self.partial.len(),
        };
        let chunk: Vec<u8> = self.partial.drain(..valid).collect();
        self.buf.push_str(&String::from_utf8_lossy(&chunk));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_split_events_crlf_and_comments() {
        let mut p = SseParser::default();
        assert!(p.push(b"data: {\"a\"").is_empty());
        assert_eq!(p.push(b":1}\r\n\r\n: keepalive\n\ndata: [DONE]\n\n"), vec!["{\"a\":1}", "[DONE]"]);
    }

    #[test]
    fn many_events_in_one_read_keep_the_partial_tail() {
        let mut p = SseParser::default();
        let mut bytes: String = (0..100).map(|i| format!("data: {{\"i\":{i}}}\n\n")).collect();
        bytes.push_str("data: {\"i\":");
        let out = p.push(bytes.as_bytes());
        assert_eq!(out.len(), 100);
        assert_eq!(out[99], "{\"i\":99}");
        assert_eq!(p.push(b"100}\n\n"), vec!["{\"i\":100}"]);
    }

    #[test]
    fn push_each_matches_push_for_any_split() {
        let input =
            "data: {\"a\":\"é\"}\n\nevent: x\ndata: l1\ndata:l2\nid: 3\n\n: comment\n\ndata:\n\ndata: [DONE]\r\n\r\n";
        let whole = SseParser::default().push(input.as_bytes());
        assert_eq!(whole, vec!["{\"a\":\"é\"}", "l1\nl2", "", "[DONE]"]);
        let bytes = input.as_bytes();
        for cut in 1..bytes.len() {
            let mut p = SseParser::default();
            let mut got = Vec::new();
            p.push_each(&bytes[..cut], |d| got.push(d.to_owned()));
            p.push_each(&bytes[cut..], |d| got.push(d.to_owned()));
            assert_eq!(got, whole, "split at {cut}");
        }
        // One byte at a time.
        let mut p = SseParser::default();
        let mut got = Vec::new();
        for b in bytes {
            p.push_each(std::slice::from_ref(b), |d| got.push(d.to_owned()));
        }
        assert_eq!(got, whole);
    }

    #[test]
    fn named_events_and_split_utf8() {
        let mut p = SseParser::default();
        let bytes = "event: content_block_delta\ndata: {\"t\":\"é\"}\n\n".as_bytes();
        let cut = bytes.iter().position(|&b| b == 0xC3).unwrap() + 1;
        assert!(p.push(&bytes[..cut]).is_empty());
        assert_eq!(p.push(&bytes[cut..]), vec!["{\"t\":\"é\"}"]);
    }
}
