//! Minimal incremental SSE parser for upstream streams (OpenAI chunks and Anthropic events).

/// Accumulates bytes and yields complete `data:` payloads.
#[derive(Default)]
pub struct SseParser {
    buf: String,
    /// Bytes of an incomplete UTF-8 sequence split across reads.
    partial: Vec<u8>,
}

impl SseParser {
    /// Feeds bytes; returns the `data` payload of every complete event (multi-line data joined
    /// with `\n`). Comments and other fields (`event:`, `id:`) are ignored: both OpenAI and
    /// Anthropic put everything needed in `data`.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        self.partial.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.partial) {
            Ok(_) => self.partial.len(),
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            Err(_) => self.partial.len(),
        };
        let chunk: Vec<u8> = self.partial.drain(..valid).collect();
        self.buf.push_str(&String::from_utf8_lossy(&chunk));
        if self.buf.contains('\r') {
            self.buf = self.buf.replace("\r\n", "\n");
        }
        let mut out = Vec::new();
        // Scan with an offset and drop consumed bytes once: draining each event from the front
        // would move the rest of the buffer per event (quadratic when one read carries many).
        let mut start = 0;
        while let Some(rel) = self.buf[start..].find("\n\n") {
            let end = start + rel;
            let data: Vec<&str> = self.buf[start..end]
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|d| d.strip_prefix(' ').unwrap_or(d))
                .collect();
            if !data.is_empty() {
                out.push(data.join("\n"));
            }
            start = end + 2;
        }
        self.buf.drain(..start);
        out
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
    fn named_events_and_split_utf8() {
        let mut p = SseParser::default();
        let bytes = "event: content_block_delta\ndata: {\"t\":\"é\"}\n\n".as_bytes();
        let cut = bytes.iter().position(|&b| b == 0xC3).unwrap() + 1;
        assert!(p.push(&bytes[..cut]).is_empty());
        assert_eq!(p.push(&bytes[cut..]), vec!["{\"t\":\"é\"}"]);
    }
}
