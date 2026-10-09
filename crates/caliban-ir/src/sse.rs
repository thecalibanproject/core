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
        while let Some(pos) = self.buf.find("\n\n") {
            let event: String = self.buf.drain(..pos + 2).collect();
            let data: Vec<&str> = event
                .lines()
                .filter_map(|l| l.strip_prefix("data:"))
                .map(|d| d.strip_prefix(' ').unwrap_or(d))
                .collect();
            if !data.is_empty() {
                out.push(data.join("\n"));
            }
        }
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
    fn named_events_and_split_utf8() {
        let mut p = SseParser::default();
        let bytes = "event: content_block_delta\ndata: {\"t\":\"é\"}\n\n".as_bytes();
        let cut = bytes.iter().position(|&b| b == 0xC3).unwrap() + 1;
        assert!(p.push(&bytes[..cut]).is_empty());
        assert_eq!(p.push(&bytes[cut..]), vec!["{\"t\":\"é\"}"]);
    }
}
