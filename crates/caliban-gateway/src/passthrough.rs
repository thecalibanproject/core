//! Byte-level passthrough for streamed chunks that need no rewriting beyond the model name.
//!
//! The general stream path parses every chunk into a `serde_json::Value`, edits it and
//! serialises it again. When nothing in a chunk's text has to change (no surrogate restoring, no
//! `<think>` splitting, no semantic-cache capture), that is wasted work: the chunk can go out as
//! the upstream sent it, with only the `model` value replaced. These scanners run serde_json over
//! the chunk once, without building a tree or allocating, to find:
//!
//! - the byte range of the top-level `model` value, replaced in place by the gateway's model id
//!   (a JSON string literal produced by serde_json, so escaping is always correct);
//! - whether the chunk carries `usage` (such chunks take the general path, so usage extraction
//!   is shared with it);
//! - the output text bytes (`delta.content`, reasoning, tool arguments) for usage estimates.
//!
//! Anything unexpected (not a JSON object, duplicate keys, unusual types, line breaks that would
//! break SSE framing) returns `None`, and the caller uses the general path for that chunk.
//! Both paths produce the same JSON value; the passthrough keeps the upstream's key order and
//! number formatting, while the general path re-serialises (keys sorted, strings re-escaped).

use bytes::BytesMut;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::fmt;
use std::ops::Range;

/// Unescaped length in bytes of a JSON string; 0 for any other value (like `Value::as_str`
/// returning `None`).
#[derive(Default, Clone, Copy)]
struct StrLen(u64);

impl<'de> Deserialize<'de> for StrLen {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = StrLen;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E>(self, s: &str) -> Result<StrLen, E> {
                Ok(StrLen(s.len() as u64))
            }
            fn visit_bool<E>(self, _: bool) -> Result<StrLen, E> {
                Ok(StrLen(0))
            }
            fn visit_i64<E>(self, _: i64) -> Result<StrLen, E> {
                Ok(StrLen(0))
            }
            fn visit_u64<E>(self, _: u64) -> Result<StrLen, E> {
                Ok(StrLen(0))
            }
            fn visit_f64<E>(self, _: f64) -> Result<StrLen, E> {
                Ok(StrLen(0))
            }
            fn visit_unit<E>(self) -> Result<StrLen, E> {
                Ok(StrLen(0))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<StrLen, A::Error> {
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(StrLen(0))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<StrLen, A::Error> {
                while a.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(StrLen(0))
            }
        }
        d.deserialize_any(V)
    }
}

/// Sum over an array's elements of `T`'s byte count; 0 for `null`. Other values fail (the caller
/// falls back to the general path).
struct SumSeq<T>(u64, std::marker::PhantomData<T>);

impl<T> Default for SumSeq<T> {
    fn default() -> Self {
        Self(0, std::marker::PhantomData)
    }
}

trait Bytes {
    fn bytes(&self) -> u64;
}

impl<'de, T: Deserialize<'de> + Bytes> Deserialize<'de> for SumSeq<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de> + Bytes> Visitor<'de> for V<T> {
            type Value = SumSeq<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array or null")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(SumSeq::default())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut n = 0;
                while let Some(t) = a.next_element::<T>()? {
                    n += t.bytes();
                }
                Ok(SumSeq(n, std::marker::PhantomData))
            }
        }
        d.deserialize_any(V(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
struct FunctionView {
    #[serde(default)]
    arguments: StrLen,
}

#[derive(Deserialize)]
struct ToolCallView {
    #[serde(default)]
    function: Option<FunctionView>,
}

impl Bytes for ToolCallView {
    fn bytes(&self) -> u64 {
        self.function.as_ref().map_or(0, |f| f.arguments.0)
    }
}

#[derive(Deserialize)]
struct DeltaView {
    #[serde(default)]
    content: StrLen,
    #[serde(default)]
    reasoning_content: StrLen,
    #[serde(default)]
    reasoning: StrLen,
    #[serde(default)]
    tool_calls: SumSeq<ToolCallView>,
}

#[derive(Deserialize)]
struct ChoiceView {
    #[serde(default)]
    delta: Option<DeltaView>,
}

impl Bytes for ChoiceView {
    fn bytes(&self) -> u64 {
        self.delta.as_ref().map_or(0, |d| d.content.0 + d.reasoning_content.0 + d.reasoning.0 + d.tool_calls.0)
    }
}

/// `Some(raw)` for any present value, `null` included (`Option<&RawValue>` would map `null` to
/// `None`, but a `"model": null` is still a key the general path rewrites).
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(d).map(Some)
}

#[derive(Deserialize)]
struct ChunkView<'a> {
    #[serde(default, borrow, deserialize_with = "present")]
    model: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    usage: Option<&'a RawValue>,
    #[serde(default)]
    choices: SumSeq<ChoiceView>,
}

/// What the passthrough needs from one OpenAI chunk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OpenAiChunk<'a> {
    /// Byte range of the top-level `model` value (the whole literal, quotes included).
    pub model: Option<Range<usize>>,
    /// The raw upstream `model` literal, for telemetry.
    pub model_raw: Option<&'a str>,
    /// A non-null top-level `usage`.
    pub usage: bool,
    /// For a `"usage": null` member: the bytes to delete to remove it (one adjacent comma
    /// included), or `None` when it cannot be cut out safely (the caller then uses the general
    /// path). OpenAI sends this member on every chunk once usage is requested.
    pub null_usage_member: Option<Range<usize>>,
    /// A top-level `usage` member is present (any value).
    pub has_usage_key: bool,
    /// Output text bytes, as the general path's `delta_bytes` counts them.
    pub delta_bytes: u64,
}

/// Byte range of `inner` within `outer`, if `inner` is a subslice of it.
fn range_in(outer: &str, inner: &str) -> Option<Range<usize>> {
    let start = (inner.as_ptr() as usize).checked_sub(outer.as_ptr() as usize)?;
    let end = start + inner.len();
    (end <= outer.len() && outer.get(start..end).is_some_and(|s| std::ptr::eq(s, inner))).then_some(start..end)
}

/// The bytes to delete to remove the top-level member whose value spans `value` and whose key
/// is written literally as `key` (quotes included), with one adjacent comma, so the object stays
/// valid JSON. `None` when the bytes around the value are not exactly that (an escaped key, for
/// example).
fn member_removal(data: &str, value: Range<usize>, key: &str) -> Option<Range<usize>> {
    let b = data.as_bytes();
    let ws = |c: u8| matches!(c, b' ' | b'\t' | b'\n' | b'\r');
    let mut i = value.start;
    while i > 0 && ws(b[i - 1]) {
        i -= 1;
    }
    if i == 0 || b[i - 1] != b':' {
        return None;
    }
    i -= 1;
    while i > 0 && ws(b[i - 1]) {
        i -= 1;
    }
    let key_start = i.checked_sub(key.len())?;
    if &data.as_bytes()[key_start..i] != key.as_bytes() {
        return None;
    }
    // The byte before the key must be structural (`{` or `,`), which also rules out a longer
    // key ending in an escaped quote followed by `usage"`.
    let mut j = key_start;
    while j > 0 && ws(b[j - 1]) {
        j -= 1;
    }
    match b.get(j.checked_sub(1)?)? {
        b',' => Some(j - 1..value.end),
        b'{' => {
            let mut k = value.end;
            while k < b.len() && ws(b[k]) {
                k += 1;
            }
            match b.get(k)? {
                b',' => Some(key_start..k + 1),
                b'}' => Some(key_start..value.end),
                _ => None,
            }
        }
        _ => None,
    }
}

/// A data payload that can be re-framed as one SSE `data:` line as it is.
fn single_line(data: &str) -> bool {
    !data.bytes().any(|b| b == b'\n' || b == b'\r')
}

/// Scans one OpenAI chunk. `None` means: use the general path.
pub(crate) fn scan_openai(data: &str) -> Option<OpenAiChunk<'_>> {
    if !single_line(data) || !data.trim_start().starts_with('{') {
        return None;
    }
    let v: ChunkView<'_> = serde_json::from_str(data).ok()?;
    let model = match v.model {
        Some(raw) => Some(range_in(data, raw.get())?),
        None => None,
    };
    let usage = v.usage.is_some_and(|u| u.get() != "null");
    let null_usage_member = match v.usage {
        Some(u) if !usage => member_removal(data, range_in(data, u.get())?, "\"usage\""),
        _ => None,
    };
    Some(OpenAiChunk {
        model,
        model_raw: v.model.map(RawValue::get),
        usage,
        null_usage_member,
        has_usage_key: v.usage.is_some(),
        delta_bytes: v.choices.0,
    })
}

/// Writes `data: <chunk>\n\n` with the model replaced by `model_json` (the gateway's model id
/// as a JSON string literal) and, when `strip_null_usage`, the `"usage": null` member removed.
pub(crate) fn write_openai(out: &mut BytesMut, data: &str, chunk: &OpenAiChunk<'_>, model_json: &str, strip_null_usage: bool) {
    write_openai_with(out, data, chunk, model_json, strip_null_usage, None);
}

/// [`write_openai`], also replacing the byte range `extra.0` with `extra.1` (a JSON literal).
pub(crate) fn write_openai_with(
    out: &mut BytesMut,
    data: &str,
    chunk: &OpenAiChunk<'_>,
    model_json: &str,
    strip_null_usage: bool,
    extra: Option<(Range<usize>, String)>,
) {
    out.extend_from_slice(b"data: ");
    let mut edits: [Option<(Range<usize>, &str)>; 3] = [
        chunk.model.clone().map(|r| (r, model_json)),
        chunk.null_usage_member.clone().filter(|_| strip_null_usage).map(|r| (r, "")),
        extra.as_ref().map(|(r, s)| (r.clone(), s.as_str())),
    ];
    edits.sort_by_key(|e| e.as_ref().map(|(r, _)| r.start));
    let mut at = 0;
    for (r, with) in edits.into_iter().flatten() {
        out.extend_from_slice(&data.as_bytes()[at..r.start]);
        out.extend_from_slice(with.as_bytes());
        at = r.end;
    }
    out.extend_from_slice(&data.as_bytes()[at..]);
    out.extend_from_slice(b"\n\n");
}

/// The one choice of a chunk handled in place while restoring surrogates.
#[derive(Debug)]
pub(crate) struct ChoiceDelta<'a> {
    pub index: u64,
    /// `delta.content` when it is a string: its literal's byte range and its unescaped text.
    pub content: Option<(Range<usize>, Cow<'a, str>)>,
    /// Tool-call argument bytes (counted as output, never rewritten).
    pub tool_bytes: u64,
}

/// What restoring surrogates in place needs from one OpenAI chunk.
#[derive(Debug)]
pub(crate) struct DeltaChunk<'a> {
    pub chunk: OpenAiChunk<'a>,
    /// The raw `id` literal.
    pub id_raw: Option<&'a str>,
    /// `None` when the chunk has no choices.
    pub choice: Option<ChoiceDelta<'a>>,
}

#[derive(Deserialize)]
struct RehydrateView<'a> {
    #[serde(default, borrow, deserialize_with = "present")]
    model: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    usage: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    id: Option<&'a RawValue>,
    #[serde(default, borrow)]
    choices: Choices<'a>,
}

#[derive(Deserialize)]
struct OneChoiceView<'a> {
    #[serde(default)]
    index: Option<u64>,
    #[serde(default, borrow, deserialize_with = "present")]
    finish_reason: Option<&'a RawValue>,
    #[serde(borrow)]
    delta: ContentDeltaView<'a>,
}

#[derive(Deserialize)]
struct ContentDeltaView<'a> {
    #[serde(default, borrow, deserialize_with = "present")]
    content: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    reasoning: Option<&'a RawValue>,
    #[serde(default, borrow, deserialize_with = "present")]
    reasoning_content: Option<&'a RawValue>,
    #[serde(default)]
    tool_calls: SumSeq<ToolCallView>,
}

/// `choices` for in-place restoring: none (absent, `null` or `[]`), exactly one (parsed), or
/// several (not handled in place).
#[derive(Default)]
enum Choices<'a> {
    #[default]
    None,
    One(OneChoiceView<'a>),
    Many,
}

impl<'de: 'a, 'a> Deserialize<'de> for Choices<'a> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<'a>(std::marker::PhantomData<&'a ()>);
        impl<'de: 'a, 'a> Visitor<'de> for V<'a> {
            type Value = Choices<'a>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array or null")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Choices::None)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let Some(first) = a.next_element::<OneChoiceView<'a>>()? else { return Ok(Choices::None) };
                if a.next_element::<IgnoredAny>()?.is_none() {
                    return Ok(Choices::One(first));
                }
                while a.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Choices::Many)
            }
        }
        d.deserialize_any(V(std::marker::PhantomData))
    }
}

/// Unescaped text of a JSON string literal (borrowed when it has no escapes); `None` for any
/// other value.
fn json_str(raw: &str) -> Option<Cow<'_, str>> {
    if !raw.starts_with('"') {
        return None;
    }
    match serde_json::from_str::<&str>(raw) {
        Ok(s) => Some(Cow::Borrowed(s)),
        Err(_) => serde_json::from_str::<String>(raw).ok().map(Cow::Owned),
    }
}

/// Scans one OpenAI chunk for in-place surrogate restoring, in one pass. `None` (use the
/// general path) unless the chunk has no choices, or exactly one unfinished choice whose `delta`
/// is an object without reasoning fields: finishing, multi-choice and reasoning chunks, and
/// choices without a delta, go through `transform_chunk`.
pub(crate) fn scan_openai_delta(data: &str) -> Option<DeltaChunk<'_>> {
    if !single_line(data) || !data.trim_start().starts_with('{') {
        return None;
    }
    let v: RehydrateView<'_> = serde_json::from_str(data).ok()?;
    let usage = v.usage.is_some_and(|u| u.get() != "null");
    let null_usage_member = match v.usage {
        Some(u) if !usage => member_removal(data, range_in(data, u.get())?, "\"usage\""),
        _ => None,
    };
    let model = match v.model {
        Some(raw) => Some(range_in(data, raw.get())?),
        None => None,
    };
    let choice = match v.choices {
        Choices::None => None,
        Choices::Many => return None,
        Choices::One(c) => {
            if c.finish_reason.is_some_and(|f| f.get() != "null") || c.delta.reasoning.is_some() || c.delta.reasoning_content.is_some() {
                return None;
            }
            let content = match c.delta.content {
                Some(raw) => match json_str(raw.get()) {
                    Some(text) => Some((range_in(data, raw.get())?, text)),
                    None => None,
                },
                None => None,
            };
            Some(ChoiceDelta { index: c.index.unwrap_or(0), content, tool_bytes: c.delta.tool_calls.0 })
        }
    };
    let chunk = OpenAiChunk {
        model,
        model_raw: v.model.map(RawValue::get),
        usage,
        null_usage_member,
        has_usage_key: v.usage.is_some(),
        delta_bytes: 0,
    };
    Some(DeltaChunk { chunk, id_raw: v.id.map(RawValue::get), choice })
}

#[derive(Deserialize)]
struct AnthropicDeltaView<'a> {
    #[serde(rename = "type", default, borrow)]
    ty: Option<&'a str>,
    #[serde(default)]
    text: StrLen,
    #[serde(default)]
    thinking: StrLen,
    #[serde(default)]
    partial_json: StrLen,
}

#[derive(Deserialize)]
struct EventView<'a> {
    #[serde(rename = "type", borrow)]
    ty: &'a str,
    #[serde(default, borrow)]
    delta: Option<AnthropicDeltaView<'a>>,
}

/// What the passthrough needs from one native Anthropic event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AnthropicEvent<'a> {
    /// The event type, also its SSE `event:` name.
    pub ty: &'a str,
    /// Streamed text bytes, as the general path counts them.
    pub delta_bytes: u64,
}

/// Scans one native Anthropic event. Only events that the general path passes through unchanged
/// when no surrogates are restored qualify: content block start, delta and stop, and `ping`.
/// `message_start` (model rewrite, usage), `message_delta` (usage), errors and anything else
/// return `None` and take the general path.
pub(crate) fn scan_anthropic(data: &str) -> Option<AnthropicEvent<'_>> {
    if !single_line(data) || !data.trim_start().starts_with('{') {
        return None;
    }
    let v: EventView<'_> = serde_json::from_str(data).ok()?;
    let delta_bytes = match v.ty {
        "content_block_delta" => match v.delta {
            Some(d) => match d.ty {
                Some("text_delta") => d.text.0,
                Some("thinking_delta") => d.thinking.0,
                Some("input_json_delta") => d.partial_json.0,
                _ => 0,
            },
            None => 0,
        },
        "content_block_start" | "content_block_stop" | "ping" => 0,
        _ => return None,
    };
    Some(AnthropicEvent { ty: v.ty, delta_bytes })
}

/// Writes `event: <type>\ndata: <event>\n\n`.
pub(crate) fn write_anthropic(out: &mut BytesMut, data: &str, ev: &AnthropicEvent<'_>) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(ev.ty.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    out.extend_from_slice(data.as_bytes());
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_model_and_counts_delta_bytes() {
        let data = r#"{"id":"c1","model":"gpt-4o","choices":[{"index":0,"delta":{"content":"héllo","reasoning_content":"ab"}},{"index":1,"delta":{"tool_calls":[{"function":{"arguments":"{\"a\":1}"}}]}}]}"#;
        let c = scan_openai(data).unwrap();
        assert_eq!(&data[c.model.clone().unwrap()], r#""gpt-4o""#);
        assert_eq!(c.model_raw, Some(r#""gpt-4o""#));
        assert!(!c.usage);
        assert_eq!(c.delta_bytes, "héllo".len() as u64 + 2 + r#"{"a":1}"#.len() as u64);
    }

    #[test]
    fn nested_model_keys_are_not_the_top_level_model() {
        let data = r#"{"choices":[{"delta":{"model":"inner"}}],"x":{"model":"y"}}"#;
        let c = scan_openai(data).unwrap();
        assert_eq!(c.model, None);
    }

    #[test]
    fn falls_back_on_anything_unusual() {
        assert!(scan_openai("[1,2]").is_none());
        assert!(scan_openai("not json").is_none());
        assert!(scan_openai(r#"{"model":"a","model":"b"}"#).is_none(), "duplicate keys");
        assert!(scan_openai("{\"model\":\n\"a\"}").is_none(), "a line break would split the SSE event");
        assert!(scan_openai(r#"{"choices":{"0":1}}"#).is_none());
        assert!(scan_openai(r#"{"choices":[{"delta":"x"}]}"#).is_none());
    }

    #[test]
    fn null_usage_member_is_cut_out_with_one_comma() {
        let model = r#""gw""#;
        for (data, want) in [
            (r#"{"id":"a","usage":null,"model":"m"}"#, r#"{"id":"a","model":"gw"}"#),
            (r#"{"usage":null,"model":"m"}"#, r#"{"model":"gw"}"#),
            (r#"{"model":"m","usage" : null }"#, r#"{"model":"gw" }"#),
            (r#"{ "usage" :null }"#, r#"{  }"#),
            (r#"{"model":"m", "usage":null, "x":1}"#, r#"{"model":"gw", "x":1}"#),
        ] {
            let c = scan_openai(data).unwrap();
            assert!(c.has_usage_key && !c.usage);
            let mut out = BytesMut::new();
            write_openai(&mut out, data, &c, model, true);
            assert_eq!(std::str::from_utf8(&out).unwrap(), format!("data: {want}\n\n"), "{data}");
        }
        // An escaped key cannot be cut out byte-wise: the caller takes the general path.
        let c = scan_openai(r#"{"us\u0061ge":null}"#).unwrap();
        assert!(c.has_usage_key && c.null_usage_member.is_none());
    }

    #[test]
    fn usage_null_is_not_usage() {
        assert!(!scan_openai(r#"{"usage":null}"#).unwrap().usage);
        assert!(scan_openai(r#"{"usage":{"prompt_tokens":1}}"#).unwrap().usage);
    }

    #[test]
    fn anthropic_events() {
        let d = r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"a\"b"}}"#;
        assert_eq!(scan_anthropic(d), Some(AnthropicEvent { ty: "content_block_delta", delta_bytes: 3 }));
        assert!(scan_anthropic(r#"{"type":"message_start","message":{"model":"m"}}"#).is_none());
        assert!(scan_anthropic(r#"{"type":"message_delta","usage":{"output_tokens":1}}"#).is_none());
        assert!(scan_anthropic(r#"{"type":"error","error":{}}"#).is_none());
        assert!(scan_anthropic(r#"{"type":"ping"}"#).is_some());
    }
}
