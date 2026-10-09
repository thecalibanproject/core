#!/usr/bin/env python3
"""Tiny OpenAI-compatible + Anthropic Messages mock used by scripts/smoke.sh. Echoes the last user
message so the smoke test can check what the upstream actually received (pseudonymized) and what
the client got back (rehydrated). Writes every request (path, auth headers, body) to $MOCK_LOG."""
import json, os, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = os.environ.get("MOCK_LOG", "/tmp/caliban-mock.jsonl")

def text_of(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return ""

def last_user(body):
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            return text_of(m.get("content"))
    return ""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.endswith("/models"):
            self._json({"object": "list", "data": [
                {"id": "Qwen/Qwen3-8B", "object": "model", "max_model_len": 32768},
                {"id": "Qwen/Qwen3-Embedding-0.6B", "object": "model"}]})
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        with open(LOG, "a") as f:
            f.write(json.dumps({"path": self.path, "auth": self.headers.get("authorization"),
                                "x_api_key": self.headers.get("x-api-key"),
                                "anthropic_version": self.headers.get("anthropic-version"), "body": body}) + "\n")
        if self.path.endswith("/rerank"):
            docs = body.get("documents") or body.get("texts") or []
            q = body.get("query", "")
            # score = shared words with the query (deterministic)
            scores = [len(set(q.lower().split()) & set(d.lower().split())) / 10 for d in docs]
            return self._json({"results": [{"index": i, "relevance_score": s} for i, s in enumerate(scores)],
                               "usage": {"total_tokens": 7}})
        if self.path.endswith("/embeddings"):
            inputs = body["input"] if isinstance(body["input"], list) else [body["input"]]
            return self._json({"object": "list", "model": body["model"],
                               "data": [{"object": "embedding", "index": i, "embedding": [0.1, 0.2, 0.3]} for i in range(len(inputs))],
                               "usage": {"prompt_tokens": 5, "total_tokens": 5}})
        if self.path.endswith("/messages"):
            return self.anthropic(body)
        text = "You said: " + last_user(body)
        # Qwen-style server without a reasoning parser: reasoning inline in content.
        if "qwen" in body["model"].lower() and body.get("chat_template_kwargs", {}).get("enable_thinking", True):
            text = "<think>Let me think about it.</think>\n\n" + text
        usage = {"prompt_tokens": 12, "completion_tokens": 7, "total_tokens": 19}
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            # Split into 3-char deltas so surrogates straddle chunk boundaries.
            for i in range(0, len(text), 3):
                chunk = {"id": "c1", "object": "chat.completion.chunk", "model": body["model"],
                         "choices": [{"index": 0, "delta": {"content": text[i:i+3]}, "finish_reason": None}]}
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode()); self.wfile.flush()
            end = {"id": "c1", "object": "chat.completion.chunk", "model": body["model"],
                   "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": usage}
            self.wfile.write(f"data: {json.dumps(end)}\n\ndata: [DONE]\n\n".encode())
            return
        resp = {"id": "x", "object": "chat.completion", "created": int(time.time()), "model": body["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
                "usage": usage}
        self._json(resp)

    def anthropic(self, body):
        """Anthropic Messages API (native passthrough target)."""
        text = "You said: " + last_user(body)
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            def ev(e):
                self.wfile.write(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode()); self.wfile.flush()
            ev({"type": "message_start", "message": {"id": "msg_mock", "type": "message", "role": "assistant", "model": body["model"],
                                                      "content": [], "usage": {"input_tokens": 12, "output_tokens": 1}}})
            ev({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
            for i in range(0, len(text), 3):
                ev({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text[i:i+3]}})
            ev({"type": "content_block_stop", "index": 0})
            ev({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 7}})
            ev({"type": "message_stop"})
            return
        self._json({"id": "msg_mock", "type": "message", "role": "assistant", "model": body["model"],
                    "content": [{"type": "text", "text": text}], "stop_reason": "end_turn", "stop_sequence": None,
                    "usage": {"input_tokens": 12, "output_tokens": 7}})

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 18000), H).serve_forever()
