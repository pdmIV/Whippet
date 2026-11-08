"""Synchronous load-once batch client for runtime-owning orchestrators."""
import collections
import json
import queue
import subprocess
import threading
import uuid


class BatchClient:
    """Supply a complete argv ending in --batch --batch-ready.

    The caller owns runtime selection, capture paths and event persistence.
    Requests are serialized. A timeout or protocol failure terminates the session;
    it never silently falls back to another executable or retries a request.
    """

    def __init__(self, argv, *, event_sink=None, startup_timeout=30, request_timeout=30,
                 max_response_characters=8 * 1024 * 1024):
        if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(v, str) for v in argv):
            raise ValueError("argv must be a nonempty sequence of strings")
        if "--batch" not in argv or "--batch-ready" not in argv:
            raise ValueError("argv must include --batch and --batch-ready")
        if startup_timeout <= 0 or request_timeout <= 0 or max_response_characters < 1:
            raise ValueError("Timeouts and response size must be positive")
        self.argv, self.event_sink = list(argv), event_sink
        self.startup_timeout, self.request_timeout = startup_timeout, request_timeout
        self.max_response_characters = max_response_characters
        self.process, self.ready = None, None
        self.stderr = collections.deque(maxlen=100)
        self._messages, self._lock = queue.Queue(), threading.Lock()
        self._used = False

    def _event(self, event, **fields):
        if self.event_sink:
            self.event_sink({"event": "whippet.batch." + event, **fields})

    def _stdout(self):
        try:
            while True:
                line = self.process.stdout.readline(self.max_response_characters + 1)
                if not line:
                    self._messages.put(EOFError("Whippet closed stdout"))
                    return
                if len(line) > self.max_response_characters:
                    self._messages.put(ValueError("Whippet response exceeds the client size limit"))
                    return
                self._messages.put(json.loads(line))
        except Exception as exc:
            self._messages.put(exc)

    def _stderr(self):
        try:
            while True:
                line = self.process.stderr.readline(4096)
                if not line:
                    return
                self.stderr.append(line.rstrip())
        except (OSError, ValueError):
            pass

    def _receive(self, timeout):
        try:
            reply = self._messages.get(timeout=timeout)
        except queue.Empty as exc:
            raise TimeoutError("Whippet batch response timed out") from exc
        if isinstance(reply, Exception):
            raise reply
        if not isinstance(reply, dict) or reply.get("schema_version") != 1:
            raise ValueError("Invalid Whippet response schema")
        return reply

    def start(self):
        if self._used:
            raise RuntimeError("A BatchClient instance represents one process; create a new client to restart")
        self._used = True
        self.process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1, shell=False)
        self._threads = [threading.Thread(target=self._stdout, daemon=True),
                         threading.Thread(target=self._stderr, daemon=True)]
        for thread in self._threads:
            thread.start()
        try:
            self._event("start", argv=self.argv)
            self.ready = self._receive(self.startup_timeout)
            if self.ready.get("event") != "ready" or self.ready.get("protocol_version") != 1 or not self.ready.get("session_id"):
                raise ValueError("Whippet did not send a compatible readiness handshake")
            self._event("ready", response=self.ready)
        except Exception:
            self.close()
            raise
        return self

    def request(self, request, *, timeout=None):
        if not isinstance(request, dict):
            raise ValueError("request must be an object")
        timeout = self.request_timeout if timeout is None else timeout
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._lock:
            if self.process is None or self.process.poll() is not None or self.ready is None:
                raise RuntimeError("Whippet batch process is not ready")
            request = dict(request)
            request.setdefault("id", uuid.uuid4().hex)
            if type(request["id"]) not in (str, int):
                raise ValueError("Client requests require a string or integer id")
            line = json.dumps(request, ensure_ascii=True, separators=(",", ":")) + "\n"
            if len(line) > 65536:
                raise ValueError("Request exceeds Whippet's 65536-character limit")
            self._event("request", session_id=self.ready["session_id"], request=request)
            try:
                self.process.stdin.write(line)
                self.process.stdin.flush()
                response = self._receive(timeout)
                if response.get("id") != request["id"] or response.get("batch", {}).get("session_id") != self.ready["session_id"]:
                    raise ValueError("Whippet response correlation mismatch")
            except Exception as exc:
                try:
                    self._event("error", request=request, error=str(exc), stderr=list(self.stderr))
                finally:
                    self.close()
                raise
            self._event("response", request_id=request["id"], response=response)
            return response

    def close(self):
        if self.process is None:
            return
        process = self.process
        if process.poll() is None:
            try:
                process.stdin.close()  # EOF is the normal graceful shutdown.
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait()
        for thread in getattr(self, "_threads", []):
            thread.join(timeout=1)
        for pipe in (process.stdin, process.stdout, process.stderr):
            if not pipe.closed:
                pipe.close()
        self.ready = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.close()
