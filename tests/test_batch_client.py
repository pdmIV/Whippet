import io
import json
import sys
import unittest
from pathlib import Path

from whippet import ADGraph, QueryEngine
from whippet.batch import run_batch
from whippet.cli import build_parser
from whippet.client import BatchClient


ROOT = Path(__file__).resolve().parents[1]
CAPTURE = ROOT / "tests" / "fixtures" / "order_dependent"


class BatchLifecycleTests(unittest.TestCase):
    def test_ready_ping_shutdown_and_correlation(self):
        args = build_parser().parse_args(["unused", "--batch", "--batch-ready"])
        out = io.StringIO()
        run_batch(QueryEngine(ADGraph()), args, stream=io.StringIO(
            '{"id":1,"mode":"ping"}\n{"id":2,"mode":"shutdown"}\n{"id":3,"mode":"ping"}\n'), output=out)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["event"], "ready")
        self.assertEqual(rows[1]["batch"]["session_id"], rows[0]["session_id"])
        self.assertEqual(rows[2]["batch"]["request_index"], 2)
        self.assertEqual(rows[2]["result"]["status"], "closing")

    def test_invalid_lifecycle_request_does_not_shutdown(self):
        args = build_parser().parse_args(["unused", "--batch"])
        out = io.StringIO()
        run_batch(QueryEngine(ADGraph()), args, stream=io.StringIO(
            '{"id":1,"mode":"shutdown","extra":true}\n{"id":2,"mode":"ping"}\n'), output=out)
        rows = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertIn("error", rows[0])
        self.assertEqual(rows[1]["result"]["status"], "ready")


class BatchClientTests(unittest.TestCase):
    def argv(self):
        return [sys.executable, str(ROOT / "whippet.py"), str(CAPTURE), "--batch", "--batch-ready"]

    def test_live_process_reuse_errors_and_event_callbacks(self):
        events = []
        with BatchClient(self.argv(), event_sink=events.append) as client:
            pid = client.process.pid
            first = client.request({"mode": "objects", "object_type": "user", "select": ["name"], "limit": 1})
            bad = client.request({"mode": "node", "node": "missing"})
            last = client.request({"mode": "ping"})
            self.assertEqual(client.process.pid, pid)
            self.assertEqual(first["batch"]["session_id"], last["batch"]["session_id"])
            self.assertEqual(last["batch"]["request_index"], 3)
            self.assertIn("error", bad)
            self.assertEqual(first["result"]["items"][0]["properties"].keys(), {"name"})
        self.assertIsNotNone(client.process.poll())
        self.assertEqual(sum(e["event"] == "whippet.batch.request" for e in events), 3)
        self.assertEqual(sum(e["event"] == "whippet.batch.response" for e in events), 3)

    def test_explicit_shutdown(self):
        with BatchClient(self.argv()) as client:
            response = client.request({"mode": "shutdown"})
            self.assertEqual(response["result"]["status"], "closing")
            client.process.wait(timeout=3)

    def test_timeout_terminates_session_without_retry(self):
        code = 'import sys,json;print(json.dumps({"schema_version":1,"event":"ready","protocol_version":1,"session_id":"test"}),flush=True);[None for line in sys.stdin]'
        argv = [sys.executable, "-u", "-c", code, "--batch", "--batch-ready"]
        with BatchClient(argv, request_timeout=.1) as client:
            with self.assertRaises(TimeoutError): client.request({"mode": "ping"})
            self.assertIsNotNone(client.process.poll())

    def test_startup_failure_and_argv_validation(self):
        argv = self.argv()
        argv[2] = str(CAPTURE / "missing.json")
        with self.assertRaises(ValueError):
            with BatchClient(argv): pass
        with self.assertRaises(ValueError): BatchClient("whippet capture --batch")
        with self.assertRaises(ValueError): BatchClient(["whippet", "--batch"])

    def test_correlation_failure_terminates_process(self):
        code = ('import sys,json;'
                'print(json.dumps({"schema_version":1,"event":"ready","protocol_version":1,"session_id":"test"}),flush=True);'
                'sys.stdin.readline();'
                'print(json.dumps({"schema_version":1,"id":"wrong","batch":{"session_id":"test"}}),flush=True);'
                'sys.stdin.read()')
        with BatchClient([sys.executable, "-u", "-c", code, "--batch", "--batch-ready"]) as client:
            with self.assertRaisesRegex(ValueError, "correlation"):
                client.request({"id": "expected", "mode": "ping"})
            self.assertIsNotNone(client.process.poll())

    def test_invalid_stdout_fails_handshake(self):
        argv = [sys.executable, "-u", "-c", 'print("not-json",flush=True)', "--batch", "--batch-ready"]
        with self.assertRaises(ValueError):
            with BatchClient(argv): pass


if __name__ == "__main__": unittest.main()
