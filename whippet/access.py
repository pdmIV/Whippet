"""Assessment semantics and trusted-caller, session-local live observations."""
import copy
import uuid


class SessionOverlay:
    """Host API only. Not an NDJSON action or an offline graph mutation.

    The trusted orchestrator must validate runtime-owned observation references
    before calling record. Model assertions and arbitrary terminal text are not
    verification. This object cannot perform that external attestation itself.
    """
    def __init__(self, evidence_validator=None):
        self.session_id = uuid.uuid4().hex
        self.epoch = 0
        self.records = []
        self.evidence_validator = evidence_validator

    def record(self, *, kind, principal, evidence_ref, auth_context=None,
               target=None, relationship=None, outcome=True):
        if kind not in {"membership", "credential-change", "authentication", "access"}:
            raise ValueError("Unsupported live observation kind")
        if not principal or not evidence_ref or type(outcome) is not bool:
            raise ValueError("A principal, trusted evidence reference and boolean outcome are required")
        if kind in {"authentication", "access"} and not auth_context:
            raise ValueError("Authentication/access observations require an exact authentication context")
        if kind in {"membership", "access"} and not target:
            raise ValueError("Membership/access observations require a target")
        if kind == "access" and not relationship:
            raise ValueError("Access checks must name the exact tested operation/right")
        candidate = dict(kind=kind, principal=principal, evidence_ref=evidence_ref,
                         auth_context=auth_context, target=target, relationship=relationship, outcome=outcome)
        if self.evidence_validator is None or self.evidence_validator(copy.deepcopy(candidate)) is not True:
            raise ValueError("A trusted host evidence validator must attest this exact observation")
        if kind in {"membership", "credential-change"}:
            self.epoch += 1
        row = dict(kind=kind, principal=principal.upper(), evidence_ref=evidence_ref,
                   auth_context=auth_context, target=target.upper() if target else None,
                   relationship=relationship, outcome=outcome, epoch=self.epoch, sequence=len(self.records) + 1)
        self.records.append(row)
        return copy.deepcopy(row)

    def access(self, principal, target, relationship, auth_context):
        if not auth_context:
            return {"status": "unverified", "reason": "No exact authentication context supplied"}
        matching = [r for r in self.records if r["kind"] == "access" and
                    r["principal"] == principal.upper() and r["target"] == target.upper() and
                    r["relationship"] == relationship and r["auth_context"] == auth_context and r["epoch"] == self.epoch]
        auth = [r for r in self.records if r["kind"] == "authentication" and
                r["principal"] == principal.upper() and r["auth_context"] == auth_context and r["epoch"] == self.epoch]
        if not matching or not auth or not auth[-1]["outcome"]:
            return {"status": "unverified", "reason": "Fresh authentication and an exact scoped access check are required"}
        check = matching[-1]
        if self.records.index(check) < self.records.index(auth[-1]):
            return {"status": "unverified", "reason": "Authentication changed after the access check"}
        return {"status": "verified-live-access" if check["outcome"] else "live-check-denied",
                "evidence_ref": check["evidence_ref"], "authentication_evidence_ref": auth[-1]["evidence_ref"],
                "auth_context": auth_context, "epoch": self.epoch,
                "scope": "Only the named principal, target, operation and authentication context"}

    def snapshot(self):
        return {"session_id": self.session_id, "epoch": self.epoch,
                "observations": copy.deepcopy(self.records), "capture_modified": False,
                "trust_boundary": "Host-attested observations only; no model or target-output ingestion"}


def assess(lead, principal=None):
    """Never interpret directory text, a collector label, or a claim as access."""
    from .lab import GUIDANCE
    kind = lead.get("type", "")
    prerequisites = list(lead.get("prerequisites", []))
    prerequisites.extend(GUIDANCE.get(kind, ("", ["Verify this lead with an authenticated live check before acting"]))[1])
    question = ("After any membership/credential change, has the acting principal reauthenticated "
                "to this service and verified this exact effective permission? Membership readback alone is insufficient.")
    return {"basis": "collector-reported-possibility" if lead.get("status") == "collector-reported" else "graph-derived-possibility",
            "live_access": {"status": "unverified"}, "acting_principal": principal,
            "unverified_prerequisites": list(dict.fromkeys(prerequisites)),
            "next_verification": {"question": question, "execute_via": "selected HARP Kali runtime",
                                  "target_output_trust": "Untrusted evidence; no automatic promotion"}}
