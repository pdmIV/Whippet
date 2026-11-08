"""Normalize Certipy find JSON, reusing its assessments rather than ESC rules."""
import hashlib
import json


def is_certipy(data):
    return isinstance(data, dict) and bool({"Certificate Authorities", "Certificate Templates"} & data.keys())


def import_certipy(graph, data, filename):
    for section, kind, name_key in (("Certificate Authorities", "EnterpriseCA", "CA Name"),
                                    ("Certificate Templates", "CertificateTemplate", "Template Name")):
        entries = data.get(section)
        if entries is None or entries == 0:
            continue
        if not isinstance(entries, dict):
            raise ValueError(f"Invalid Certipy {section} in {filename}")
        for index, entry in entries.items():
            if not isinstance(entry, dict):
                raise ValueError(f"Invalid Certipy entry in {filename}:{section}:{index}")
            name = entry.get(name_key) or entry.get("Name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"Missing Certipy {name_key} in {filename}:{index}")
            for key in ("[!] Vulnerabilities", "Vulnerabilities"):
                if entry.get(key) is not None and not isinstance(entry[key], dict):
                    raise ValueError(f"Invalid Certipy vulnerabilities in {filename}:{index}")
            # Report identities are namespaced by file, not silently merged with
            # directory identities or another forest's same-named templates.
            namespace = hashlib.sha256(str(filename).encode()).hexdigest()[:12]
            objectid = f"CERTIPY:{namespace}:{kind}:{index}".upper()
            props = {"name": f"{name} [CERTIPY {namespace}:{index}]", "objectid": objectid,
                     "collector": "certipy", "source_file": filename, "report": entry}
            graph.add_node(props["name"], props, kind)


def reported_findings(graph):
    rows = []
    for node, props in sorted(graph._props.items()):
        if props.get("collector") != "certipy":
            continue
        report = props["report"]
        for key in ("[!] Vulnerabilities", "Vulnerabilities"):
            findings = report.get(key) or {}
            if not isinstance(findings, dict):
                raise ValueError(f"Invalid Certipy vulnerabilities in {props['source_file']}")
            for label, description in sorted(findings.items()):
                if not description:
                    continue
                rows.append({"query": "adcs", "subject": node, "category": label,
                             "evidence": description, "status": "collector-reported",
                             "source_file": props["source_file"],
                             "principal_scope_verified": False,
                             "prerequisites": ["Verify enrollment/control rights for the current principal, CA/template publication, and current CA/DC mitigations."]})
    return rows
