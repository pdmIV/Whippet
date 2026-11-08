"""Offline GPO scope analysis. Scope is distinct from resultant policy."""
from collections import deque


def value(data, *keys):
    lowered = {key.lower(): val for key, val in data.items()}
    for key in keys:
        if key.lower() in lowered:
            return lowered[key.lower()]
    return None


def flag(data, *keys):
    val = value(data, *keys)
    if type(val) is bool:
        return val
    if type(val) is int and val in (0, 1):
        return bool(val)
    if isinstance(val, str) and val.lower() in ("true", "false"):
        return val.lower() == "true"
    return None


class PolicyAnalyzer:
    def __init__(self, graph):
        self.g = graph
        self._rows = None

    def _links(self, gpo):
        links, seen = [], set()
        for container, props in sorted(self.g._props.items()):
            for link in props.get("gpo_links", []):
                reference = value(link, "GUID", "ObjectIdentifier")
                if reference is not None and not isinstance(reference, str):
                    raise ValueError("GPO link identifier must be a string")
                if not reference or self.g.resolve(reference.strip("{}")) != gpo:
                    continue
                seen.add(container)
                links.append((container, link))
        # Preserve usable legacy graph-only inputs without inventing flags.
        for container, kind in self.g.neighbors(gpo):
            if kind == "GPLink" and container not in seen:
                links.append((container, {}))
        return links

    def _section_enabled(self, props, kind):
        key = "computer" if kind == "Computer" else "user"
        explicit = flag(props, key + "enabled", key + "settingsenabled")
        states = [explicit] if explicit is not None else []
        flags = value(props, "flags", "gpoflags")
        if type(flags) is int and 0 <= flags <= 3:
            states.append(not bool(flags & (2 if key == "computer" else 1)))
        status = value(props, "gpostatus")
        statuses = {"allsettingsenabled": 0, "usersettingsdisabled": 1,
                    "computersettingsdisabled": 2, "allsettingsdisabled": 3}
        if isinstance(status, str) and status.lower() in statuses:
            states.append(not bool(statuses[status.lower()] & (2 if key == "computer" else 1)))
        return False if False in states else True if True in states else None

    def impacts(self, gpo=None):
        if self._rows is None:
            rows = []
            for policy in sorted(n for n in self.g._props if self.g.node_type(n) == "GPO"):
                props = self.g._props[policy]
                for container, link in self._links(policy):
                    enabled = flag(link, "IsEnabled", "Enabled")
                    disabled = flag(link, "IsDisabled", "Disabled")
                    enforced = flag(link, "IsEnforced", "Enforced")
                    options = value(link, "Options", "LinkOptions")
                    if type(options) is int and options >= 0:
                        enabled = enabled is not False and not bool(options & 1)
                        enforced = bool(options & 2)
                    if disabled is True:
                        enabled = False
                    # SharpHound/BloodHound.py Links arrays contain active links;
                    # absent Enabled is not evidence that the link is disabled.
                    link_active = enabled is not False
                    queue = deque([(container, [container], [], {container})])
                    seen = set()
                    while queue:
                        node, path, unknown, ancestry = queue.popleft()
                        if node in seen:
                            continue
                        seen.add(node)
                        node_props = self.g._props.get(node, {})
                        block = flag(node_props, "blocksinheritance", "blockinheritance")
                        if link_active and node != container and self.g.node_type(node) == "OU":
                            if block is True and enforced is not True:
                                # Unknown enforcement could bypass this OU: keep
                                # descendants as unknown rather than falsely deny.
                                if enforced is False:
                                    rows.append({"gpo": policy, "target": node, "target_type": "OU",
                                                 "link_container": container, "path": path,
                                                 "scope_status": "blocked-inheritance", "link": link,
                                                 "enforced": enforced, "unknowns": [], "conditional": False,
                                                 "verified_application": False})
                                    continue
                                unknown = unknown + [f"Link enforcement unknown at blocked OU: {node}"]
                            elif block is None and enforced is not True:
                                unknown = unknown + [f"Inheritance-block setting unknown: {node}"]
                        kind = self.g.node_type(node)
                        if kind in ("User", "Computer"):
                            section = self._section_enabled(props, kind)
                            status = "candidate-scope"
                            if not link_active: status = "disabled-link"
                            elif section is False: status = "disabled-section"
                            elif unknown: status = "unknown-inheritance"
                            checks = list(unknown)
                            if section is None: checks.append(f"{kind} GPO section enabled state not collected")
                            checks.extend(["Read/apply security filtering and deny ACEs require evaluation",
                                           "WMI filtering and resultant policy require evaluation"])
                            wmi = value(props, "gpcwqlfilter", "wmifilter")
                            rows.append({"gpo": policy, "target": node, "target_type": kind,
                                         "link_container": container, "path": path, "link": link,
                                         "enforced": enforced, "section_enabled": section,
                                         "wmi_filter": wmi, "scope_status": status,
                                         "conditional": status in ("candidate-scope", "unknown-inheritance"),
                                         "unknowns": checks, "verified_application": False})
                            continue
                        for child, edge in sorted(self.g.neighbors(node)):
                            if edge == "Contains" and child not in ancestry:
                                queue.append((child, path + [child], list(unknown), ancestry | {child}))
            self._rows = sorted(rows, key=lambda r: (r["gpo"], r["target"], r["link_container"], r["path"]))
        if gpo is not None:
            gpo = self.g.resolve(gpo)
            if self.g.node_type(gpo) != "GPO":
                raise ValueError(f"Expected a loaded GPO: {gpo}")
            return [r for r in self._rows if r["gpo"] == gpo]
        return self._rows
