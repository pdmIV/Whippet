"use strict";
/*
 * Whippet browser visualizer — zero-dependency Canvas force-directed graph.
 *
 * Two small classes:
 *   ForceGraph  — physics + rendering + pan/zoom/drag on a <canvas>
 *   App         — wires the sidebar controls to the /api/* endpoints
 *
 * Everything is fetched from the QueryEngine-backed JSON API; this file holds
 * no AD logic of its own, only presentation.
 */

const TYPE_COLOR = {
  User: "#4ea1ff",
  Computer: "#59d499",
  Group: "#ffb454",
  Domain: "#b48ead",
  Unknown: "#8a93a0",
};
const HVT_RING = "#ffd166";
const PATH_COLOR = "#ff5d5d";
const EDGE_COLOR = "rgba(125,136,150,0.35)";
const LABEL_COLOR = "#aeb7c2";

// ── tiny fetch helper ──────────────────────────────────────────────────────────
async function api(path, params) {
  const url = new URL(path, window.location.origin);
  if (params) Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, v);
  });
  const res = await fetch(url);
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  return res.json();
}

// ════════════════════════════════════════════════════════════════════════════════
//  ForceGraph
// ════════════════════════════════════════════════════════════════════════════════
class ForceGraph {
  constructor(canvas, { onExpand } = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.onExpand = onExpand || (() => {});

    this.nodes = new Map();          // id -> node
    this.edges = [];                 // {source, target, etype, highlight}
    this.edgeKeys = new Set();
    this.highlightNodes = new Set();

    this.scale = 1;
    this.tx = 0;
    this.ty = 0;
    this.focusNode = null;

    this.hover = null;
    this.dragNode = null;
    this.panning = false;
    this.moved = false;
    this.last = { x: 0, y: 0 };

    this._resize();
    window.addEventListener("resize", () => this._resize());
    this._bindEvents();
    this._loop();
  }

  // ── data ───────────────────────────────────────────────────────────────────
  setData(sub, opts = {}) {
    this.nodes.clear();
    this.edges = [];
    this.edgeKeys.clear();
    this.highlightNodes = new Set((opts.highlightNodes || []).map(s => s.toUpperCase()));
    this.focusNode = (opts.focusNode || "").toUpperCase() || null;
    this._ingest(sub, opts);
    this._seedPositions();
    if (opts.fit !== false) this.fit();
    if (this.focusNode) this.centerOn(this.focusNode);
  }

  merge(sub) {
    this._ingest(sub, {});
  }

  _ingest(sub, opts) {
    const cx = this.canvas.clientWidth / 2;
    const cy = this.canvas.clientHeight / 2;
    (sub.nodes || []).forEach(n => {
      if (!this.nodes.has(n.id)) {
        this.nodes.set(n.id, {
          id: n.id, type: n.type || "Unknown", high_value: !!n.high_value,
          x: cx + (Math.random() - 0.5) * 300,
          y: cy + (Math.random() - 0.5) * 300,
          vx: 0, vy: 0, fixed: false,
        });
      } else {
        const ex = this.nodes.get(n.id);
        ex.type = n.type || ex.type;
        ex.high_value = ex.high_value || !!n.high_value;
      }
    });
    const hl = new Set((opts.highlightEdges || []).map(e => e.source.toUpperCase() + "→" + e.target.toUpperCase() + "|" + (e.etype || "")));
    (sub.edges || []).forEach(e => {
      const key = e.source.toUpperCase() + "→" + e.target.toUpperCase() + "|" + (e.etype || "");
      if (this.nodes.has(e.source) && this.nodes.has(e.target)) {
        if (this.edgeKeys.has(key)) return;
        this.edgeKeys.add(key);
        this.edges.push({ source: e.source, target: e.target, etype: e.etype, highlight: hl.has(key) });
      }
    });
  }

  _seedPositions() {
    // Lay nodes on a circle so the simulation starts from a spread-out state.
    const arr = [...this.nodes.values()];
    const cx = this.canvas.clientWidth / 2, cy = this.canvas.clientHeight / 2;
    const R = Math.min(cx, cy) * 0.82 + arr.length * 6;
    arr.forEach((n, i) => {
      const a = (i / Math.max(arr.length, 1)) * Math.PI * 2;
      const jitter = 0.15 + Math.random() * 0.2;
      n.x = cx + R * Math.cos(a) * jitter;
      n.y = cy + R * Math.sin(a) * jitter;
      n.vx = n.vy = 0;
    });
  }

  clear() {
    this.nodes.clear();
    this.edges = [];
    this.edgeKeys.clear();
    this.highlightNodes.clear();
    this.focusNode = null;
  }

  centerOn(id) {
    const node = this.nodes.get((id || "").toUpperCase());
    if (!node) return;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    this.tx = w / 2 - node.x * this.scale;
    this.ty = h / 2 - node.y * this.scale;
  }

  // ── simulation ──────────────────────────────────────────────────────────────
  _tick() {
    const arr = [...this.nodes.values()];
    const n = arr.length;
    if (n === 0) return;

    const density = Math.max(1, n / 40);
    const REP = 9000 * density, SPRING = 0.018, LEN = 120 + density * 8, GRAV = 0.008, DAMP = 0.85;
    const cx = this.canvas.clientWidth / 2, cy = this.canvas.clientHeight / 2;

    for (let i = 0; i < n; i++) {
      const a = arr[i];
      let fx = (cx - a.x) * GRAV, fy = (cy - a.y) * GRAV;
      for (let j = 0; j < n; j++) {
        if (i === j) continue;
        const b = arr[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy || 0.01;
        const f = REP / d2;
        const d = Math.sqrt(d2);
        fx += (dx / d) * f;
        fy += (dy / d) * f;
      }
      a._fx = fx; a._fy = fy;
    }
    for (const e of this.edges) {
      const a = this.nodes.get(e.source), b = this.nodes.get(e.target);
      if (!a || !b) continue;
      let dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = (d - LEN) * SPRING;
      const ux = dx / d, uy = dy / d;
      a._fx += ux * f; a._fy += uy * f;
      b._fx -= ux * f; b._fy -= uy * f;
    }
    for (let i = 0; i < n; i++) {
      const a = arr[i];
      const ar = a.high_value ? 14 : 11;
      for (let j = i + 1; j < n; j++) {
        const b = arr[j];
        const br = b.high_value ? 14 : 11;
        let dx = b.x - a.x, dy = b.y - a.y;
        let d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const minD = (ar + br + 10) * Math.min(2.2, 1 + density * 0.45);
        if (d >= minD) continue;
        const push = (minD - d) * (0.04 + density * 0.01);
        const ux = dx / d, uy = dy / d;
        a._fx -= ux * push; a._fy -= uy * push;
        b._fx += ux * push; b._fy += uy * push;
      }
    }
    for (const a of arr) {
      if (a === this.dragNode || a.fixed) { a.vx = a.vy = 0; continue; }
      a.vx = (a.vx + a._fx) * DAMP;
      a.vy = (a.vy + a._fy) * DAMP;
      // clamp to keep things from exploding
      a.vx = Math.max(-30, Math.min(30, a.vx));
      a.vy = Math.max(-30, Math.min(30, a.vy));
      a.x += a.vx;
      a.y += a.vy;
    }
  }

  // ── view transforms ─────────────────────────────────────────────────────────
  _toScreen(x, y) { return [x * this.scale + this.tx, y * this.scale + this.ty]; }
  _toWorld(sx, sy) { return [(sx - this.tx) / this.scale, (sy - this.ty) / this.scale]; }

  fit() {
    const arr = [...this.nodes.values()];
    if (!arr.length) { this.scale = 1; this.tx = 0; this.ty = 0; return; }
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    arr.forEach(n => {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    });
    const pad = 80;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    const gw = (maxX - minX) || 1, gh = (maxY - minY) || 1;
    this.scale = Math.min((w - pad) / gw, (h - pad) / gh, 1.6);
    this.scale = Math.max(this.scale, 0.15);
    this.tx = w / 2 - ((minX + maxX) / 2) * this.scale;
    this.ty = h / 2 - ((minY + maxY) / 2) * this.scale;
  }

  // ── rendering ────────────────────────────────────────────────────────────────
  _loop() {
    this._tick();
    this._render();
    requestAnimationFrame(() => this._loop());
  }

  _render() {
    const ctx = this.ctx;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    const dense = this.nodes.size > 40;
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
    ctx.save();
    ctx.scale(this.dpr, this.dpr);

    // edges
    for (const e of this.edges) {
      const a = this.nodes.get(e.source), b = this.nodes.get(e.target);
      if (!a || !b) continue;
      const focused = e.highlight || this.highlightNodes.has(a.id) || this.highlightNodes.has(b.id) || a === this.hover || b === this.hover;
      if (dense && !focused) continue;
      const [ax, ay] = this._toScreen(a.x, a.y);
      const [bx, by] = this._toScreen(b.x, b.y);
      ctx.strokeStyle = e.highlight ? PATH_COLOR : (dense ? "rgba(125,136,150,0.16)" : EDGE_COLOR);
      ctx.lineWidth = e.highlight ? 2.2 : (dense ? 0.8 : 1);
      ctx.beginPath();
      ctx.moveTo(ax, ay);
      ctx.lineTo(bx, by);
      ctx.stroke();
      if (!dense || e.highlight) this._arrow(ax, ay, bx, by, e.highlight);
    }

    // nodes
    const showAllLabels = this.nodes.size <= 18;
    for (const node of this.nodes.values()) {
      const [x, y] = this._toScreen(node.x, node.y);
      const r = (node.high_value ? 9 : 7) * Math.min(Math.max(this.scale, 0.6), 1.4);
      ctx.beginPath();
      ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = TYPE_COLOR[node.type] || TYPE_COLOR.Unknown;
      ctx.fill();
      if (node.high_value) {
        ctx.lineWidth = 2.5;
        ctx.strokeStyle = HVT_RING;
        ctx.stroke();
      }
      if (this.highlightNodes.has(node.id) || node === this.hover) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = "#fff";
        ctx.stroke();
      }
      if (showAllLabels || node === this.hover || this.highlightNodes.has(node.id)) {
        ctx.fillStyle = LABEL_COLOR;
        ctx.font = "11px ui-sans-serif, system-ui, sans-serif";
        ctx.textAlign = "center";
        const label = node.id.length > 34 ? node.id.slice(0, 32) + "…" : node.id;
        ctx.fillText(label, x, y + r + 12);
      }
    }
    ctx.restore();
  }

  _arrow(ax, ay, bx, by, highlight) {
    const ctx = this.ctx;
    const ang = Math.atan2(by - ay, bx - ax);
    // stop short of the node circle
    const r = 9;
    const tx = bx - Math.cos(ang) * r, ty = by - Math.sin(ang) * r;
    const size = highlight ? 8 : 6;
    ctx.fillStyle = highlight ? PATH_COLOR : EDGE_COLOR;
    ctx.beginPath();
    ctx.moveTo(tx, ty);
    ctx.lineTo(tx - size * Math.cos(ang - 0.4), ty - size * Math.sin(ang - 0.4));
    ctx.lineTo(tx - size * Math.cos(ang + 0.4), ty - size * Math.sin(ang + 0.4));
    ctx.closePath();
    ctx.fill();
  }

  // ── interaction ──────────────────────────────────────────────────────────────
  _resize() {
    this.dpr = window.devicePixelRatio || 1;
    const w = this.canvas.clientWidth, h = this.canvas.clientHeight;
    this.canvas.width = w * this.dpr;
    this.canvas.height = h * this.dpr;
  }

  _nodeAt(sx, sy) {
    let best = null, bestD = 14;
    for (const node of this.nodes.values()) {
      const [x, y] = this._toScreen(node.x, node.y);
      const d = Math.hypot(x - sx, y - sy);
      if (d < bestD) { bestD = d; best = node; }
    }
    return best;
  }

  _bindEvents() {
    const c = this.canvas;
    const pos = ev => {
      const rect = c.getBoundingClientRect();
      return [ev.clientX - rect.left, ev.clientY - rect.top];
    };

    c.addEventListener("mousedown", ev => {
      const [sx, sy] = pos(ev);
      this.moved = false;
      this.last = { x: sx, y: sy };
      const node = this._nodeAt(sx, sy);
      if (node) { this.dragNode = node; }
      else { this.panning = true; c.classList.add("grabbing"); }
    });

    window.addEventListener("mousemove", ev => {
      const [sx, sy] = pos(ev);
      if (this.dragNode) {
        const [wx, wy] = this._toWorld(sx, sy);
        this.dragNode.x = wx; this.dragNode.y = wy;
        this.dragNode.vx = this.dragNode.vy = 0;
        this.moved = true;
      } else if (this.panning) {
        this.tx += sx - this.last.x;
        this.ty += sy - this.last.y;
        this.last = { x: sx, y: sy };
        this.moved = true;
      } else {
        const node = this._nodeAt(sx, sy);
        this.hover = node;
        this._tooltip(node, ev);
      }
    });

    window.addEventListener("mouseup", () => {
      if (this.dragNode && !this.moved) this.onExpand(this.dragNode.id);
      this.dragNode = null;
      this.panning = false;
      c.classList.remove("grabbing");
    });

    c.addEventListener("wheel", ev => {
      ev.preventDefault();
      const [sx, sy] = pos(ev);
      const factor = ev.deltaY < 0 ? 1.1 : 0.9;
      const [wx, wy] = this._toWorld(sx, sy);
      this.scale = Math.max(0.1, Math.min(4, this.scale * factor));
      // keep the cursor anchored over the same world point
      this.tx = sx - wx * this.scale;
      this.ty = sy - wy * this.scale;
    }, { passive: false });

    c.addEventListener("contextmenu", ev => {
      const [sx, sy] = pos(ev);
      const node = this._nodeAt(sx, sy);
      if (!node) return;
      ev.preventDefault();
      node.fixed = !node.fixed;
    });
  }

  _tooltip(node, ev) {
    const tip = document.getElementById("tooltip");
    if (!node) { tip.classList.add("hidden"); return; }
    tip.innerHTML = `<div class="t-name">${escapeHtml(node.id)}</div>`
      + `<div class="t-type">${node.type}${node.high_value ? " • high-value" : ""}</div>`;
    tip.style.left = (ev.clientX + 14) + "px";
    tip.style.top = (ev.clientY + 14) + "px";
    tip.classList.remove("hidden");
  }
}

// ════════════════════════════════════════════════════════════════════════════════
//  App controller
// ════════════════════════════════════════════════════════════════════════════════
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function fmtPath(path) {
  // path: [[node, etype], ...]
  return path.map((step, i) => i === 0
    ? escapeHtml(step[0])
    : ` <span class="etype">─[${escapeHtml(step[1])}]→</span> ${escapeHtml(step[0])}`
  ).join("");
}

class App {
  constructor() {
    this.graph = new ForceGraph(document.getElementById("graph"), {
      onExpand: id => this.expand(id),
    });
    this.el = {
      queryType: document.getElementById("queryType"),
      primary: document.getElementById("primary"),
      primaryLabel: document.getElementById("primaryLabel"),
      secondary: document.getElementById("secondary"),
      secondaryField: document.getElementById("secondaryField"),
      hops: document.getElementById("hops"),
      hopsRow: document.getElementById("hopsRow"),
      exhaustive: document.getElementById("exhaustive"),
      run: document.getElementById("run"),
      results: document.getElementById("results"),
      stats: document.getElementById("stats"),
      overlay: document.getElementById("overlay"),
      nodeOptions: document.getElementById("nodeOptions"),
    };
    this._bind();
    this._loadStats();
    this._onTypeChange();
  }

  _bind() {
    this.el.run.addEventListener("click", () => this.run());
    this.el.queryType.addEventListener("change", () => this._onTypeChange());
    [this.el.primary, this.el.secondary].forEach(inp => {
      inp.addEventListener("input", () => this._autocomplete(inp.value));
      inp.addEventListener("keydown", e => { if (e.key === "Enter") this.run(); });
    });
    document.querySelectorAll("[data-quick]").forEach(b =>
      b.addEventListener("click", () => this.quick(b.dataset.quick)));
  }

  async _loadStats() {
    try {
      const s = await api("/api/stats");
      this.el.stats.textContent =
        `${s.nodes.toLocaleString()} nodes · ${s.edges.toLocaleString()} edges · ${s.backend}`;
    } catch (e) { this.el.stats.textContent = "stats unavailable"; }
  }

  _onTypeChange() {
    const t = this.el.queryType.value;
    const labels = {
      "reach-to": "Target node",
      "reach-from": "Source node",
      "path": "To node",
      "transitive": "Group",
      "neighborhood": "Node",
    };
    this.el.primaryLabel.textContent = labels[t];
    this.el.secondaryField.classList.toggle("hidden", t !== "path");
    const showHops = (t === "reach-to" || t === "reach-from" || t === "path" || t === "neighborhood");
    this.el.hopsRow.classList.toggle("hidden", !showHops);
  }

  async _autocomplete(q) {
    if (!q || q.length < 2) return;
    try {
      const { results } = await api("/api/search", { q, limit: 15 });
      this.el.nodeOptions.innerHTML = results.map(r => `<option value="${escapeHtml(r)}">`).join("");
    } catch (_) {}
  }

  _setResults(html) { this.el.results.innerHTML = html; }
  _error(msg) { this._setResults(`<p class="err">⚠ ${escapeHtml(msg)}</p>`); }
  _hideOverlay() { this.el.overlay.classList.add("hidden"); }

  async run() {
    const t = this.el.queryType.value;
    const primary = this.el.primary.value.trim();
    if (!primary) { this._error("Enter a node first."); return; }
    const hops = this.el.hops.value || 6;
    const exhaustive = this.el.exhaustive.checked ? 1 : "";
    try {
      if (t === "path") {
        const from = this.el.secondary.value.trim();
        if (!from) { this._error("Path needs both a From and a To node."); return; }
        await this.queryPath(from, primary, exhaustive, hops);
      } else if (t === "reach-to") {
        await this.queryReach(primary, "to", exhaustive, hops);
      } else if (t === "reach-from") {
        await this.queryReach(primary, "from", exhaustive, hops);
      } else if (t === "transitive") {
        await this.queryTransitive(primary);
      } else if (t === "neighborhood") {
        await this.expand(primary, hops, true);
      }
      this._hideOverlay();
    } catch (e) { this._error(e.message); }
  }

  async queryPath(from, to, exhaustive, hops) {
    const data = await api("/api/path", { from, to, exhaustive, hops });
    const hlEdges = [];
    (data.all.paths || []).forEach(p => {
      for (let i = 1; i < p.path.length; i++)
        hlEdges.push({ source: p.path[i - 1][0], target: p.path[i][0], etype: p.path[i][1] });
    });
    this.graph.setData(data.subgraph, {
      highlightEdges: hlEdges,
      highlightNodes: [from, to],
    });
    let html = "";
    const s = data.shortest;
    html += `<h3>Shortest path</h3>`;
    html += s.found
      ? `<div class="path">${fmtPath(s.path)}</div><p class="muted">${s.hops} hop(s) · ${s.elapsed_ms.toFixed(1)} ms</p>`
      : `<p class="muted">No path found.</p>`;
    const all = data.all;
    html += `<h3>All paths (${all.depth_label})</h3>`;
    if (!all.paths.length) html += `<p class="muted">None within bound.</p>`;
    all.paths.forEach((p, i) => {
      html += `<div class="path">[${i + 1}] (${p.hops} hops)<br>${fmtPath(p.path)}</div>`;
    });
    if (all.limit_reached) html += `<p class="muted">… limit ${all.max_paths} reached</p>`;
    this._setResults(html);
  }

  async queryReach(node, dir, exhaustive, hops) {
    const data = await api("/api/reach", { node, dir, exhaustive, hops });
    const r = data.reach;
    this.graph.setData(data.subgraph, { highlightNodes: [r.root] });
    const verb = dir === "to" ? "can reach" : "is reachable from";
    let html = `<h3>${escapeHtml(r.root)}</h3>`;
    html += `<p class="muted">${r.total} node(s) ${verb} this · ${r.elapsed_ms.toFixed(1)} ms`
      + `${r.exhaustive ? " · exhaustive" : " · ≤" + r.hops + " hops"}</p>`;
    const dists = Object.keys(r.by_distance).map(Number).sort((a, b) => a - b);
    dists.forEach(d => {
      const bucket = r.by_distance[d];
      html += `<h3>Hop ${d} <span class="muted">(${bucket.length})</span></h3><ul>`;
      bucket.slice(0, 50).forEach(n => html += `<li>${escapeHtml(n)}</li>`);
      if (bucket.length > 50) html += `<li class="muted">… and ${bucket.length - 50} more</li>`;
      html += `</ul>`;
    });
    this._setResults(html);
  }

  async queryTransitive(group) {
    const data = await api("/api/transitive", { group });
    const m = data.members;
    this.graph.setData(data.subgraph, { highlightNodes: [m.group] });
    let html = `<h3>${escapeHtml(m.group)}</h3>`;
    html += `<p class="muted">${m.members.length} effective member(s) · ${m.elapsed_ms.toFixed(1)} ms</p><ul>`;
    m.members.slice(0, 200).forEach(n => html += `<li>${escapeHtml(n)}</li>`);
    if (m.members.length > 200) html += `<li class="muted">… and ${m.members.length - 200} more</li>`;
    html += `</ul>`;
    this._setResults(html);
  }

  async expand(node, hops = 1, replace = false) {
    const data = await api("/api/graph", { focus: node, hops });
    if (!data.nodes || !data.nodes.length) {
      if (replace) this._error(`Node not found: ${node}`);
      return;
    }
    if (replace) this.graph.setData(data, {
      highlightNodes: [node.toUpperCase()],
      focusNode: node,
      fit: false,
    });
    else this.graph.merge(data);
    const existing = this.el.results.querySelector(".graph-status");
    if (existing) existing.remove();
    if (replace && data.truncated) {
      this.el.results.insertAdjacentHTML("afterbegin",
        `<p class="muted graph-status">Focused view: large neighborhood trimmed around ${escapeHtml(node.toUpperCase())}. Right-click nodes to pin them.</p>`);
    }
    this._hideOverlay();
  }

  async quick(kind) {
    if (kind === "reset") {
      this.graph.clear();
      this.el.overlay.classList.remove("hidden");
      this._setResults('<p class="muted">Graph cleared.</p>');
      return;
    }
    if (kind === "hvt") {
      const { targets } = await api("/api/hvt");
      let html = `<h3>High-value targets (${targets.length})</h3><ul>`;
      targets.forEach(t => html += `<li><a href="#" data-node="${escapeHtml(t)}">${escapeHtml(t)}</a></li>`);
      html += `</ul>`;
      this._setResults(html);
      this.el.results.querySelectorAll("a[data-node]").forEach(a =>
        a.addEventListener("click", ev => { ev.preventDefault(); this.expand(a.dataset.node, 1, true); }));
      return;
    }
    if (kind === "users") {
      const { users } = await api("/api/users");
      let html = `<h3>Users (${users.length})</h3>`;
      users.slice(0, 300).forEach(u => {
        const flags = u.flags.map(f => `<span class="pill flag">${escapeHtml(f)}</span>`).join("");
        html += `<div style="margin:4px 0"><a href="#" data-node="${escapeHtml(u.name)}">${escapeHtml(u.name)}</a> ${flags}</div>`;
      });
      this._setResults(html);
      this.el.results.querySelectorAll("a[data-node]").forEach(a =>
        a.addEventListener("click", ev => { ev.preventDefault(); this.expand(a.dataset.node, 1, true); }));
    }
  }
}

window.addEventListener("DOMContentLoaded", () => new App());
