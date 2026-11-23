"use strict";
/* Live overview: every value is read from /api/dashboard (saved data only). */
(() => {
  const sync = document.querySelector("#dashboard-sync");
  if (!sync) return;
  const UI = window.SegCheckUI;
  const svg = (...args) => UI.svg(...args);
  const el = (...args) => UI.el(...args);
  const KEYS = ["pass", "fail", "inconclusive", "not_exercised"];
  const LABEL = { pass: "Pass", fail: "Fail", inconclusive: "No answer", not_exercised: "Not exercised" };
  const signatures = {};
  const tooltip = document.querySelector("#viz-tooltip");
  /* Run after layout; falls back to a timer because rAF pauses in hidden tabs. */
  const later = fn => { let done = false; const run = () => { if (!done) { done = true; fn(); } }; requestAnimationFrame(() => requestAnimationFrame(run)); setTimeout(run, 120); };

  function changed(name, value) {
    const signature = JSON.stringify(value);
    if (signatures[name] === signature) return false;
    signatures[name] = signature;
    return true;
  }
  function tip(node, text) {
    node.addEventListener("mousemove", event => {
      tooltip.textContent = text;
      tooltip.style.setProperty("left", `${Math.min(event.clientX + 14, window.innerWidth - 290)}px`);
      tooltip.style.setProperty("top", `${event.clientY + 14}px`);
      tooltip.classList.add("show");
    });
    node.addEventListener("mouseleave", () => tooltip.classList.remove("show"));
  }

  /* ---- KPI sparklines ---- */
  function spark(id, values) {
    const node = document.querySelector(id);
    if (!node || !changed(id, values)) return;
    node.replaceChildren();
    if (values.length < 2) return;
    const max = Math.max(1, ...values);
    const step = 120 / (values.length - 1);
    const points = values.map((value, index) => `${(index * step).toFixed(1)},${(40 - value / max * 34).toFixed(1)}`);
    node.append(svg("path", { d: `M0,42 L${points.join(" L")} L120,42 Z`, class: "spark-area" }));
    const line = svg("path", { d: `M${points.join(" L")}`, class: "spark-line", pathLength: 100, "stroke-dasharray": "100", "stroke-dashoffset": UI.reduced ? 0 : 100 });
    node.append(line);
    if (!UI.reduced) later(() => { line.style.setProperty("transition", "stroke-dashoffset 1.2s ease"); line.setAttribute("stroke-dashoffset", 0); });
  }

  /* ---- Posture gauge (exercised checks only) ---- */
  function posture(outcomes) {
    if (!changed("posture", outcomes)) return;
    const exercised = outcomes.pass + outcomes.fail + outcomes.inconclusive;
    const rate = exercised ? outcomes.pass / exercised * 100 : 0;
    const gauge = document.querySelector("#gauge-value");
    gauge.setAttribute("stroke-dasharray", `${(rate * .75).toFixed(2)} 100`);
    gauge.classList.toggle("is-empty", !exercised || rate === 0);
    const number = document.querySelector("#gauge-number");
    if (exercised) UI.countTo(number, rate, { decimals: 0, suffix: "%" }); else number.textContent = "—";
    // Two short lines: one long line was cut off at the gauge's edges.
    document.querySelector("#gauge-sub").textContent = exercised ? `${outcomes.pass} of ${exercised} checks passed` : "no checks run yet";
    const sub2 = document.querySelector("#gauge-sub2");
    if (sub2) sub2.textContent = exercised ? `${outcomes.fail} failed · ${outcomes.inconclusive} no answer` : "";
    const legend = document.querySelector("#posture-legend");
    legend.replaceChildren();
    const total = KEYS.reduce((sum, key) => sum + outcomes[key], 0);
    for (const key of KEYS) {
      const row = el("div", "legend-row");
      row.append(el("span", `legend-swatch sw-${key}`), el("span", "", LABEL[key]), el("b", "", String(outcomes[key])));
      legend.append(row);
    }
    const bar = el("div", "stacked-bar");
    const segments = KEYS.map(key => { const span = el("span", `sw-${key}`); bar.append(span); return [span, key]; });
    legend.append(bar);
    later(() => segments.forEach(([span, key]) => span.style.setProperty("width", `${total ? outcomes[key] / total * 100 : 0}%`)));
  }

  /* ---- Saved outcome donut ---- */
  function donut(outcomes) {
    if (!changed("donut", outcomes)) return;
    const ring = document.querySelector("#outcomes-ring");
    const legend = document.querySelector("#outcomes-legend");
    ring.replaceChildren(svg("circle", { cx: 110, cy: 110, r: 82, class: "donut-base" }));
    legend.replaceChildren();
    const sum = KEYS.reduce((total, key) => total + outcomes[key], 0);
    let offset = 0;
    for (const key of KEYS) {
      const fraction = sum ? outcomes[key] / sum * 100 : 0;
      if (fraction) {
        const seg = svg("circle", { cx: 110, cy: 110, r: 82, class: `donut-seg donut-${key}`, pathLength: 100,
          "stroke-dasharray": UI.reduced ? `${fraction} ${100 - fraction}` : "0 100", "stroke-dashoffset": -offset, transform: "rotate(-90 110 110)" });
        seg.append(svg("title", {}, `${LABEL[key]}: ${outcomes[key]}`));
        ring.append(seg);
        if (!UI.reduced) later(() => seg.setAttribute("stroke-dasharray", `${fraction} ${100 - fraction}`));
      }
      offset += fraction;
      const row = el("div", "legend-row");
      row.append(el("span", `legend-swatch sw-${key}`), el("span", "", LABEL[key]), el("b", "", String(outcomes[key])));
      legend.append(row);
    }
    const label = svg("text", { x: 110, y: 116, "text-anchor": "middle", class: "gauge-number" }, "0");
    ring.append(label);
    UI.countTo(label, sum);
  }

  /* ---- Run history stacked bars ---- */
  function history(runs) {
    if (!changed("history", runs)) return;
    const chart = document.querySelector("#assessment-trend");
    if (!runs.length) return;
    chart.replaceChildren();
    const top = 20, bottom = 210, left = 44, width = 600;
    const totals = runs.map(run => KEYS.reduce((sum, key) => sum + (run.breakdown[key] || 0), 0));
    const max = Math.max(1, ...totals);
    const ticks = max <= 4 ? max : 4;
    for (let index = 0; index <= ticks; index++) {
      const y = bottom - (bottom - top) * index / ticks;
      chart.append(svg("line", { x1: left - 6, x2: left + width, y1: y, y2: y, class: "axis-line" }));
      chart.append(svg("text", { x: left - 12, y: y + 4, "text-anchor": "end", class: "axis-text" }, String(Math.round(max * index / ticks))));
    }
    const slot = width / Math.max(runs.length, 4);
    const barWidth = Math.min(46, slot * .62);
    runs.forEach((run, index) => {
      let y = bottom;
      const x = left + slot * index + (slot - barWidth) / 2;
      const group = svg("a", { href: run.url });
      for (const key of KEYS) {
        const value = run.breakdown[key] || 0;
        if (!value) continue;
        const height = value / max * (bottom - top);
        const rect = svg("rect", { x, y: UI.reduced ? y - height : bottom, width: barWidth, height: UI.reduced ? height : 0, rx: 4, class: `bar bar-${key}` });
        group.append(rect);
        const finalY = y - height;
        if (!UI.reduced) setTimeout(() => { rect.setAttribute("y", finalY); rect.setAttribute("height", Math.max(0, height - 1.5)); }, 40 + index * 45);
        y -= height;
      }
      const when = run.created_at ? new Date(run.created_at).toLocaleString() : "";
      tip(group, `#${run.id} · ${run.policy}\n${run.source_zone} · ${when}\nPass ${run.breakdown.pass} · Fail ${run.breakdown.fail} · No answer ${run.breakdown.inconclusive} · Not exercised ${run.breakdown.not_exercised}${run.duration_ms != null ? ` · ${run.duration_ms} ms` : ""}`);
      chart.append(group);
      chart.append(svg("text", { x: x + barWidth / 2, y: bottom + 20, "text-anchor": "middle", class: "axis-text" }, `#${run.id}`));
    });
  }

  /* ---- Topology ---- */
  function topology(data) {
    const insights = data.insights;
    const model = { zones: data.zones, source: data.source_zone, ip: data.source_ip, edges: insights.edges, roles: data.roles };
    if (!changed("topology", model) || !data.zones.length) return;
    const map = document.querySelector("#network-map");
    map.replaceChildren();
    const H = 360;
    const probe = { x: 78, y: H / 2 };
    const positions = {};
    const sourceKey = data.source_zone;
    const others = data.zones.filter(zone => zone.key !== sourceKey);
    if (data.zones.some(zone => zone.key === sourceKey)) positions[sourceKey] = { x: 300, y: H / 2 };
    const columns = others.length > 4 ? 2 : 1;
    const perColumn = Math.ceil(others.length / columns) || 1;
    others.forEach((zone, index) => {
      const column = Math.floor(index / perColumn);
      const row = index % perColumn;
      const count = Math.min(perColumn, others.length - column * perColumn);
      const x = columns === 1 ? 700 : 545 + column * 235;  // second column ends at 880 (< 900 viewBox)
      const y = count === 1 ? H / 2 : 55 + row * ((H - 110) / (count - 1));
      positions[zone.key] = { x, y };
    });

    for (const radius of [110, 220, 330]) map.append(svg("circle", { cx: probe.x, cy: probe.y, r: radius, class: "topo-ring" }));
    const edgeLayer = svg("g"), nodeLayer = svg("g");
    map.append(edgeLayer, nodeLayer);

    const curve = (a, b) => {
      const mid = (a.x + b.x) / 2;
      return `M${a.x + 100},${a.y} C${mid},${a.y} ${mid},${b.y} ${b.x - 100},${b.y}`;
    };
    let pathIndex = 0;
    function packets(pathId, status) {
      if (UI.reduced) return;
      for (const delay of [0, 1.1]) {
        const dot = svg("circle", { r: 3.5, class: `packet-${status}` });
        const motion = svg("animateMotion", { dur: status === "fail" ? "1.6s" : "2.4s", repeatCount: "indefinite", begin: `${delay}s` });
        motion.append(svg("mpath", { href: `#${pathId}` }));
        dot.append(motion);
        edgeLayer.append(dot);
      }
    }
    // Probe → declared source zone.
    if (positions[sourceKey]) {
      const id = `edge-${pathIndex++}`;
      edgeLayer.append(svg("path", { id, d: `M${probe.x + 34},${probe.y} L${positions[sourceKey].x - 100},${positions[sourceKey].y}`, class: "topo-edge flow edge-pass" }));
    }
    const drawn = new Set();
    for (const edge of insights.edges) {
      const a = positions[edge.source], b = positions[edge.destination];
      if (!a || !b) continue;
      const id = `edge-${pathIndex++}`;
      let d;
      if (edge.source === edge.destination) d = `M${a.x - 40},${a.y - 38} C${a.x - 70},${a.y - 120} ${a.x + 70},${a.y - 120} ${a.x + 40},${a.y - 38}`;
      else d = curve(a, b);
      const path = svg("path", { id, d, class: `topo-edge flow edge-${edge.status}` });
      tip(path, `${edge.source} → ${edge.destination}${edge.cde ? " (CDE)" : ""}\nLatest: ${edge.pass} pass · ${edge.fail} fail · ${edge.inconclusive} inconclusive\nAssessment #${edge.assessment_id} · ${UI.relative(edge.last_tested)}`);
      edgeLayer.append(path);
      packets(id, edge.status);
      drawn.add(`${edge.source}>${edge.destination}`);
    }
    if (positions[sourceKey]) {
      for (const zone of others) {
        if (drawn.has(`${sourceKey}>${zone.key}`)) continue;
        const path = svg("path", { d: curve(positions[sourceKey], positions[zone.key]), class: "topo-edge edge-planned" });
        tip(path, `${sourceKey} → ${zone.key}: no saved test from this probe yet`);
        edgeLayer.append(path);
      }
    }

    // Probe node.
    const probeGroup = svg("g", { class: "topo-probe" });
    probeGroup.append(svg("circle", { cx: probe.x, cy: probe.y, r: 30, class: "probe-ring" }), svg("circle", { cx: probe.x, cy: probe.y, r: 30, class: "probe-ring r2" }),
      svg("circle", { cx: probe.x, cy: probe.y, r: 30, class: "probe-core" }),
      svg("text", { x: probe.x, y: probe.y + 4, "text-anchor": "middle", class: "node-title" }, "PROBE"),
      svg("text", { x: probe.x, y: probe.y + 54, "text-anchor": "middle", class: "node-sub" }, data.source_ip));
    tip(probeGroup, `This PC (probe) ${data.source_ip}\nDeclared zone: ${data.source_zone}\nAttempts leave from this PC's network position.`);
    nodeLayer.append(probeGroup);

    for (const zone of data.zones) {
      const position = positions[zone.key];
      if (!position) continue;
      const role = (data.roles || {})[zone.key] || "custom";
      const group = svg("g", { class: `topo-node${role === "cde" ? " is-cde" : ""}${zone.key === sourceKey ? " is-source" : ""}` });
      group.append(svg("rect", { x: position.x - 100, y: position.y - 38, width: 200, height: 76, rx: 14 }),
        svg("text", { x: position.x - 86, y: position.y - 15, class: "node-tag" }, role === "cde" ? "CDE · IN SCOPE" : zone.key === sourceKey ? "PROBE ZONE" : role.toUpperCase()),
        svg("text", { x: position.x - 86, y: position.y + 4, class: "node-title" }, zone.name.length > 21 ? zone.name.slice(0, 20) + "…" : zone.name),
        svg("text", { x: position.x - 86, y: position.y + 22, class: "node-sub" }, `${zone.cidr || zone.key} · ${zone.assets} asset${zone.assets === 1 ? "" : "s"}`));
      tip(group, `${zone.name} (${zone.key})\nRole: ${role}\nSubnet: ${zone.cidr || "not set"}\n${zone.assets} registered assets`);
      nodeLayer.append(group);
    }
  }

  /* ---- PCI coverage ---- */
  function pci(data) {
    const info = data.insights.pci;
    if (!changed("pci", { info, controls: data.insights.controls })) return;
    document.querySelector("#pci-cde-chip").textContent = `CDE zones: ${info.cde_zones.length ? info.cde_zones.join(", ") : "none"}`;
    const foot = document.querySelector("#kpi-cde-foot");
    if (foot) foot.textContent = `${info.cde_zones.length} CDE · ${info.out_of_scope_zones.length} out-of-scope`;
    const total = info.out_of_scope_zones.length;
    const tested = info.tested_sources.filter(item => info.out_of_scope_zones.includes(item.zone)).length;
    const percent = total ? tested / total * 100 : 0;
    later(() => document.querySelector("#pci-meter").style.setProperty("width", `${percent}%`));
    document.querySelector("#pci-meter-label").textContent = info.cde_zones.length
      ? `${tested} of ${total} out-of-scope zones exercised against the CDE · ${info.cde_checks_active} CDE checks`
      : "Add a target network of kind 'Card data environment' in New audit, Step 2.";
    const list = document.querySelector("#pci-sources");
    list.replaceChildren();
    const testedMap = Object.fromEntries(info.tested_sources.map(item => [item.zone, item.last_tested]));
    for (const zone of info.out_of_scope_zones) {
      const item = el("li", "coverage-item");
      const name = el("span"); name.append(el("span", "zone-name", zone), el("span", "muted small", info.planned_sources.includes(zone) ? " · CDE checks defined" : " · no CDE checks defined"));
      const chip = el("span", `chip ${testedMap[zone] ? "chip-pass" : "chip-idle"}`, testedMap[zone] ? `exercised ${UI.relative(testedMap[zone])}` : "not exercised");
      item.append(name, chip); list.append(item);
    }
    const bars = document.querySelector("#control-bars");
    bars.replaceChildren();
    const max = Math.max(1, ...data.insights.controls.map(control => control.checks));
    if (!data.insights.controls.length) bars.append(el("p", "muted small", "No mapped controls yet: run an audit with a standard."));
    for (const control of data.insights.controls) {
      const row = el("div", "control-bar");
      const meter = el("div", "coverage-meter"); const fill = el("span"); meter.append(fill);
      row.append(el("span", "mono", control.label.replace("pci_dss", "PCI DSS").replace("nist_sp800_53", "NIST 800-53").replace("iso27002", "ISO 27002")), meter, el("b", "", String(control.checks)));
      bars.append(row);
      later(() => fill.style.setProperty("width", `${control.checks / max * 100}%`));
    }
  }

  function activity(items) {
    if (!changed("activity", items)) return;
    const feed = document.querySelector("#activity-feed");
    feed.replaceChildren();
    if (!items.length) { const li = el("li", "s-idle"); li.append(el("span", "muted", "No runs yet."), el("span")); feed.append(li); return; }
    for (const job of items) {
      const li = el("li", `s-${job.status}`);
      const link = el("a", "", `Run #${job.id} · ${job.status}`); link.href = job.assessment_id ? `/assessments/${job.assessment_id}` : job.url;
      const meta = el("small", "", `${job.completed}/${job.total} · ${UI.relative(job.updated_at)}`);
      const chip = el("span", `chip ${job.status === "completed" ? "chip-pass" : ["running", "queued"].includes(job.status) ? "chip-info" : job.status === "cancelled" ? "chip-idle" : "chip-fail"}`, job.status);
      const left = el("span"); left.append(link, el("br"), meta);
      li.append(left, chip); feed.append(li);
    }
  }

  /* ---- Check results card: total, a live proportion bar and the legend ---- */
  function results(totals) {
    const bar = document.querySelector("[data-results-bar]");
    if (!bar) return;
    const value = (key) => Number(totals[key] ?? bar.dataset[key]) || 0;
    const fail = value("fail"), pass = value("pass"), inconclusive = value("inconclusive");
    const sum = Math.max(1, fail + pass + inconclusive);
    bar.querySelector(".seg-fail").style.width = `${fail / sum * 100}%`;
    bar.querySelector(".seg-pass").style.width = `${pass / sum * 100}%`;
    bar.querySelector(".seg-inconclusive").style.width = `${inconclusive / sum * 100}%`;
    bar.setAttribute("aria-label", `${fail} failed, ${pass} passed, ${inconclusive} no answer`);
    const total = document.querySelector('[data-results="total"]');
    if (total && totals.total !== undefined) UI.countTo(total, Number(totals.total) || 0);
    const foot = document.querySelector("[data-results-foot]");
    if (foot) {
      const [f, p, i] = foot.querySelectorAll("b");
      f.textContent = fail; p.textContent = pass; i.textContent = inconclusive;
    }
  }
  results({});

  async function poll() {
    if (document.hidden) { setTimeout(poll, 5000); return; }
    try {
      const data = await UI.json("/api/dashboard");
      for (const node of document.querySelectorAll("[data-metric]")) UI.countTo(node, Number(data.metrics[node.dataset.metric]) || 0);
      results(data.results || {});
      const insights = data.insights;
      posture(insights.outcomes);
      donut(insights.outcomes);
      history(insights.runs);
      pci(data);
      activity(insights.activity);
      spark("#spark-runs", insights.runs.map(run => KEYS.reduce((sum, key) => sum + (run.breakdown[key] || 0), 0)));
      spark("#spark-fail", insights.runs.map(run => run.breakdown.fail || 0));
      const run = document.querySelector("#active-run-link");
      run.hidden = !data.active_job;
      if (data.active_job) { run.href = data.active_job.url; run.textContent = `Live run #${data.active_job.id} · ${data.active_job.completed}/${data.active_job.total}`; }
      sync.textContent = "Workspace data refreshed " + new Date().toLocaleTimeString();
    } catch (error) { sync.textContent = error.message; }
    setTimeout(poll, 5000);
  }
  poll();
})();
