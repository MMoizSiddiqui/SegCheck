"use strict";
/* Segmentation map: this PC on the left, target networks and hosts on the right, one line per host
   coloured by its result. Click a host for its rules; "Replay" plays the run's attempts in order.
   On the Overview, a run strip lets you step through past audits (data-runs-url).
   Runs under the app's CSP: no inline script or style, everything built with DOM APIs. */
(() => {
  const UI = window.SegCheckUI;
  if (!UI) return;
  const svg = (...args) => UI.svg(...args);
  const el = (...args) => UI.el(...args);
  const TONE_TEXT = { fail: "Failed", pass: "Passed", unproven: "No answer, not proven", skipped: "Not run" };
  const W = 900;

  function layout(run) {
    const zones = run.zones || [];
    const rows = zones.reduce((sum, zone) => sum + Math.max(1, Math.ceil(zone.hosts.length / 3)) + 1, 0);
    const H = Math.max(260, 60 + rows * 60);  // rows leave room for the "OPEN: …" label under a failing host
    const positions = {};
    let y = 30;
    const boxes = zones.map(zone => {
      const lines = Math.max(1, Math.ceil(zone.hosts.length / 3));
      const box = { zone, x: 520, y, w: 360, h: 46 + lines * 60 };
      zone.hosts.forEach((host, index) => {
        positions[host.ip] = { x: box.x + 60 + (index % 3) * 110, y: box.y + 52 + Math.floor(index / 3) * 60 };
      });
      y += box.h + 16;
      return box;
    });
    return { H: Math.max(H, y + 10), boxes, positions, pc: { x: 110, y: Math.max(H, y + 10) / 2 } };
  }

  function render(container, run) {
    container.replaceChildren();
    if (!run || !(run.zones || []).length) {
      container.append(el("p", "muted", "Nothing to show yet: run an audit and its map appears here."));
      return;
    }
    const { H, boxes, positions, pc } = layout(run);
    const toolbar = el("div", "segmap-toolbar");
    const replay = el("button", "ghost-button small-button", "▶ Replay attempts");
    replay.type = "button";
    const status = el("span", "segmap-status muted", `${run.attempts.length} attempts · click a host for its rules`);
    toolbar.append(replay, status);
    const map = svg("svg", { viewBox: `0 0 ${W} ${H}`, class: "segmap-svg", role: "img", "aria-label": `Map of audit ${run.id}` });
    const edges = svg("g"), nodes = svg("g"), packets = svg("g");
    map.append(edges, nodes, packets);
    const panel = el("div", "segmap-panel");
    panel.append(el("p", "muted", "Click a host to see what was tested there, what happened and why."));
    const legend = el("div", "segmap-legend");
    for (const tone of ["fail", "pass", "unproven", "skipped"]) {
      const item = el("span", `lg lg-${tone}`); item.append(el("i"), document.createTextNode(TONE_TEXT[tone])); legend.append(item);
    }
    // Alarm strip: what needs attention, before anyone reads the map.
    const hosts = (run.zones || []).flatMap(zone => zone.hosts);
    const openPorts = {};
    for (const attempt of run.attempts || []) {
      if (attempt.observed === "reachable") {
        const what = attempt.protocol === "icmp" ? "ping" : `${attempt.protocol.toUpperCase()} ${attempt.port}`;
        (openPorts[attempt.host] = openPorts[attempt.host] || []).push(what);
      }
    }
    const tally = tone => hosts.filter(host => host.tone === tone).length;
    const strip = el("div", "segmap-alerts");
    const open = tally("fail"), proven = tally("pass"), unproven = tally("unproven");
    if (open) strip.append(el("span", "alert-pill is-fail", `⚠ ${open} host${open === 1 ? "" : "s"} with an open path`));
    if (proven) strip.append(el("span", "alert-pill is-pass", `✓ ${proven} blocked and proven`));
    if (unproven) strip.append(el("span", "alert-pill is-unproven", `? ${unproven} not proven (no firewall log)`));
    if (!open && !unproven && proven) strip.append(el("span", "alert-pill is-calm", "All clear on every tested path"));
    container.append(strip, toolbar, map, legend, panel);

    // This PC
    const pcGroup = svg("g", { class: "segmap-pc" });
    pcGroup.append(svg("rect", { x: pc.x - 90, y: pc.y - 42, width: 180, height: 84, rx: 16 }),
      svg("text", { x: pc.x, y: pc.y - 14, "text-anchor": "middle", class: "segmap-tag" }, "THIS PC"),
      svg("text", { x: pc.x, y: pc.y + 6, "text-anchor": "middle", class: "segmap-title" }, (run.source_name || run.source_zone || "").slice(0, 22)),
      svg("text", { x: pc.x, y: pc.y + 26, "text-anchor": "middle", class: "segmap-sub" }, run.source_ip || ""));
    nodes.append(pcGroup);

    const lines = {}, dots = {};
    let selected = null;
    function select(host, zone) {
      if (selected) selected.classList.remove("is-selected");
      selected = dots[host.ip]; if (selected) selected.classList.add("is-selected");
      panel.replaceChildren();
      const head = el("div", "segmap-panel-head");
      head.append(el("strong", "mono", host.ip), el("span", `chip tone-chip tone-${host.tone}`, TONE_TEXT[host.tone]), el("span", "muted", `${zone.name || zone.key}${zone.role === "cde" ? " · CDE" : ""} ${zone.cidr ? "· " + zone.cidr : ""}`));
      panel.append(head);
      for (const rule of host.rules) {
        const card = el("div", `segmap-rule tone-${rule.tone}`);
        card.append(el("b", "", rule.name), el("div", "small", `${rule.service} · ${rule.expected} → ${rule.outcome}`), el("p", "small", rule.why));
        if (rule.fix) card.append(el("p", "small segmap-fix", "What to do: " + rule.fix));
        panel.append(card);
      }
      if (run.url && !location.pathname.startsWith(run.url)) {
        const link = el("a", "text-link", "Open the full report →"); link.href = run.url; panel.append(link);
      }
    }

    for (const box of boxes) {
      const zone = box.zone;
      const group = svg("g", { class: `segmap-zone${zone.role === "cde" ? " is-cde" : ""}` });
      group.append(svg("rect", { x: box.x, y: box.y, width: box.w, height: box.h, rx: 14 }),
        svg("text", { x: box.x + 14, y: box.y + 22, class: "segmap-tag" }, `${zone.role === "cde" ? "CDE · " : ""}${zone.name || zone.key}`.toUpperCase().slice(0, 34)),
        svg("text", { x: box.x + box.w - 14, y: box.y + 22, "text-anchor": "end", class: "segmap-sub" }, zone.cidr || ""));
      nodes.append(group);
      for (const host of zone.hosts) {
        const p = positions[host.ip];
        const midX = (pc.x + 90 + p.x) / 2;
        const path = svg("path", { d: `M${pc.x + 90},${pc.y} C${midX},${pc.y} ${midX},${p.y} ${p.x - 16},${p.y}`,
          class: `segmap-edge tone-${host.tone}${host.tone === "fail" ? " is-alarm" : ""}` });
        edges.append(path);
        lines[host.ip] = path;
        if (host.tone === "pass" || host.tone === "unproven") {
          // A short bar where the path meets the network's boundary: stopped there (proven when green).
          const length = path.getTotalLength();
          let point = path.getPointAtLength(length * 0.86);
          for (let t = 0.5; t <= 0.98; t += 0.01) { const q = path.getPointAtLength(length * t); if (q.x >= box.x - 6) { point = q; break; } }
          edges.append(svg("line", { x1: point.x, y1: point.y - 9, x2: point.x, y2: point.y + 9, class: `segmap-stop tone-${host.tone}` }));
        }
        const dot = svg("g", { class: `segmap-host tone-${host.tone}`, tabindex: "0", role: "button", "aria-label": `${host.ip}: ${TONE_TEXT[host.tone]}` });
        if (host.tone === "fail") {
          dot.append(svg("circle", { cx: p.x, cy: p.y, r: 14, class: "alarm-ring" }), svg("circle", { cx: p.x, cy: p.y, r: 14, class: "alarm-ring is-late" }));
        }
        dot.append(svg("circle", { cx: p.x, cy: p.y, r: 14 }), svg("text", { x: p.x, y: p.y + 30, "text-anchor": "middle", class: "segmap-ip" }, host.ip));
        const badge = { fail: "!", pass: "✓", unproven: "?" }[host.tone];
        if (badge) dot.append(svg("text", { x: p.x, y: p.y + 5, "text-anchor": "middle", class: `segmap-badge tone-${host.tone}` }, badge));
        if (host.tone === "fail" && openPorts[host.ip]) {
          const list = [...new Set(openPorts[host.ip])];
          dot.append(svg("text", { x: p.x, y: p.y + 45, "text-anchor": "middle", class: "segmap-open", fill: "#ff6b6b" },
            `OPEN: ${list.slice(0, 3).join(", ")}${list.length > 3 ? ` +${list.length - 3}` : ""}`));
        }
        dot.addEventListener("click", () => select(host, zone));
        dot.addEventListener("keydown", event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(host, zone); } });
        nodes.append(dot);
        dots[host.ip] = dot;
      }
    }
    const firstFail = boxes.flatMap(box => box.zone.hosts.map(host => [host, box.zone])).find(([host]) => host.tone === "fail");
    if (firstFail) select(...firstFail);

    // Replay: one moving dot per attempt, in the order they were sent.
    let playing = null;
    replay.addEventListener("click", () => {
      if (playing) { playing.stop(); return; }
      const attempts = run.attempts.filter(a => lines[a.host]);
      if (!attempts.length) return;
      for (const dot of Object.values(dots)) dot.classList.add("is-pending");
      container.classList.add("is-replaying");   // no red until the attempt that gets through is reached
      for (const node of container.querySelectorAll(".is-revealed")) node.classList.remove("is-revealed");
      const found = [];
      const step = Math.max(40, Math.min(450, 12000 / attempts.length));
      let index = 0, timer = null, stopped = false;
      const announced = new Set();
      replay.textContent = "■ Stop";
      status.classList.remove("is-alarm");
      const finish = () => {
        stopped = true; clearTimeout(timer); packets.replaceChildren();
        container.classList.remove("is-replaying");
        for (const dot of Object.values(dots)) dot.classList.remove("is-pending", "flash-reached", "flash-silent", "is-alerting");
        replay.textContent = "▶ Replay attempts"; playing = null;
        status.textContent = found.length
          ? `Replay finished: ${found.length} hole${found.length === 1 ? "" : "s"} found — ${found.slice(0, 4).join(" · ")}${found.length > 4 ? " …" : ""}`
          : `Replay finished: ${run.attempts.length} attempts, nothing got through`;
        status.classList.toggle("is-alarm", Boolean(found.length));
      };
      playing = { stop: finish };
      const next = () => {
        if (stopped) return;
        if (index >= attempts.length) { finish(); return; }
        const attempt = attempts[index++];
        const line = lines[attempt.host];
        const length = line.getTotalLength();
        const packet = svg("circle", { r: 5, class: `segmap-packet ${attempt.observed === "reachable" ? "is-reached" : "is-silent"}` });
        packets.append(packet);
        const started = performance.now();
        const duration = Math.max(180, step * 1.6);
        const move = now => {
          const t = Math.min(1, (now - started) / duration);
          const point = line.getPointAtLength(length * t);
          packet.setAttribute("cx", point.x); packet.setAttribute("cy", point.y);
          if (t < 1 && !stopped) requestAnimationFrame(move); else packet.remove();
        };
        requestAnimationFrame(move);
        const target = dots[attempt.host];
        target.classList.remove("is-pending");
        if (!target.classList.contains("tone-fail")) { target.classList.add("is-revealed"); line.classList.add("is-revealed"); }  // blocked hosts show their colour once tried
        target.classList.toggle("flash-silent", attempt.observed !== "reachable");
        const what = attempt.protocol === "icmp" ? "ping" : `${attempt.protocol.toUpperCase()} ${attempt.port}`;
        status.textContent = `Attempt ${index}/${attempts.length}: ${what} → ${attempt.host} · ${attempt.label}`;
        if (attempt.observed === "reachable" && !announced.has(`${attempt.host}|${what}`)) {
          announced.add(`${attempt.host}|${what}`);
          found.push(`${attempt.host} · ${what}`);
          target.classList.add("is-revealed", "is-alerting");
          line.classList.add("is-revealed");
          status.classList.add("is-alarm");
          if (UI.toast) UI.toast(`Hole found: ${attempt.host} answered on ${what}. Something that must be blocked got through.`, "error");
        }
        timer = setTimeout(next, step);
      };
      next();
    });
  }

  // A single run (report page).
  for (const container of document.querySelectorAll("[data-segmap]")) {
    try { render(container, JSON.parse(container.dataset.segmap)); } catch (error) { container.textContent = "The map could not be drawn."; }
  }

  // Overview: step through past runs.
  for (const shell of document.querySelectorAll("[data-runs-url]")) {
    const strip = el("div", "segmap-runs");
    const holder = el("div", "segmap");
    const controls = el("div", "segmap-toolbar");
    const prev = el("button", "ghost-button small-button", "◀ Older"); prev.type = "button";
    const nextButton = el("button", "ghost-button small-button", "Newer ▶"); nextButton.type = "button";
    const play = el("button", "ghost-button small-button", "▶ Play history"); play.type = "button";
    const label = el("span", "segmap-status muted", "");
    controls.append(prev, nextButton, play, label);
    shell.append(controls, strip, holder);
    let runs = [], current = -1, playing = null;
    async function show(index) {
      if (index < 0 || index >= runs.length) return;
      current = index;
      strip.querySelectorAll("button").forEach((button, i) => button.classList.toggle("is-current", i === index));
      const run = runs[index];
      label.textContent = `Audit #${run.id} · ${new Date(run.created_at).toLocaleString()} · ${run.verdict.word}`;
      try { render(holder, await UI.json(`${shell.dataset.runsUrl}/${run.id}/map`)); } catch (error) { holder.textContent = error.message; }
    }
    prev.addEventListener("click", () => show(current - 1));
    nextButton.addEventListener("click", () => show(current + 1));
    play.addEventListener("click", () => {
      if (playing) { clearInterval(playing); playing = null; play.textContent = "▶ Play history"; return; }
      play.textContent = "■ Stop"; show(0);
      playing = setInterval(() => { if (current >= runs.length - 1) { clearInterval(playing); playing = null; play.textContent = "▶ Play history"; } else show(current + 1); }, 2600);
    });
    UI.json(shell.dataset.runsUrl).then(data => {
      runs = data.runs || [];
      if (!runs.length) { holder.append(el("p", "muted", "No audits yet: run one and its map appears here.")); controls.hidden = true; return; }
      runs.forEach((run, i) => {
        const button = el("button", `segmap-run tone-${run.verdict.tone}`, `#${run.id}`); button.type = "button";
        button.title = `${run.name} · ${run.verdict.word}: ${run.verdict.title}`;
        button.addEventListener("click", () => show(i));
        strip.append(button);
      });
      show(runs.length - 1);
    }).catch(error => { holder.textContent = error.message; });
  }
})();
