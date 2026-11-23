"use strict";
/* Live execution console. All values come from the persisted job status API. */
(() => {
  const root = document.querySelector("#live-assessment");
  if (!root) return;
  const UI = window.SegCheckUI;
  const active = new Set(["queued", "running"]);
  const total = Number(root.dataset.total) || 1;
  const created = root.dataset.created ? new Date(root.dataset.created) : null;
  const HEADINGS = { completed: "Assessment completed", failed: "Assessment could not finish", cancelled: "Assessment cancelled", interrupted: "Assessment interrupted" };
  let finished = false, failures = 0, seen = 0, lastUpdate = null;
  const $ = selector => document.querySelector(selector);

  function stamp(date = new Date()) { return date.toLocaleTimeString([], { hour12: false }); }
  function log(text, tone = "") {
    const trace = $("#execution-trace");
    if (trace.firstElementChild?.classList.contains("t-dim") && trace.children.length === 1) trace.replaceChildren();
    const item = UI.el("li", tone, `[${stamp()}] ${text}`);
    trace.append(item); trace.scrollTop = trace.scrollHeight;
  }

  /* Plain words for each probe result: same glossary as the report (data-reasons on the page). */
  const page = document.querySelector("#live-assessment");
  let glossary = [];
  try { glossary = JSON.parse(page?.dataset.reasons || "[]"); } catch (error) { glossary = []; }
  const LOGGED = "blocked by the firewall (its log shows it)";
  function plain(reason) {
    if (String(reason || "").includes(LOGGED)) {
      return { label: "Blocked (logged)", text: "No reply, and the firewall's own log shows it blocked this attempt: blocked, and proven." };
    }
    const code = String(reason || "").split(";")[0].trim();
    const hit = glossary.find(([prefix]) => code.startsWith(prefix));
    return hit ? { label: hit[1], text: hit[2] } : { label: code.replace(/_/g, " "), text: "" };
  }

  function lanes(events, status) {
    const container = $("#lanes");
    container.replaceChildren();
    events.forEach((event, index) => {
      const lane = UI.el("div", `lane o-${event.observed}${index >= seen ? " just-landed" : ""}`);
      const bar = UI.el("span", "lane-bar"); const fill = UI.el("span"); bar.append(fill);
      lane.append(UI.el("span", "lane-idx", String(index + 1).padStart(2, "0")), UI.el("span", "lane-target", event.protocol === "icmp" ? `${event.host} · ICMP` : `${event.host}:${event.port}${event.protocol === "udp" ? "/udp" : ""}`),
        bar, UI.el("span", `chip chip-${event.observed}`, plain(event.reason).label), UI.el("span", "lane-ms", `${event.duration_ms} ms`),
        UI.el("span", "lane-reason", plain(event.reason).text || event.reason || ""));
      lane.title = event.reason || "";
      container.append(lane);
      const width = Math.max(3, Math.min(100, event.duration_ms / 1000 * 100));
      const apply = () => fill.style.setProperty("width", `${width}%`);
      if (index >= seen && !UI.reduced) setTimeout(apply, 60); else apply();
    });
    if (active.has(status)) {
      for (let index = events.length; index < total; index++) {
        const lane = UI.el("div", "lane is-pending");
        const bar = UI.el("span", "lane-bar"); bar.append(UI.el("span"));
        lane.append(UI.el("span", "lane-idx", String(index + 1).padStart(2, "0")), UI.el("span", "lane-target muted", index === events.length ? "connecting…" : "queued"),
          bar, UI.el("span", "chip chip-idle", "pending"), UI.el("span", "lane-ms", "—"));
        container.append(lane);
      }
    }
  }

  function blips(events) {
    const group = $("#radar-blips");
    group.replaceChildren();
    events.forEach((event, index) => {
      // One track at radius 100, between the counter in the middle and the progress ring: dots never cover the text.
      // Dot size follows the number of attempts so they stay apart (5 px for a few, down to 1.6 px for 400).
      const angle = (index / total) * Math.PI * 2 - Math.PI / 2;
      const radius = 100;
      const size = Math.max(1.6, Math.min(5, (Math.PI * radius / Math.max(1, total)) * 0.8));
      const open = event.observed === "reachable";
      const dot = UI.svg("circle", { cx: 130 + Math.cos(angle) * radius, cy: 130 + Math.sin(angle) * radius, r: open ? Math.min(6, size + 1.5) : size,
        fill: event.observed === "reachable" ? "#f0915f" : "#fbbf3c", class: "radar-blip" });
      dot.append(UI.svg("title", {}, `${event.host}:${event.port} · ${event.observed}`));
      group.append(dot);
    });
  }

  function elapsed(status) {
    if (!created) return;
    const end = active.has(status) ? new Date() : (lastUpdate || new Date());
    const seconds = Math.max(0, (end - created) / 1000);
    $("#elapsed").textContent = seconds < 60 ? `${seconds.toFixed(1)} s` : `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  }

  function render(data) {
    const status = data.status;
    lastUpdate = data.updated_at ? new Date(data.updated_at) : lastUpdate;
    $("#job-status").textContent = status.toUpperCase();
    $("#job-status").dataset.state = status;
    $("#job-status").className = `live-indicator chip ${status === "completed" ? "chip-pass" : active.has(status) ? "chip-info" : status === "cancelled" ? "chip-idle" : "chip-fail"}`;
    $("#job-heading").textContent = status === "failed" && String(data.message || "").startsWith("Stopped early")
      ? "Stopped early: fix the setup and run again" : (HEADINGS[status] || "Assessment in progress");
    if (status === "failed" && String(data.message || "").startsWith("Stopped early")) {
      $("#job-status").textContent = "Stopped";
      $("#job-status").className = "live-indicator chip chip-inconclusive";
    }
    $("#job-count").textContent = `${data.completed} / ${data.total}`;
    $("#job-progress").value = data.completed;
    $("#job-message").textContent = data.message;
    $("#radar-count").textContent = `${data.completed}/${data.total}`;
    $("#progress-ring").setAttribute("stroke-dashoffset", String(100 - data.completed / Math.max(1, data.total) * 100));
    $("#live-card").classList.toggle("is-running", active.has(status));
    UI.countTo($("#reachable-count"), data.events.filter(e => e.observed === "reachable").length, { duration: 400 });
    // Silence is split live: blocks the firewall logged (proven) and replies that are still missing (not proven yet).
    const silent = data.events.filter(e => e.observed === "inconclusive");
    const logged = silent.filter(e => String(e.reason || "").includes(LOGGED)).length;
    UI.countTo($("#logged-count"), logged, { duration: 400 });
    UI.countTo($("#inconclusive-count"), silent.length - logged, { duration: 400 });
    for (const event of data.events.slice(seen)) {
      log(`${(event.protocol || "tcp").toUpperCase()} ${event.host}${event.protocol === "icmp" ? "" : ":" + event.port} → ${plain(event.reason).label}: ${plain(event.reason).text || event.reason || ""} (${event.duration_ms} ms)`, event.observed === "reachable" ? "t-ok" : "t-warn");
    }
    lanes(data.events, status);
    blips(data.events);
    seen = data.events.length;
    elapsed(status);
    if (data.assessment_url) {
      const link = $("#completed-report");
      const url = new URL(data.assessment_url, window.location.origin);
      if (url.origin === window.location.origin) { link.href = url.href; link.hidden = false; }
    }
    $("#cancel-job").hidden = !active.has(status) || data.cancel_requested;
    if (!active.has(status) && !finished) log(`Run ${status}. ${data.message}`, status === "completed" ? "t-ok" : "t-err");
  }

  async function poll() {
    if (finished) return;
    if (document.hidden) { setTimeout(poll, 1500); return; }
    try {
      const response = await fetch(root.dataset.statusUrl, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (response.redirected || !response.headers.get("content-type")?.includes("application/json")) {
        finished = true;
        $("#job-status").textContent = "Signed out";
        $("#job-status").className = "live-indicator chip chip-idle";
        throw new Error("You were signed out (SegCheck restarted). Sign in again, then open History to see how this audit ended.");
      }
      if (!response.ok) throw new Error(`SegCheck answered with an error (${response.status}). Retrying automatically…`);
      const data = await response.json();
      failures = 0;
      render(data);
      finished = !active.has(data.status);
    } catch (error) {
      failures++;
      $("#job-message").textContent = error instanceof TypeError
        ? "SegCheck is not reachable right now (closed or restarting). Retrying automatically… If it was restarted, this audit stops and is shown as interrupted."
        : error.message;
    }
    if (!finished) setTimeout(poll, Math.min(8000, 700 * 2 ** failures));
  }

  // Server-rendered lanes: animate their bars once.
  for (const fill of document.querySelectorAll("#lanes .lane-bar > span")) fill.style.setProperty("width", "40%");
  setInterval(() => { if (!finished) elapsed("running"); }, 250);
  log("Console attached. Polling persisted job state.", "t-dim");
  poll();
})();
