/* New audit page: small helpers only; every form also works without JavaScript. */
(() => {
  const page = document.querySelector("#audit");
  if (!page) return;
  const csrf = () => (document.querySelector('input[name="csrf_token"]') || {}).value || "";

  /* Step 1: choosing a detected network fills in the address fields. */
  const hereForm = page.querySelector("[data-here-form]");
  if (hereForm) {
    hereForm.querySelectorAll('input[name="pick"]').forEach((radio) => {
      radio.addEventListener("change", () => {
        for (const key of ["ip", "cidr", "gateway"]) {
          const field = hereForm.querySelector(`[data-field="${key}"]`);
          if (field) field.value = radio.dataset[key] || "";
        }
      });
    });
  }

  /* Step 2: more target rows. */
  const rows = page.querySelector("[data-rows]");
  const addRow = page.querySelector("[data-add-row]");
  if (rows && addRow) {
    addRow.addEventListener("click", () => {
      const all = rows.querySelectorAll("[data-row]");
      if (all.length >= 20) return;
      const copy = all[all.length - 1].cloneNode(true);
      copy.querySelectorAll("input").forEach((input) => { input.value = ""; });
      rows.appendChild(copy);
      copy.querySelector("input").focus();
    });
  }

  /* Step 2: discovery (known hosts and ping sweep). */
  page.querySelectorAll("[data-target]").forEach((card) => {
    const form = card.querySelector("[data-found]");
    const list = card.querySelector("[data-found-list]");
    const status = card.querySelector("[data-discover-status]");
    const foundStatus = card.querySelector("[data-found-status]");
    const known = new Set([...card.querySelectorAll(".host-chip .mono")].map((el) => el.textContent.trim()));

    function show(result, how) {
      list.replaceChildren();
      const hosts = (result.hosts || []).filter((host) => !known.has(host.address));
      if (!hosts.length) {
        form.hidden = true;
        status.textContent = how === "sweep"
          ? `Nothing new answered in ${result.network} (${result.pinged} addresses pinged). A firewall may block ping: type the hosts below.`
          : "This PC does not know any other host in this network yet. Try a ping sweep, or type the hosts below.";
        return;
      }
      for (const host of hosts) {
        const label = document.createElement("label");
        label.className = "found-host";
        const box = document.createElement("input");
        box.type = "checkbox"; box.name = "hosts"; box.value = host.address;
        box.checked = !card.classList.contains("own-network");  // own network: pick only what you mean to test
        const ip = document.createElement("span"); ip.className = "mono"; ip.textContent = host.address;
        const info = document.createElement("small");
        info.textContent = [host.name, host.seen].filter(Boolean).join(" · ");
        label.append(box, ip, info);
        if (host.name) {
          const forName = document.createElement("input"); forName.type = "hidden"; forName.name = "host_for_name"; forName.value = host.address;
          const name = document.createElement("input"); name.type = "hidden"; name.name = "host_name"; name.value = host.name.slice(0, 150);
          label.append(forName, name);
        }
        list.appendChild(label);
      }
      foundStatus.textContent = card.classList.contains("own-network")
        ? `${hosts.length} host(s) found in your own network. Tick only the ones you want to test (e.g. the router).`
        : `${hosts.length} host(s) found. Untick any you do not want to test.`;
      status.textContent = "";
      form.hidden = false;
    }

    async function run(url, options, how, button) {
      button.disabled = true;
      status.textContent = how === "sweep" ? "Pinging every address (up to about 15 seconds)…" : "Reading what this PC already knows…";
      try {
        const response = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" }, ...options });
        const data = await response.json();
        if (!response.ok) { status.textContent = data.error || "That did not work. Type the hosts below instead."; return; }
        show(data, how);
      } catch (error) {
        status.textContent = "SegCheck did not answer. Is the black SegCheck window still open?";
      } finally {
        button.disabled = false;
      }
    }

    card.querySelector("[data-known]").addEventListener("click", (event) =>
      run(card.dataset.knownUrl, {}, "known", event.currentTarget));
    card.querySelector("[data-sweep]").addEventListener("click", (event) => {
      if (!card.querySelector("[data-sweep-ok]").checked) {
        status.textContent = "Tick the box first: a ping sweep sends one ping to every address of this network.";
        return;
      }
      const body = new URLSearchParams({ csrf_token: csrf(), authorized: "yes" });
      run(card.dataset.sweepUrl, { method: "POST", body, headers: { Accept: "application/json", "X-CSRFToken": csrf() } }, "sweep", event.currentTarget);
    });
  });

  /* Step 3: show firewall details only when there is a firewall. */
  const fwForm = page.querySelector("[data-firewall-form]");
  if (fwForm) {
    const details = fwForm.querySelector("[data-firewall-details]");
    const sync = () => { details.hidden = (fwForm.querySelector('input[name="mode"]:checked') || {}).value !== "firewall"; };
    fwForm.querySelectorAll('input[name="mode"]').forEach((radio) => radio.addEventListener("change", sync));
    sync();
  }

  /* Step 3: live log status. */
  const live = page.querySelector(".firewall-live");
  if (live) {
    const refresh = async () => {
      try {
        const response = await fetch(page.dataset.statusUrl, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
        if (response.ok) {
          const state = (await response.json())[live.dataset.device];
          if (state) {
            const chip = live.querySelector(".device-state");
            chip.className = "chip device-state " + (state.connected ? "chip-pass" : state.listening ? "chip-inconclusive" : "chip-fail");
            chip.textContent = state.error || (state.connected ? "Logs arriving" : state.listening ? "Listening, waiting for the first log" : "Not listening yet");
            live.querySelector(".device-count").textContent = state.parsed;
            const learned = live.querySelector("[data-learned]");
            if (state.learned_sender) { learned.hidden = false; learned.querySelector("[data-learned-ip]").textContent = state.learned_sender; }
            const advice = live.querySelector(".device-advice");
            advice.replaceChildren(...(state.advice || []).map((tip) => { const li = document.createElement("li"); li.textContent = tip; return li; }));
            advice.hidden = !(state.advice || []).length;
          }
        }
      } catch (error) { /* best effort */ }
      setTimeout(refresh, 4000);
    };
    refresh();
  }

  /* Step 4: standard / own rules, attempt counter, rule rows. */
  const launch = page.querySelector("[data-launch-form]");
  if (launch) {
    const max = Number(launch.dataset.max);
    const out = launch.querySelector("[data-attempts]");
    const eta = launch.querySelector("[data-eta]");
    const mode = () => (launch.querySelector('input[name="mode"]:checked') || {}).value;

    const standardPreview = launch.querySelector('[data-send-preview="standard"]');
    function line(strong, rest) {
      const item = document.createElement("li");
      const b = document.createElement("b"); b.textContent = strong;
      item.append(b, document.createTextNode(rest));
      return item;
    }
    /* Counting what a rule will send (same rules as the server: ranges, subnets, port ranges). */
    function ipToInt(ip) { const p = ip.split(".").map(Number); return p.length === 4 && p.every((n) => n >= 0 && n <= 255) ? ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3] : NaN; }
    function countAddresses(text) {
      let total = 0;
      for (const token of text.split(/[\s,;]+/).filter(Boolean)) {
        if (token.includes("/")) { const bits = 32 - Number(token.split("/")[1]); const size = 2 ** bits; total += size > 2 ? size - 2 : size; }
        else if (token.includes("-")) {
          const [first, last] = token.split("-");
          const end = last.includes(".") ? last : first.split(".").slice(0, 3).concat(last).join(".");
          const span = ipToInt(end) - ipToInt(first) + 1;
          total += Number.isFinite(span) && span > 0 ? span : 0;
        } else total += 1;
      }
      return total;
    }
    function countPorts(text) {
      let total = 0;
      for (const token of text.split(/[\s,;]+/).filter(Boolean)) {
        if (token.includes("-")) { const [x, y] = token.split("-").map(Number); total += y >= x ? y - x + 1 : 0; } else total += 1;
      }
      return total;
    }
    function rulePreview(row) {
      const target = row.querySelector('[name="r_target"]').selectedOptions[0];
      const service = row.querySelector('[name="r_service"]').selectedOptions[0];
      const typed = row.querySelector('[name="r_targets"]').value.trim();
      const preview = row.querySelector("[data-rule-preview]");
      const hosts = target?.value === "text" ? countAddresses(typed) : Number(target?.dataset.count || 0);
      const toText = target?.value === "text" ? (typed ? `${hosts} typed address(es)` : "the addresses you type") : (target?.dataset.label || "?");
      let proto = service?.dataset.proto || "", portsText = service?.dataset.ports || "";
      if (service?.value === "custom") { proto = row.querySelector('[name="r_protocol"]').value; portsText = row.querySelector('[name="r_ports"]').value; }
      const each = proto === "icmp" ? 1 : countPorts(portsText);
      const must = row.querySelector('[name="r_must"]').value === "deny" ? "must NOT answer" : "must answer";
      const what = proto === "icmp" ? "1 ping" : each ? `${proto.toUpperCase()} ${portsText}` : `${proto.toUpperCase()} (type the ports)`;
      if (preview) preview.textContent = `Sends ${what} to ${toText} → ${each * hosts} attempt(s); ${must}.`;
      return each * hosts;
    }
    function count() {
      launch.querySelectorAll("[data-mode-panel]").forEach((panel) => { panel.hidden = panel.dataset.modePanel !== mode(); });
      if (mode() === "custom") {
        const total = [...launch.querySelectorAll("[data-rule-row]")].reduce((sum, row) => sum + rulePreview(row), 0);
        out.textContent = String(total);
        out.classList.toggle("is-over", total > max || !total);
        eta.textContent = total > max ? `Too many: the limit is ${max}.` : total ? `at most ${Math.ceil(total / 60)} min` : "Add a rule with ports.";
        return;
      }
      const pack = launch.querySelector('input[name="pack"]:checked');
      if (!pack) { out.textContent = "–"; eta.textContent = "Choose a standard."; return; }
      const ticked = new Set([...launch.querySelectorAll('input[name="groups"]:checked')].map((box) => box.value));
      const card = pack.closest(".pack-card");
      let perTarget = 0;
      card.querySelectorAll("[data-group]").forEach((g) => { if (ticked.has(g.dataset.group)) perTarget += Number(g.dataset.cost); });
      const total = perTarget * Number(pack.dataset.targets || 0);
      out.textContent = String(total);
      if (standardPreview) {
        standardPreview.replaceChildren();
        const title = document.createElement("p");
        title.className = "send-title";
        title.textContent = `What will be sent to ${pack.dataset.targetList || "the targets"}:`;
        const list = document.createElement("ul");
        card.querySelectorAll("[data-group]").forEach((g) => {
          if (ticked.has(g.dataset.group)) list.append(line(g.dataset.label, ` · ${g.dataset.detail} (${g.dataset.cost} per host)`));
        });
        standardPreview.append(title, list);
      }
      if (!perTarget) eta.textContent = "Tick at least one probe this standard uses.";
      else if (total > max) eta.textContent = `Too many: the limit is ${max}. Untick some probes or remove hosts.`;
      else eta.textContent = `at most ${Math.ceil(total / 60)} min`;
      out.classList.toggle("is-over", total > max || !perTarget);
    }
    launch.addEventListener("change", count);
    if (!launch.querySelector('input[name="pack"]:not([disabled])')) {
      const custom = launch.querySelector('input[name="mode"][value="custom"]');
      if (custom) custom.checked = true;  // no standard fits (e.g. only hosts in this PC's own network)
    }
    count();

    const ruleRows = launch.querySelector("[data-rule-rows]");
    const panel = launch.querySelector('[data-mode-panel="custom"]');
    const csvStatus = launch.querySelector("[data-csv-status]");
    const wireRule = (row) => {
      const service = row.querySelector("[data-service]");
      const ports = row.querySelector("[data-custom-ports]");
      const target = row.querySelector("[data-target-select]");
      const typed = row.querySelector("[data-typed-targets]");
      const sync = () => { ports.hidden = service.value !== "custom"; typed.hidden = target.value !== "text"; };
      service.addEventListener("change", () => { sync(); count(); });
      target.addEventListener("change", () => { sync(); if (!typed.hidden) typed.focus(); count(); });
      row.addEventListener("input", count);
      row.querySelector("[data-remove-rule]").addEventListener("click", () => {
        if (ruleRows.querySelectorAll("[data-rule-row]").length > 1) { row.remove(); count(); }
      });
      sync();
    };
    function newRow() {
      const all = ruleRows.querySelectorAll("[data-rule-row]");
      const copy = all[all.length - 1].cloneNode(true);
      copy.querySelectorAll("input").forEach((input) => { if (input.type !== "file") input.value = ""; });
      copy.querySelectorAll("select").forEach((select) => { select.selectedIndex = 0; });
      ruleRows.appendChild(copy);
      wireRule(copy);
      return copy;
    }
    ruleRows.querySelectorAll("[data-rule-row]").forEach(wireRule);
    launch.querySelector("[data-add-rule]").addEventListener("click", () => {
      if (ruleRows.querySelectorAll("[data-rule-row]").length >= 100) return;
      newRow(); count();
    });

    /* CSV: from, to, service, protocol, ports, must, reason (the client's access matrix). */
    function parseCsv(text) {
      const rows = []; let row = [], field = "", quoted = false;
      for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (quoted) {
          if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (ch === '"') quoted = false; else field += ch;
        } else if (ch === '"') quoted = true;
        else if (ch === "," || ch === ";") { row.push(field.trim()); field = ""; }
        else if (ch === "\n" || ch === "\r") { if (ch === "\r" && text[i + 1] === "\n") i++; row.push(field.trim()); rows.push(row); row = []; field = ""; }
        else field += ch;
      }
      if (field || row.length) { row.push(field.trim()); rows.push(row); }
      return rows.filter((r) => r.some(Boolean));
    }
    const csvCell = (value) => /[",;\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
    function serviceKey(value) {
      const v = (value || "").trim().toLowerCase();
      const select = ruleRows.querySelector("[data-service]");
      const hit = [...select.options].find((o) => o.value.toLowerCase() === v || o.textContent.trim().toLowerCase() === v
        || o.textContent.trim().toLowerCase().startsWith(v + " ") || o.textContent.trim().toLowerCase().startsWith(v + " ("));
      return hit ? hit.value : "custom";
    }
    function mustValue(value) {
      const v = (value || "").trim().toLowerCase();
      return ["work", "works", "allow", "allowed", "approved", "yes", "open", "must work"].includes(v) ? "allow" : "deny";
    }
    launch.querySelector("[data-load-csv]").addEventListener("change", async (event) => {
      const file = event.target.files[0];
      if (!file) return;
      const rows = parseCsv(await file.text());
      event.target.value = "";
      if (!rows.length) { csvStatus.textContent = "That file is empty."; return; }
      const header = rows[0].map((h) => h.toLowerCase());
      const col = (name) => header.indexOf(name);
      if (col("to") < 0 || (col("service") < 0 && col("ports") < 0)) {
        csvStatus.textContent = "The first line must name the columns: from, to, service, protocol, ports, must, reason (download the example).";
        return;
      }
      const here = [panel.dataset.hereName, panel.dataset.hereKey].map((v) => (v || "").toLowerCase());
      const mine = [], others = [];
      for (const r of rows.slice(1)) {
        const from = (r[col("from")] || "").trim().toLowerCase();
        (col("from") < 0 || !from || ["*", "any", "all"].includes(from) || here.includes(from) ? mine : others).push(r);
      }
      if (!mine.length) { csvStatus.textContent = `No rows for this network (${panel.dataset.hereName}); ${others.length} row(s) are for other departments.`; return; }
      ruleRows.querySelectorAll("[data-rule-row]").forEach((row, index) => { if (index > 0) row.remove(); });
      mine.slice(0, 100).forEach((r, index) => {
        const row = index === 0 ? ruleRows.querySelector("[data-rule-row]") : newRow();
        const target = row.querySelector("[data-target-select]");
        const to = (r[col("to")] || "").trim();
        const single = [...target.options].find((o) => o.dataset.addresses === to && !o.value.startsWith("net:"));
        target.value = single ? single.value : "text";
        row.querySelector("[data-typed-targets]").value = single ? "" : to;
        const service = row.querySelector("[data-service]");
        const ports = col("ports") >= 0 ? (r[col("ports")] || "") : "";
        service.value = col("service") >= 0 && r[col("service")] ? serviceKey(r[col("service")]) : "custom";
        if (service.value === "custom") {
          const protocol = (col("protocol") >= 0 ? r[col("protocol")] : "") || "tcp";
          row.querySelector('[name="r_protocol"]').value = protocol.toLowerCase() === "udp" ? "udp" : "tcp";
          row.querySelector('[name="r_ports"]').value = ports || (col("service") >= 0 ? r[col("service")] : "");
        }
        row.querySelector('[name="r_must"]').value = mustValue(col("must") >= 0 ? r[col("must")] : "");
        row.querySelector('[name="r_reason"]').value = col("reason") >= 0 ? (r[col("reason")] || "") : "";
        row.querySelectorAll("select").forEach((select) => select.dispatchEvent(new Event("change")));
      });
      launch.querySelector('input[name="mode"][value="custom"]').checked = true;
      count();
      csvStatus.textContent = `Loaded ${Math.min(mine.length, 100)} rule(s) for ${panel.dataset.hereName}` +
        (others.length ? `; skipped ${others.length} for other departments.` : ".");
    });
    launch.querySelector("[data-save-csv]").addEventListener("click", () => {
      const lines = [["from", "to", "service", "protocol", "ports", "must", "reason"].join(",")];
      for (const row of ruleRows.querySelectorAll("[data-rule-row]")) {
        const target = row.querySelector("[data-target-select]").selectedOptions[0];
        const to = target.value === "text" ? row.querySelector("[data-typed-targets]").value.trim() : (target.dataset.addresses || "");
        if (!to) continue;
        const service = row.querySelector("[data-service]").value;
        const custom = service === "custom";
        lines.push([panel.dataset.hereName, to, service, custom ? row.querySelector('[name="r_protocol"]').value : "",
          custom ? row.querySelector('[name="r_ports"]').value : "",
          row.querySelector('[name="r_must"]').value === "deny" ? "blocked" : "work", row.querySelector('[name="r_reason"]').value].map(csvCell).join(","));
      }
      const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `segcheck-rules-${(panel.dataset.hereName || "audit").replace(/[^a-z0-9]+/gi, "-").toLowerCase()}.csv`;
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(link.href), 2000);
      csvStatus.textContent = `Saved ${lines.length - 1} rule(s). Load this file on the next PC, or add rows for other departments.`;
    });
  }
})();
