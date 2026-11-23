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
    /* × on a row removes it; the last row is only emptied, so the form always keeps one. */
    rows.addEventListener("click", (event) => {
      const button = event.target.closest("[data-remove-row]");
      if (!button) return;
      const row = button.closest("[data-row]");
      if (rows.querySelectorAll("[data-row]").length > 1) row.remove();
      else row.querySelectorAll("input").forEach((input) => { input.value = ""; });
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
      const body = new URLSearchParams({ csrf_token: csrf() });
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

    /* 3b follows the type chosen in 3a at once (before saving), so the administrator's steps always match it. */
    const kind = fwForm.querySelector('select[name="kind"]');
    const saved = kind ? kind.value : "";
    const preview = page.querySelector("[data-fw-preview]");
    const showSteps = () => {
      const blocks = page.querySelectorAll("[data-fw-steps]");
      if (!kind || !blocks.length) return;
      blocks.forEach((block) => { block.hidden = block.dataset.fwSteps !== kind.value; });
      if (preview) {
        const changed = kind.value !== saved;
        preview.hidden = !changed;
        preview.textContent = changed ? `Showing the steps for ${kind.selectedOptions[0].textContent.trim()} (saved automatically).` : "";
      }
      page.querySelectorAll(".firewall-live .lab-note:not([data-fw-preview])").forEach((note) => { note.hidden = kind.value !== saved; });
      const howto = page.querySelector(".firewall-live details.howto");
      if (howto && kind.value !== saved) howto.open = true;
    };
    if (kind) kind.addEventListener("change", showSteps);
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
    /* Same rules as the server (audit_setup.parse_ports / parse_addresses): wrong input is named as it is typed,
       and Launch is stopped with the exact problem. */
    function portsError(text) {
      const value = text.trim();
      if (!value) return "Type the ports to test, e.g. 8080 or 9000-9010.";
      if (/\d\s+-|-\s+\d/.test(value)) return "Remove the spaces around the dash: write a range as 9000-9010.";
      let total = 0;
      for (const token of value.split(/[\s,;]+/).filter(Boolean)) {
        if (/^\d+$/.test(token)) {
          const port = Number(token);
          if (port < 1 || port > 65535) return `${token} is not a port: ports go from 1 to 65535.`;
          total += 1;
        } else if (/^\d+-\d+$/.test(token)) {
          const [first, last] = token.split("-").map(Number);
          if (first < 1 || last > 65535) return `${token}: ports go from 1 to 65535.`;
          if (last < first) return `The range ${token} runs backwards: write it as ${last}-${first}.`;
          total += last - first + 1;
        } else if (/^\d+:\d+$/.test(token)) {
          return `${token}: write ranges with a dash, as ${token.replace(":", "-")}.`;
        } else {
          return `"${token}" is not a port or a range. Use numbers, e.g. 8080, or ranges, e.g. 9000-9010 (no names like "http").`;
        }
      }
      if (total > 400) return `${total} ports is too many for one rule (at most 400). Split it into several rules.`;
      return "";
    }
    function addressesError(text) {
      const value = text.trim();
      if (!value) return "Type the addresses to test, e.g. 10.30.0.20, 10.30.0.10-20 or 10.30.0.0/28.";
      const ip = (part) => /^\d{1,3}(\.\d{1,3}){3}$/.test(part) && part.split(".").every((n) => Number(n) <= 255);
      for (const token of value.split(/[\s,;]+/).filter(Boolean)) {
        if (token.includes(":")) continue;  // IPv6: checked by SegCheck when you launch
        if (token.includes("/")) {
          const [base, bits] = token.split("/");
          if (!ip(base) || !/^\d+$/.test(bits) || Number(bits) > 32) return `${token} is not a subnet. Write it like 10.30.0.0/28.`;
          if (2 ** (32 - Number(bits)) > 258) return `${token} has ${2 ** (32 - Number(bits))} addresses; one rule covers at most 256 (use /24 or smaller).`;
        } else if (token.includes("-")) {
          const [first, last] = token.split("-");
          const end = last && last.includes(".") ? last : `${first.split(".").slice(0, 3).join(".")}.${last}`;
          if (!ip(first) || !ip(end)) return `${token} is not a range. Write it like 10.30.0.10-20 or 10.30.0.10-10.30.0.40.`;
          if (ipToInt(end) < ipToInt(first)) return `The range ${token} runs backwards.`;
          if (ipToInt(end) - ipToInt(first) + 1 > 256) return `${token} covers more than 256 addresses; split it.`;
        } else if (!ip(token)) {
          return `"${token}" is not an IP address. Write addresses like 10.30.0.20 (names are not accepted).`;
        }
      }
      return "";
    }
    function ruleErrors(row) {
      const service = row.querySelector('[name="r_service"]');
      const target = row.querySelector('[name="r_target"]');
      const portsInput = row.querySelector('[name="r_ports"]');
      const typedInput = row.querySelector('[name="r_targets"]');
      const portsProblem = service.value === "custom" && row.querySelector('[name="r_protocol"]').value !== "icmp"
        ? portsError(portsInput.value) : "";
      const targetsProblem = target.value === "text" ? addressesError(typedInput.value) : "";
      const show = (input, box, problem, touched) => {
        const visible = Boolean(problem) && touched;
        if (box) { box.hidden = !visible; box.textContent = visible ? problem : ""; }
        input.setAttribute("aria-invalid", visible ? "true" : "false");
      };
      show(portsInput, row.querySelector("[data-ports-error]"), portsProblem, portsInput.value.trim() !== "" || row.dataset.checked === "1");
      show(typedInput, row.querySelector("[data-targets-error]"), targetsProblem, typedInput.value.trim() !== "" || row.dataset.checked === "1");
      return portsProblem ? { input: portsInput, text: portsProblem } : targetsProblem ? { input: typedInput, text: targetsProblem } : null;
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
      const problem = ruleErrors(row);
      if (preview) {
        preview.textContent = problem && (row.dataset.checked === "1" || problem.input.value.trim())
          ? `Fix this rule first: ${problem.text}` : `Sends ${what} to ${toText} → ${each * hosts} attempt(s); ${must}.`;
        preview.classList.toggle("is-error", Boolean(problem) && (row.dataset.checked === "1" || Boolean(problem.input.value.trim())));
      }
      return problem ? 0 : each * hosts;
    }
    function count() {
      launch.querySelectorAll("[data-mode-panel]").forEach((panel) => { panel.hidden = panel.dataset.modePanel !== mode(); });
      if (mode() === "custom") {
        const total = [...launch.querySelectorAll("[data-rule-row]")].reduce((sum, row) => sum + rulePreview(row), 0);
        out.textContent = String(total);
        out.classList.toggle("is-over", total > max || !total);
        eta.textContent = total > max ? `Too many: the limit is ${max}.` : total ? duration(total) : "Add a rule with ports.";
        return;
      }
      const several = launch.querySelector('input[name="scope"]:checked')?.value === "several";
      syncScope(several);
      showRelevantProbes(several);
      const ticked = new Set([...launch.querySelectorAll('input[name="groups"]:checked')].map((box) => box.value));
      if (several) {
        const chosen = [...launch.querySelectorAll('input[name="pack"]:checked')];
        const pairs = new Map();
        for (const box of chosen) {
          const hosts = (box.dataset.targetList || "").split(",").map((h) => h.trim()).filter(Boolean);
          box.closest(".pack-card").querySelectorAll("[data-group]").forEach((g) => {
            if (ticked.has(g.dataset.group)) hosts.forEach((h) => pairs.set(`${h}|${g.dataset.group}`, Number(g.dataset.cost)));
          });
        }
        const total = [...pairs.values()].reduce((a, b) => a + b, 0);
        out.textContent = chosen.length ? String(total) : "–";
        if (standardPreview) {
          standardPreview.replaceChildren();
          const title = document.createElement("p");
          title.className = "send-title";
          title.textContent = chosen.length ? `${chosen.length} standard check(s) chosen. Probes shared by several standards are sent once:` : "Tick the standards to include.";
          const list = document.createElement("ul");
          chosen.forEach((box) => list.append(line(box.closest(".pack-card").querySelector("strong").textContent,
            ` · ${box.closest(".pack-card").querySelector(".pack-meta").textContent} · ${box.dataset.targets} target(s)`)));
          standardPreview.append(title, list);
        }
        eta.textContent = !chosen.length ? "Tick at least one standard." : !total ? "Tick probes these standards use." :
          total > max ? `Too many: the limit is ${max}. Untick some standards or probes.` : duration(total);
        out.classList.toggle("is-over", total > max || !total);
        return;
      }
      const pack = launch.querySelector('input[name="pack"]:checked');
      if (!pack) { out.textContent = "–"; eta.textContent = "Choose a standard."; return; }
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
      else eta.textContent = duration(total);
      out.classList.toggle("is-over", total > max || !perTarget);
    }
    /* "Which probes" lists only the probe kinds the chosen standard(s) actually send; the others are hidden,
       so nobody thinks they apply. (Without JavaScript all are listed, and only the relevant ones are sent.) */
    function showRelevantProbes(several) {
      const chosen = [...launch.querySelectorAll('input[name="pack"]:checked')];
      const used = new Set();
      chosen.forEach((box) => box.closest(".pack-card").querySelectorAll("[data-group]").forEach((g) => used.add(g.dataset.group)));
      launch.querySelectorAll('input[name="groups"]').forEach((box) => {
        const card = box.closest(".group-card");
        if (card) card.hidden = !used.has(box.value);
      });
      const hint = launch.querySelector("[data-probes-hint]");
      if (!hint) return;
      if (!chosen.length) {
        hint.textContent = several ? "Tick the standards above: the probes they use appear here." : "Choose a standard above: the probes it uses appear here.";
      } else {
        const name = chosen.length === 1 ? `“${chosen[0].closest(".pack-card").querySelector("strong").textContent.trim()}”`
          : `the ${chosen.length} chosen standards`;
        hint.textContent = `The ${used.size} kind${used.size === 1 ? "" : "s"} of probe ${name} ${chosen.length === 1 ? "uses" : "use"}. ` +
          "Only these are sent; untick any you don't need.";
      }
    }
    /* Attempts run one after another. A blocked attempt: 1 s wait, then up to 2 s for the firewall's log line (the lab's
       firewall sends its logs about once a second). Measured in the lab: 50 attempts in 68 s, so about 1.5 s with logs.
       A silent attempt that the firewall did not log as blocked is tried again (3 s more), so without logs blocked doors
       cost about 4.4 s each. Open or refused doors answer at once. Plus a few seconds at the end for the last log lines. */
    function duration(attempts) {
      const fmt = (seconds) => seconds < 60 ? `${seconds} s` : `${Math.floor(seconds / 60)} min ${String(seconds % 60).padStart(2, "0")} s`;
      const logged = launch.dataset.logs === "1";
      const usual = Math.ceil(attempts * (logged ? 1.5 : 4.4) + 6);
      const worst = Math.ceil(attempts * 4.4 + 6);
      return logged ? `about ${fmt(usual)} with the firewall's logs (up to ${fmt(worst)} if they stop arriving; longer on a slow network)`
                    : `up to about ${fmt(worst)} (silent attempts are tried twice; longer on a slow network; connecting the firewall's logs makes it faster)`;
    }
    function syncScope(several) {
      const boxes = [...launch.querySelectorAll('input[name="pack"]')];
      const want = several ? "checkbox" : "radio";
      if (boxes.length && boxes[0].type !== want) {
        const first = boxes.find((box) => box.checked && !box.disabled);
        boxes.forEach((box) => { box.type = want; box.checked = !several && box === first; });
        if (several && first) first.checked = true;
      }
      const hint = launch.querySelector("[data-scope-hint]");
      if (hint) hint.hidden = !several;
    }
    launch.querySelector("[data-select-all-packs]")?.addEventListener("click", () => {
      launch.querySelectorAll('input[name="pack"]:not([disabled])').forEach((box) => { box.checked = true; });
      count();
    });
    launch.addEventListener("change", count);
    // My own rules: stop Launch on a wrong rule, say exactly what is wrong (popup) and put the cursor there.
    launch.addEventListener("submit", (event) => {
      if (mode() !== "custom") return;
      const rows = [...launch.querySelectorAll("[data-rule-row]")];
      rows.forEach((row) => { row.dataset.checked = "1"; });
      const index = rows.findIndex((row) => ruleErrors(row));
      count();
      if (index < 0) return;
      event.preventDefault();
      const problem = ruleErrors(rows[index]);
      const ui = window.SegCheckUI;
      if (ui && ui.toast) ui.toast(`Rule ${index + 1}: ${problem.text}`, "error");
      problem.input.focus();
      problem.input.select?.();
    });
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
      const typedBox = row.querySelector("[data-typed-box]") || typed;
      const sync = () => { ports.hidden = service.value !== "custom"; typedBox.hidden = target.value !== "text"; };
      service.addEventListener("change", () => { sync(); count(); });
      target.addEventListener("change", () => { sync(); if (!typedBox.hidden) typed.focus(); count(); });
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

  /* Autosave: Step 1 and Step 3a save themselves a moment after a change (no page reload; errors pop up).
     "Save Step N and continue" also sends anything typed but not yet added, then opens the next step.
     Without JavaScript every form still has its own submit button. */
  const ui = window.SegCheckUI || {};
  const say = (text, kind) => { if (ui.toast) ui.toast(text, kind); };
  const post = async (form) => {
    const response = await fetch(form.action, { method: "POST", body: new FormData(form), credentials: "same-origin" });
    if (response.redirected && new URL(response.url).pathname.startsWith("/login")) {
      return { ok: false, error: "You were signed out (SegCheck restarted). Sign in again; then redo the last change." };
    }
    const doc = new DOMParser().parseFromString(await response.text(), "text/html");
    const error = doc.querySelector(".flash-message.flash-error");
    if (!response.ok || error) return { ok: false, error: error ? error.textContent.trim() : "Could not save. Reload the page and try again." };
    const done = doc.querySelector(".flash-message.flash-success");
    return { ok: true, message: done ? done.textContent.trim() : "" };
  };
  const snapshot = (form) => [...new FormData(form)].filter(([key]) => key !== "csrf_token")
    .map(([key, value]) => `${key}=${value instanceof File ? value.name : value}`).join("&");
  const autosaves = [];
  page.querySelectorAll("form[data-autosave]").forEach((form) => {
    const button = form.querySelector("[data-autosave-button]");
    if (button) button.hidden = true;
    const status = document.createElement("p");
    status.className = "autosave-status";
    status.setAttribute("role", "status");
    form.append(status);
    let saved = snapshot(form);
    let timer = null;
    let running = Promise.resolve(true);
    const save = (force = false) => {
      clearTimeout(timer);
      running = running.then(async () => {
        if (force !== true && snapshot(form) === saved) return true;
        if (!form.checkValidity()) {
          status.textContent = "Not saved yet: fill in the highlighted fields.";
          status.dataset.state = "waiting";
          return false;
        }
        status.textContent = "Saving…";
        status.dataset.state = "saving";
        const state = snapshot(form);
        try {
          const result = await post(form);
          if (!result.ok) {
            status.textContent = "Not saved.";
            status.dataset.state = "error";
            say(result.error, "error");
            return false;
          }
          saved = state;
          const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
          status.textContent = `✓ Saved automatically · ${time}`;
          status.dataset.state = "saved";
          return true;
        } catch (error) {
          status.textContent = "Not saved: SegCheck is not reachable.";
          status.dataset.state = "error";
          return false;
        }
      });
      return running;
    };
    form.addEventListener("change", () => { clearTimeout(timer); timer = setTimeout(save, 400); });
    form.addEventListener("input", (event) => {
      if (event.target.matches("input[type=text], input:not([type]), textarea")) { clearTimeout(timer); timer = setTimeout(save, 1500); }
    });
    form.addEventListener("submit", (event) => { event.preventDefault(); save(true); });
    autosaves.push({ form, save });
  });

  const typedSomething = (form) => {
    if (form.matches(".add-targets")) {
      return [...form.querySelectorAll('input[name="t_name"], input[name="t_cidr"], input[name="t_hosts"]')].some((input) => input.value.trim());
    }
    return [...form.querySelectorAll("input[type=text], input:not([type]), textarea, input[type=file]")]
      .some((input) => (input.type === "file" ? input.files.length : input.value.trim()));
  };
  page.querySelectorAll("[data-step-finish]").forEach((button) => {
    const section = button.closest(".step-card");
    button.addEventListener("click", async () => {
      button.disabled = true;
      const label = button.textContent;
      button.textContent = "Saving…";
      const stop = (message) => { if (message) say(message, "error"); button.disabled = false; button.textContent = label; };
      for (const item of autosaves.filter((entry) => section.contains(entry.form))) {
        if (!(await item.save(button.dataset.done !== "yes"))) return stop(item.form.checkValidity() ? "" : "Fill in the highlighted fields first.");
      }
      const pending = [...section.querySelectorAll("form[data-pending-form]")].filter(typedSomething);
      for (const form of pending) {
        if (!form.checkValidity()) { form.reportValidity(); return stop(""); }
        const result = await post(form);
        if (!result.ok) return stop(result.error);
      }
      const changed = pending.length || autosaves.some((entry) => section.contains(entry.form));
      if (!changed && button.dataset.done !== "yes") return stop(button.dataset.waiting);
      try { sessionStorage.setItem("segcheck-step-saved", `Step ${button.dataset.stepFinish} saved.`); } catch (error) { /* private mode */ }
      location.replace(`${location.pathname}#step-${button.dataset.next}`);
      location.reload();
    });
  });
  try {
    const note = sessionStorage.getItem("segcheck-step-saved");
    if (note) { sessionStorage.removeItem("segcheck-step-saved"); say(note, "success"); }
  } catch (error) { /* private mode */ }

  /* Step 3a: "Here it is …" follows the "Firewall's address in this network" field as it is typed (autosave does not reload). */
  const hereText = page.querySelector("[data-fw-here-text]");
  const hereField = page.querySelector('form[data-firewall-form] input[name="firewall_ip"]');
  if (hereText && hereField) {
    const follow = () => { hereText.textContent = hereField.value.trim() || hereText.dataset.empty; };
    hereField.addEventListener("input", follow);
    follow();
  }

  /* Step 3a: a suggested firewall address is added to the field only when the auditor clicks it (then autosaved). */
  page.querySelectorAll("[data-add-address]").forEach((chip) => chip.addEventListener("click", () => {
    const input = page.querySelector("[data-other-ips]");
    if (!input) return;
    const list = input.value.split(/[\s,;]+/).filter(Boolean);
    if (!list.includes(chip.dataset.addAddress)) list.push(chip.dataset.addAddress);
    input.value = list.join(" ");
    input.dispatchEvent(new Event("change", { bubbles: true }));
    chip.remove();
  }));

  /* Step 4: each standard's full explanation opens in a side drawer (native <dialog>: Esc closes, focus is kept inside). */
  page.querySelectorAll("[data-pack-open]").forEach((button) => {
    const dialog = document.getElementById(button.dataset.packOpen);
    if (!dialog || typeof dialog.showModal !== "function") return;
    button.addEventListener("click", () => dialog.showModal());
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close(); /* a click on the dimmed backdrop */
    });
    dialog.querySelectorAll("[data-pack-close]").forEach((close) => close.addEventListener("click", () => dialog.close()));
    dialog.addEventListener("close", () => button.focus());
    const use = dialog.querySelector("[data-pack-use]");
    if (use) use.addEventListener("click", () => {
      const input = page.querySelector(`input[name="pack"][value="${use.dataset.packUse}"]`);
      if (input && !input.disabled) {
        input.checked = true;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
      dialog.close();
    });
  });
})();
