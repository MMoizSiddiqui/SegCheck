"use strict";
/* Shared SegCheck interface behaviour: motion, clock, health and helpers.
   Runs under the app's CSP (no inline script, no external resources). */
(() => {
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const SVG = "http://www.w3.org/2000/svg";

  const UI = {
    reduced,
    svg(type, attrs = {}, text) {
      const node = document.createElementNS(SVG, type);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
      if (text !== undefined) node.textContent = text;
      return node;
    },
    el(type, className, text) {
      const node = document.createElement(type);
      if (className) node.className = className;
      if (text !== undefined) node.textContent = text;
      return node;
    },
    /* Animate a number from its current value to target. */
    countTo(node, target, { duration = 900, decimals = 0, suffix = "" } = {}) {
      if (!node) return;
      const start = parseFloat(node.dataset.value ?? node.textContent) || 0;
      node.dataset.value = target;
      if (reduced || start === target) { node.textContent = target.toFixed(decimals) + suffix; return; }
      const begin = performance.now();
      // Guarantee the final value even when animation frames are paused (hidden tab).
      clearTimeout(node._countTimer);
      node._countTimer = setTimeout(() => { node.textContent = target.toFixed(decimals) + suffix; }, duration + 120);
      const step = now => {
        const t = Math.min(1, (now - begin) / duration);
        const eased = 1 - Math.pow(1 - t, 3);
        node.textContent = (start + (target - start) * eased).toFixed(decimals) + suffix;
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    },
    relative(iso) {
      if (!iso) return "never";
      const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
      if (!Number.isFinite(seconds)) return "unknown";
      if (seconds < 45) return "just now";
      const units = [["d", 86400], ["h", 3600], ["m", 60]];
      for (const [unit, size] of units) if (seconds >= size) return `${Math.floor(seconds / size)}${unit} ago`;
      return `${seconds}s ago`;
    },
    async json(url) {
      const response = await fetch(url, { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok || !response.headers.get("content-type")?.includes("application/json")) {
        throw new Error("Data unavailable. Reload to check your session.");
      }
      return response.json();
    },
  };
  window.SegCheckUI = UI;

  /* Reveal cards as they scroll into view. */
  function reveal() {
    const items = document.querySelectorAll(".setup-card, .dashboard-panel, .metric-card, .viz-card, .result-card, .assessment-panel, .policy-card");
    if (reduced || !("IntersectionObserver" in window)) return;
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) if (entry.isIntersecting) { entry.target.classList.add("is-visible"); observer.unobserve(entry.target); }
    }, { rootMargin: "0px 0px -6% 0px" });
    items.forEach((item, index) => {
      item.classList.add("reveal");
      item.style.setProperty("--reveal-delay", `${Math.min(index, 8) * 45}ms`);
      observer.observe(item);
    });
    // Never leave content hidden if the observer cannot fire (background tab, print, old engine).
    setTimeout(() => items.forEach(item => item.classList.add("is-visible")), 1400);
  }

  /* Count-up for any server-rendered number marked data-countup. */
  function countups() {
    for (const node of document.querySelectorAll("[data-countup]")) {
      const target = parseFloat(node.textContent);
      if (Number.isFinite(target)) { node.textContent = "0"; node.dataset.value = 0; UI.countTo(node, target); }
    }
  }

  function clock() {
    const node = document.querySelector("[data-clock]");
    if (!node) return;
    const tick = () => { node.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
    tick(); setInterval(tick, 1000);
  }

  /* Lightweight liveness indicator from the unauthenticated health endpoint. */
  async function health() {
    const dots = document.querySelectorAll("[data-health-dot]");
    const label = document.querySelector("[data-health-label]");
    if (!dots.length) return;
    let ok = false;
    try {
      const response = await fetch("/api/health", { cache: "no-store", headers: { Accept: "application/json" } });
      ok = response.ok && (await response.json()).database === "available";
    } catch (error) { ok = false; }
    dots.forEach(dot => dot.classList.toggle("is-down", !ok));
    if (label) label.textContent = ok ? "Local instance · database online" : "Local instance · unreachable";
    setTimeout(health, ok ? 20000 : 5000);
  }

  /* Table filter: any input[data-filter-table="#id"] filters that table's rows. */
  function filters() {
    for (const input of document.querySelectorAll("[data-filter-table]")) {
      const table = document.querySelector(input.dataset.filterTable);
      if (!table) continue;
      input.addEventListener("input", () => {
        const query = input.value.trim().toLowerCase();
        for (const row of table.tBodies[0]?.rows || []) row.hidden = query && !row.textContent.toLowerCase().includes(query);
      });
    }
  }

  /* Card filter: input[data-filter-cards="#id"] filters that container's article children. */
  function cardFilters() {
    for (const input of document.querySelectorAll("[data-filter-cards]")) {
      const container = document.querySelector(input.dataset.filterCards);
      if (!container) continue;
      input.addEventListener("input", () => {
        const query = input.value.trim().toLowerCase();
        for (const card of container.querySelectorAll(":scope > article")) card.hidden = query && !card.textContent.toLowerCase().includes(query);
      });
    }
  }

  /* CSP-safe confirmation for irreversible actions: <button data-confirm="...">.
     Inline onclick handlers are blocked by the app's Content-Security-Policy. */
  document.addEventListener("submit", event => {
    const submitter = event.submitter;
    const message = submitter?.dataset.confirm || event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  }, true);

  /* Keep the active item visible in the horizontally scrolling mobile nav. */
  function navFocus() {
    const active = document.querySelector(".sidebar-nav .nav-link.active");
    const nav = document.querySelector(".sidebar-nav");
    if (active && nav && nav.scrollWidth > nav.clientWidth) nav.scrollLeft = active.offsetLeft - 16;
  }

  /* Pop-up messages: every saved/refused action's message also appears as a toast in the corner, so it is seen
     even when the page has jumped to a step further down. Success closes by itself; errors stay until closed. */
  function toast(text, kind = "info") {
    let stack = document.querySelector(".toast-stack");
    if (!stack) {
      stack = UI.el("div", "toast-stack");
      stack.setAttribute("aria-live", "polite");
      document.body.append(stack);
    }
    const item = UI.el("div", `toast toast-${kind}`);
    item.setAttribute("role", kind === "error" ? "alert" : "status");
    const icon = UI.el("span", "toast-icon", kind === "error" ? "!" : kind === "success" ? "\u2713" : "i");
    const body = UI.el("span", "toast-text", text);
    const close = UI.el("button", "toast-close", "\u00d7");
    close.type = "button";
    close.setAttribute("aria-label", "Close message");
    const remove = () => { item.classList.add("is-leaving"); setTimeout(() => item.remove(), reduced ? 0 : 250); };
    close.addEventListener("click", remove);
    item.append(icon, body, close);
    stack.append(item);
    if (kind !== "error") setTimeout(remove, 7000);
    return item;
  }
  UI.toast = toast;

  function flashToasts() {
    for (const message of document.querySelectorAll(".flash-message[role=status]")) {
      const kind = message.classList.contains("flash-error") ? "error" : message.classList.contains("flash-success") ? "success" : "info";
      toast(message.textContent.trim(), kind);
    }
  }

  document.addEventListener("DOMContentLoaded", () => { navFocus(); reveal(); countups(); clock(); health(); filters(); cardFilters(); flashToasts(); });
})();
