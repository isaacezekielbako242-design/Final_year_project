// EduVulnScanner dashboard logic.
// All scan data is inserted with textContent (never innerHTML) because the
// evidence deliberately contains injected payload strings.
(function () {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const form = $("#scan-form");
  const startBtn = $("#start-btn");
  const authz = $("#authorized");
  const formError = $("#form-error");
  let currentJob = null;
  let currentFindings = [];
  let pollTimer = null;

  // ---- form helpers --------------------------------------------------------
  authz.addEventListener("change", () => { startBtn.disabled = !authz.checked; });

  document.querySelectorAll("[data-target]").forEach((btn) => {
    btn.addEventListener("click", () => {
      $("#target_url").value = btn.dataset.target;
      $("#eval-version").value = btn.dataset.version;
    });
  });

  $("#fill-demo").addEventListener("click", () => {
    form.user1_username.value = "alice"; form.user1_password.value = "alice-pass-123";
    form.user2_username.value = "bob";   form.user2_password.value = "bob-pass-456";
  });

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }

  async function api(url, options) {
    const resp = await fetch(url, options);
    let data = {};
    try { data = await resp.json(); } catch (_) { /* non-JSON */ }
    if (!resp.ok) throw new Error(data.error || `Request failed (HTTP ${resp.status})`);
    return data;
  }

  // ---- start a scan ----------------------------------------------------------
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    formError.textContent = "";
    if (!authz.checked) { formError.textContent = "Please confirm that you are authorised to test this target."; return; }
    const target = form.target_url.value.trim();
    if (!/^https?:\/\/[^\s/]+/i.test(target)) { formError.textContent = "Enter a valid http:// or https:// URL."; return; }

    const payload = {
      target_url: target,
      authorized: true,
      user1_username: form.user1_username.value.trim(), user1_password: form.user1_password.value,
      user2_username: form.user2_username.value.trim(), user2_password: form.user2_password.value,
      login_url: form.login_url.value.trim(),
      max_pages: form.max_pages.value, delay: form.delay.value,
      modules: Array.from(form.querySelectorAll("input[name=modules]:checked")).map((c) => c.value),
    };
    startBtn.disabled = true;
    try {
      const data = await api("/api/scans", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
      });
      currentJob = data.job_id;
      // Passwords are not kept in the page after the scan has started.
      form.user1_password.value = ""; form.user2_password.value = "";
      showProgress();
      poll();
    } catch (err) {
      formError.textContent = err.message;
      startBtn.disabled = !authz.checked;
    }
  });

  function showProgress() {
    $("#progress-panel").classList.remove("hidden");
    $("#results-panel").classList.add("hidden");
    $("#eval-panel").classList.add("hidden");
    $("#eval-output").classList.add("hidden");
    $("#progress-bar").classList.remove("failed");
    setProgress(0, "Starting…", "");
  }

  function setProgress(pct, stage, msg) {
    $("#progress-bar").style.width = pct + "%";
    $("#progress-pct").textContent = pct + "%";
    $("#progress-stage").textContent = stage;
    $("#progress-msg").textContent = msg || "";
  }

  async function poll() {
    clearTimeout(pollTimer);
    try {
      const job = await api(`/api/scans/${currentJob}`);
      setProgress(job.percent, job.stage, job.status === "failed" ? job.error : job.message);
      if (job.status === "running") { pollTimer = setTimeout(poll, 700); return; }
      startBtn.disabled = !authz.checked;
      if (job.status === "failed") {
        $("#progress-bar").classList.add("failed");
        $("#progress-stage").textContent = "Scan failed";
        return;
      }
      renderResults(job.result);
    } catch (err) {
      setProgress(0, "Connection error", err.message);
      startBtn.disabled = !authz.checked;
    }
  }

  // ---- results ---------------------------------------------------------------
  function renderResults(r) {
    $("#results-panel").classList.remove("hidden");
    $("#eval-panel").classList.remove("hidden");
    $("#report-btn").href = `/scans/${currentJob}/report`;
    $("#json-btn").href = `/scans/${currentJob}/json`;
    const sessions = r.sessions.map((s) => `${s.label} ${s.authenticated ? "logged in" : "login failed"}`).join(", ");
    $("#result-meta").textContent =
      `Target ${r.target} · scanned ${r.started_at.replace("T", " ")} · ${r.duration_seconds}s · ` +
      `${r.requests_sent} requests` + (sessions ? ` · ${sessions}` : " · unauthenticated");

    const s = r.summary;
    $("#sum-total").textContent = s.total;
    $("#sum-high").textContent = s.by_severity.High;
    $("#sum-medium").textContent = s.by_severity.Medium;
    $("#sum-low").textContent = s.by_severity.Low;

    const bars = $("#category-bars");
    bars.replaceChildren();
    const max = Math.max(1, ...Object.values(s.by_category));
    Object.entries(s.by_category).forEach(([cat, n]) => {
      const row = el("div", null, "cat-row");
      row.append(el("span", cat));
      const track = el("div", null, "cat-track");
      const fill = el("div", null, "cat-fill");
      fill.style.width = (100 * n / max) + "%";
      track.append(fill);
      row.append(track, el("strong", n));
      bars.append(row);
    });

    currentFindings = r.findings;
    renderTable();

    const notes = $("#notes-list");
    notes.replaceChildren();
    [...r.notes, ...r.limitations.map((l) => "Limitation: " + l)].forEach((n) => notes.append(el("li", n)));

    // Guess which testbed was scanned to pre-select the evaluation version.
    if (/:5002\b/.test(r.target)) $("#eval-version").value = "patched";
    else if (/:5001\b/.test(r.target)) $("#eval-version").value = "vulnerable";
  }

  function renderTable() {
    const filter = $("#severity-filter").value;
    const body = $("#results-body");
    body.replaceChildren();
    const rows = currentFindings.filter((f) => !filter || f.severity === filter);
    $("#no-findings").classList.toggle("hidden", currentFindings.length !== 0);
    rows.forEach((f) => {
      const tr = document.createElement("tr");
      tr.append(el("td", f.finding_id));
      const sev = el("td"); sev.append(el("span", f.severity, "badge " + f.severity)); tr.append(sev);
      tr.append(el("td", f.category));
      tr.append(el("td", f.url, "url"));
      tr.append(el("td", f.parameter || "—"));
      const ev = el("td");
      const det = el("details", null, "evidence");
      det.append(el("summary", f.title));
      det.append(el("pre", `Test input: ${f.test_input || "—"}\n\nEvidence: ${f.evidence}\n\nConfidence: ${f.confidence}\n\nRemediation: ${f.remediation}`));
      ev.append(det);
      tr.append(ev);
      body.append(tr);
    });
  }
  $("#severity-filter").addEventListener("change", renderTable);

  // ---- evaluation ------------------------------------------------------------
  $("#eval-btn").addEventListener("click", async () => {
    if (!currentJob) return;
    try {
      const ev = await api(`/api/scans/${currentJob}/evaluate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ version: $("#eval-version").value }),
      });
      $("#eval-output").classList.remove("hidden");
      $("#ev-tp").textContent = ev.tp; $("#ev-fp").textContent = ev.fp; $("#ev-fn").textContent = ev.fn;
      $("#ev-precision").textContent = ev.precision_display;
      $("#ev-recall").textContent = ev.recall_display;
      $("#ev-f1").textContent = ev.f1_display;
      const body = $("#coverage-body");
      body.replaceChildren();
      Object.entries(ev.coverage_by_category).forEach(([cat, c]) => {
        const tr = document.createElement("tr");
        [cat, c.documented, c.detected, c.coverage_display, c.false_positives].forEach((v) => tr.append(el("td", v)));
        body.append(tr);
      });
      const details = $("#eval-details");
      details.replaceChildren();
      ev.true_positives.forEach((t) => details.append(el("li", `TP: ${t.ground_truth_id} matched by ${t.finding_id} (${t.category}, ${t.url} [${t.parameter || "—"}])`)));
      ev.false_negatives.forEach((g) => details.append(el("li", `FN: ${g.ground_truth_id} not detected — ${g.function} (${g.url})`)));
      ev.false_positives.forEach((f) => details.append(el("li", `FP: ${f.finding_id} ${f.title} at ${f.url} [${f.parameter || "—"}]`)));
      details.append(el("li", `Saved to ${ev.saved_to.join(" and ")}`));
    } catch (err) {
      alert(err.message);
    }
  });
})();
