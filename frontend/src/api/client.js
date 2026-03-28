// API client — all calls to the FastAPI backend

const BASE = "/api";

// ─── Network Context ──────────────────────────────────────────────────────────

export async function uploadNetworkContext(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/network`, { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Upload failed");
  }
  return res.json();
}

export async function getNetworkContext() {
  const res = await fetch(`${BASE}/network`);
  if (!res.ok) throw new Error("Failed to fetch network context");
  return res.json();
}

// ─── Intents ──────────────────────────────────────────────────────────────────

export async function submitIntent(intent, autoApprove = false) {
  const res = await fetch(`${BASE}/intents`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ intent, auto_approve: autoApprove }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to submit intent");
  }
  return res.json(); // { session_id, status, current_step, message }
}

export async function getIntentStatus(sessionId) {
  const res = await fetch(`${BASE}/intents/${sessionId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to get status");
  }
  return res.json();
}

export async function reviewIntent(sessionId, approve, feedback = "") {
  const res = await fetch(`${BASE}/intents/${sessionId}/review`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ approve, feedback }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    // Include the HTTP status code in the message so callers can distinguish
    // 409 Conflict (duplicate resume in-flight) from other errors.
    throw new Error(`${res.status}:${err.detail || "Failed to submit review"}`);
  }
  return res.json();
}

export async function getFinalConfig(sessionId) {
  const res = await fetch(`${BASE}/intents/${sessionId}/config`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Failed to get config");
  }
  return res.json();
}

// ─── Health ───────────────────────────────────────────────────────────────────

export async function healthCheck() {
  const res = await fetch("/health");
  if (!res.ok) throw new Error("Backend unreachable");
  return res.json();
}
