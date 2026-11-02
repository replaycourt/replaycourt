// Read-only NEAR JSON-RPC client: view calls (query / call_function) with endpoint fallback.
import cfg from "./config.js";

export const rpcState = { endpoint: null, failures: [] };
let preferred = 0; // index of the endpoint that answered last
const cache = new Map(); // key -> { at, promise }
const CACHE_MS = 15_000;

class RpcError extends Error {}
export class ContractError extends Error {}

async function post(url, body, timeoutMs) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) throw new RpcError(`HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    throw new RpcError(e.name === "AbortError" ? `timeout after ${timeoutMs} ms` : e.message || String(e));
  } finally {
    clearTimeout(timer);
  }
}

/** One JSON-RPC request; tries every configured endpoint, starting with the last one that worked. */
export async function rpc(method, params) {
  const n = cfg.rpc.length;
  const errors = [];
  for (let k = 0; k < n; k++) {
    const idx = (preferred + k) % n;
    const url = cfg.rpc[idx];
    try {
      const j = await post(url, { jsonrpc: "2.0", id: "replaycourt-web", method, params }, cfg.rpcTimeoutMs);
      if (j.error) throw new RpcError(j.error.cause?.name || j.error.name || j.error.message || "RPC error");
      preferred = idx;
      rpcState.endpoint = url;
      return j.result;
    } catch (e) {
      const host = new URL(url).host;
      errors.push(`${host}: ${e.message}`);
      rpcState.failures.push(`${new Date().toISOString().slice(11, 19)} ${host}: ${e.message}`);
    }
  }
  throw new RpcError(`no RPC endpoint answered (${errors.join("; ")})`);
}

function b64(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function viewUncached(method, args) {
  const res = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: cfg.contractId,
    method_name: method,
    args_base64: b64(JSON.stringify(args)),
  });
  if (res.error) throw new ContractError(`${method}: ${res.error}`);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(res.result)));
}

/** Contract view call, cached for a few seconds so navigation does not repeat requests. */
export function view(method, args = {}) {
  const key = method + JSON.stringify(args);
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < CACHE_MS) return hit.promise;
  const promise = viewUncached(method, args);
  cache.set(key, { at: Date.now(), promise });
  promise.catch(() => cache.delete(key));
  return promise;
}

/** All pages of a paginated view (the contract caps limit at 50). */
export async function listAll(method, args = {}) {
  const all = [];
  for (let from = 0; ; from += 50) {
    const page = await view(method, { ...args, from_index: from, limit: 50 });
    if (!Array.isArray(page)) throw new ContractError(`${method}: unexpected answer`);
    all.push(...page);
    if (page.length < 50) return all;
  }
}
