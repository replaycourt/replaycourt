// A minimal NEAR JSON-RPC endpoint for the stdio tests: answers the queries the server makes at
// startup and in read tools (view_access_key, view_account, call_function) from fixed state, so the
// real src/server.ts can be spawned without a network. Anything else is a JSON-RPC error.

import http from "node:http";
import type { AddressInfo } from "node:net";

export interface RpcState {
  /** public key -> raw permission ("FullAccess" or {FunctionCall: ...}); missing = no such key. */
  keys: Record<string, unknown>;
  /** contract view method -> result (JSON value), or a function of the args. */
  views: Record<string, unknown | ((args: Record<string, unknown>) => unknown)>;
  /** Every query, for assertions: "view_access_key", "call_function:get_vault", ... */
  seen: string[];
}

const BLOCK = { block_height: 1, block_hash: "11111111111111111111111111111111" };

export async function startMockRpc(state: Partial<RpcState> = {}): Promise<{ url: string; state: RpcState; close: () => Promise<void> }> {
  const st: RpcState = { keys: state.keys ?? {}, views: state.views ?? {}, seen: [] };
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => (body += c.toString()));
    req.on("end", () => {
      let reply: Record<string, unknown>;
      let id: unknown = null;
      try {
        const rpc = JSON.parse(body) as { id: unknown; method: string; params: Record<string, unknown> };
        id = rpc.id;
        reply = { jsonrpc: "2.0", id, result: answer(st, rpc.method, rpc.params) };
      } catch (e) {
        reply = { jsonrpc: "2.0", id, error: { code: -32000, message: (e as Error).message, name: "HANDLER_ERROR", cause: { name: "UNSUPPORTED" } } };
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(reply));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    state: st,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

function answer(st: RpcState, method: string, p: Record<string, unknown>): unknown {
  if (method !== "query") throw new Error(`method ${method} not supported by the mock`);
  const kind = String(p.request_type);
  if (kind === "view_access_key") {
    st.seen.push(kind);
    const perm = st.keys[String(p.public_key)];
    if (perm === undefined) return { error: `access key ${String(p.public_key)} does not exist while viewing`, logs: [], ...BLOCK };
    return { nonce: 5, permission: perm, ...BLOCK };
  }
  if (kind === "view_account") {
    st.seen.push(kind);
    return { amount: (5n * 10n ** 24n).toString(), locked: "0", code_hash: "11111111111111111111111111111111", storage_usage: 500, storage_paid_at: 0, ...BLOCK };
  }
  if (kind === "call_function") {
    const name = String(p.method_name);
    st.seen.push(`call_function:${name}`);
    if (!(name in st.views)) throw new Error(`view ${name} not in the mock`);
    const args = JSON.parse(Buffer.from(String(p.args_base64), "base64").toString("utf8")) as Record<string, unknown>;
    const v = st.views[name];
    const value = typeof v === "function" ? (v as (a: Record<string, unknown>) => unknown)(args) : v;
    return { result: [...Buffer.from(JSON.stringify(value), "utf8")], logs: [], ...BLOCK };
  }
  throw new Error(`query ${kind} not supported by the mock`);
}
