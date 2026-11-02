// ReplayCourt explorer configuration - the only file to edit for another deployment.
// Every host used below (RPC endpoints, an https evidence base) must also be listed in
// connect-src of the Content-Security-Policy in index.html; the page warns if one is missing.
export default {
  network: "testnet",
  // The showcase deployment (demo/SHOWCASE.md). Other deployments without editing this file:
  // ?contract=<account> in the page URL, e.g. ?contract=contract.example.testnet.
  contractId: "contract.replaycourt.testnet",
  // NEAR JSON-RPC endpoints, tried in order; the next one is used on a network error,
  // an HTTP error or a timeout (docs.near.org -> RPC providers).
  rpc: ["https://test.rpc.fastnear.com", "https://near-testnet.drpc.org"],
  rpcTimeoutMs: 8000,
  // On-chain evidence_uri values are paths below runs/, relative to the repository root
  // (runs/<network>/<contract>/<id>/evidence.json in v2, .../verdict.json in v1). They are resolved against this base:
  // "../" = the repository root when the repository is served and this page is /web/.
  // For a hosted page use e.g. "https://raw.githubusercontent.com/<owner>/<repo>/<branch>/".
  evidenceBase: "../",
  explorer: "https://testnet.nearblocks.io",
};
