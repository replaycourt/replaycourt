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
  // Guided cases on the overview page. They describe submissions of this one contract, so they
  // are shown only for it; status and payout next to each case are read live from the chain.
  tourContract: "contract.replaycourt.testnet",
  tour: [
    { id: 1, title: "A real exploit gets paid", text: "The TempleDAO hack of 2022, replayed on a private copy of Ethereum. The attack really drains the victim, so the hunter is paid." },
    { id: 4, title: "A fake profit loses its deposit", text: "The proof only looks profitable because it pretends to be the victim. The replay sees through that." },
    { id: 2, title: "A reworded copy is caught", text: "The same attack as #1 in new words. It has the same fingerprint and came later, so it counts as a duplicate." },
    { id: 7, title: "Talking to the judge does not work", text: "The report tells the verifier to mark it valid. No AI reads it: only what the replay shows counts." },
    { id: 6, title: "An AI agent earns a bounty", text: "An AI agent reports from a vault with limits it cannot change. The owner objects, then stalls, and pays for it." },
  ],
};
