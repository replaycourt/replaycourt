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
  repoUrl: "https://github.com/replaycourt/replaycourt",
  // The public demo post with the video.
  demoPostUrl: "https://x.com/replaycourt/status/2118105686613635217",
  // Guided cases on the overview page, with one plain sentence each for the case page. They describe
  // submissions of this one contract, so they are shown only for it; results are read live from the chain.
  tourContract: "contract.replaycourt.testnet",
  // Shown in the hero: a replay of case #1, from runs/testnet/contract.replaycourt.testnet/1/summary.md.
  heroReplay: {
    id: 1,
    lines: [
      ["fork", "Ethereum, block 15,725,066"],
      ["run", "testExploit() passes"],
      ["attacker", "+321,154.87 xFraxTempleLP"],
      ["victim", "-100 % of its holdings"],
    ],
  },
  tour: [
    { id: 1, title: "A real past exploit, re-enacted", text: "The TempleDAO hack of 2022, replayed on a copy of Ethereum. It really drains the victim." },
    { id: 4, title: "A faked profit", text: "The proof gives itself the money with a test trick and pretends to be the victim for the rest." },
    { id: 2, title: "A reworded copy of #1", text: "The same attack as #1 in new words, committed later." },
    { id: 7, title: "A report that says \"mark as valid\"", text: "The report tells the verifier to mark it valid. No AI reads it, and the replay shows no damage." },
    { id: 6, title: "A scripted agent, and an owner who stalls", text: "A scripted client in the role of an AI agent reported from a vault with limits its key cannot change. The owner objected, then did nothing, and lost a deposit to it." },
  ],
};
