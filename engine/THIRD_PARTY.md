# Third-party code in `engine/`

The engine itself (Python, `replay.py` and `replaylib/`) is part of ReplayCourt (MIT, see
`../LICENSE`). It is a port of the author's own pre-hackathon prototype
(baseline code, see the repository README).

The following third-party files are vendored. They are Solidity sources that the engine copies
into each throw-away Foundry workspace; they are never executed outside `forge test`.
Every file is pinned by upstream commit and sha256 in `vendor/VENDOR.json`:

```bash
python3 -I engine/tools/vendor.py verify   # check the vendored files against the pins
python3 -I engine/tools/vendor.py fetch    # re-download missing/changed files from the pinned commits
```

| Path | Upstream | Commit | License | What and why |
|---|---|---|---|---|
| `vendor/forge-std/src/**` (28 files) | https://github.com/foundry-rs/forge-std | `3353993420c6e488a2914ce02d88174e80ad80f8` | MIT OR Apache-2.0 (dual; used under MIT) | Forge Standard Library (`Test`, `Vm`, `console`, ...). Every PoC imports `forge-std/Test.sol`. This is the commit DeFiHackLabs pins in its `foundry.lock`. |
| `vendor/forge-std/LICENSE-MIT`, `vendor/forge-std/LICENSE-APACHE` | same | same | - | upstream license texts |
| `vendor/DeFiHackLabs/src/test/interface.sol` | https://github.com/SunWeb3Sec/DeFiHackLabs | `d4bd931e758a375ed7fcecf52322dfeab54f8c0d` | Apache-2.0 (repository license) | Shared interfaces (`IERC20`, ...) that DeFiHackLabs PoCs import as `./../interface.sol`. Needed by demo report 01. Unmodified. |
| `vendor/DeFiHackLabs/LICENSE` | same | same | - | upstream license text (Apache-2.0) |

Notes:

- DeFiHackLabs is licensed under Apache-2.0 at the repository level (`LICENSE`, GitHub reports
  `Apache-2.0`). Its individual `.sol` files carry the Solidity default header
  `SPDX-License-Identifier: UNLICENSED`; we rely on the repository license and keep the files
  unmodified. Upstream has no `NOTICE` file.
- Demo report `reports/01_templedao_stax.md` contains the DeFiHackLabs PoC
  `src/test/2022-10/Templedao_exp.sol` (same commit, Apache-2.0) verbatim inside its
  ```` ```solidity ```` block (sha256 of the PoC
  `3a459dd07a7fd3562e78c67ddce4d80988c5decd472e9031ee2d6c62ffe5d069`, identical to upstream).
  Report `02_seneca_chamber.md` contains a shortened adaptation of DeFiHackLabs
  `src/test/2024-02/Seneca_exp.sol` (Apache-2.0; changed: own minimal interfaces, forge-std only,
  English assertion message). Both say so in their text.
- The DeFiHackLabs support files `basetest.sol` and `tokenhelper.sol` are not vendored because no
  demo PoC needs them. `replaylib/forge.py` copies them into the workspace only if present, so a
  deployment that accepts DeFiHackLabs-style PoCs can add them with the same pinning approach.
- The Python engine uses only the Python standard library. Foundry (`forge`) is an external
  tool installed by the user (https://getfoundry.sh), not vendored.
