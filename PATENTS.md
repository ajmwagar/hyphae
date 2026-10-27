# Patents

hyphae is licensed under **GPL-3.0-or-later** (see `LICENSE`). GPLv3 includes a
patent grant covering the *contributions to this project*.

**That grant does not cover third-party codec patents.** Specifically:

| Subject | Covered by this project's licence? |
|---|---|
| The SIP/IMS/RTP code in this repository | yes |
| **AMR-WB (G.722.2)** | **no** — patent pool (Via LA) |
| **EVS** | **no** — patent pool (Via LA) |
| Opus | yes, royalty-free (Xiph/Cisco/Google/Skype grants) |

## What this means

1. **Nothing encumbered ships in the default build.** The core has Opus only.
   AMR-WB is available only through the separate `codec-amr` package with the
   non-default `amr-wb`/`amr-wb-dlopen` features, which link a *system*
   libopencore-amrwb at the distributor's choice. No AMR-WB/EVS codec
   implementation is in this source tree, so the default source distribution
   creates no codec royalty obligation. See `codec-amr/PATENTS.md`.
2. **Whoever puts a codec on a device pays for it.** Codec licensing attaches to
   devices, not to source code. See
   [docs/adr/0001-codec-licensing.md](docs/adr/0001-codec-licensing.md) for the
   two supported modes (retrofit vs manufacture).
3. **Contributors grant no patent rights beyond their contribution.** Do not
   contribute code you believe reads on a third-party patent without disclosing
   it in the PR.

## Standards-essential patents and FRAND

3GPP/ETSI standards-essential patents are subject to FRAND commitments from
their holders. Implementers are expected to obtain their own licences where
required. This project does not grant, sublicense, or administer any such
licence, and makes no representation about your freedom to operate.

## Reporting

If you believe something in this repository infringes a patent, open an issue
marked `patent` or contact the maintainer privately so it can be assessed. The
project would rather remove a feature than ship an infringement.
