# cryptol-saber-cortex

A multi-stage implementation of the [SABER](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/) post-quantum key encapsulation mechanism (KEM), developed as part of a course project. The goal is to move from a formal specification down to an optimized embedded implementation, with correctness preserved at each stage.

## Components

**`HighLevelSpec/`** — A formal Cryptol specification of SABER, closely following the Round 3 submission document. This serves as the mathematical ground truth for the project. See `HighLevelSpec/README.md` for details.

**`C-Implementation/`** — A portable C implementation of SABER, developed independently from the reference implementation. Correctness will be validated against the Cryptol spec. _(In progress)_

**`Cortex-M4/`** — A performance-optimized implementation of SABER targeting the ARM Cortex-M4 microcontroller. _(Planned)_

## Reference

SABER: Mod-LWR based KEM — [Round 3 specification](https://www.esat.kuleuven.be/cosic/pqcrypto/saber/files/saberspecround3.pdf)
