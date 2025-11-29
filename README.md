
# ML-KEM Cairo implementation

This repository contains a functional untested ML-KEM variant in Cairo. To see sample usage see lib.cairo . If you build upon it, consider referencing or citing this repository. It also includes the:

SHA3-256

SHA3-512

SHAKE128 / SHAKE256

NTT / inverse NTT

Signed and wrapping modular arithmetic (Zq)

Sampling utilities and constants

# Running the Project

Install Scarb, the Cairo package manager:

https://docs.swmansion.com/scarb/download

Clone the repository and cd into src:

git clone https://github.com/letasmar/CairoMlkem.git && cd CairoMlkem

Then run:

scarb execute

This executes main() from lib.cairo, performing:

ML-KEM key generation

Encapsulation

Decapsulation

Printing the shared key bytes