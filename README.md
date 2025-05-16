# OABE
This repo is a proof of concept implementation of paper "Attribute-Based Encryption With Payable Outsourced Decryption Using Blockchain and Responsive Zero Knowledge Proof." arXiv preprint arXiv:2411.03844. https://doi.org/10.48550/arXiv.2411.03844.

three parts now:
* Zero-knowledge proof circuit implementation using Rust and Halo2.
The implementation is based on scroll zkevm-circuits(https://github.com/scroll-tech/zkevm-circuits), an excellent repo with strict security audits. Our main circuit for OABE is in circuits/zkevm-circuits/src/pairing_circuit.rs, and the test is in circuits/prover/src/test/inner.rs. Remember to run download_setup.sh to get trusted setup params before running test.
* Smart contract implementation using Solidity.
The implementation is in the folder Contract-CP-POABE.
* Outsourced decryption Attribute based encryption implementation using Rust. 
The implementation can refer to my repo: https://github.com/dongliangCai/rabe, and was merged into the most popular Rust ABE implementation repo: https://github.com/Fraunhofer-AISEC/rabe.
