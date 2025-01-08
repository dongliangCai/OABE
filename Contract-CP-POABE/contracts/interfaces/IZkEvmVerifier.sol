// SPDX-License-Identifier: MIT
// This file comes from morph (github: github.com/morph-l2/morph)

pragma solidity ^0.8.16;

interface IZkEvmVerifier {
    /// @notice Verify aggregate zk proof.
    /// @param aggrProof The aggregated proof.
    /// @param publicInputHash The public input hash.
    function verify(bytes calldata aggrProof, bytes32 publicInputHash) external view;
}
