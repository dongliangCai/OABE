// 这个没有用到。直接用hardhat测试了

import { hexlify } from "ethers/lib/utils";
import { ethers } from "hardhat";
import { ZkEvmVerifierV1 } from "../typechain-types";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import fs from "fs";

async function main() {
    let deployer: SignerWithAddress;
    let zkEvmVerifier: ZkEvmVerifierV1;

    [deployer] = await ethers.getSigners();

    const bytecode = hexlify(fs.readFileSync("./attr_num_20_data/evm_verifier.bin"));
    const tx = await deployer.sendTransaction({ data: bytecode });
    const receipt = await tx.wait();

    console.log("evm verifier(plonk verifier) address: %s\n\tTX_HASH: %s", receipt.contractAddress.toLocaleLowerCase(), tx.hash);

    const ZkEvmVerifierV1 = await ethers.getContractFactory("ZkEvmVerifierV1", deployer);
    zkEvmVerifier = await ZkEvmVerifierV1.deploy(receipt.contractAddress);
    await zkEvmVerifier.deployed();

    console.log("ZkEvmVerifierV1 deployed to: %s\n\tTX_HASH: %s", zkEvmVerifier.address.toLocaleLowerCase(), zkEvmVerifier.deployTransaction.hash);
}

main();