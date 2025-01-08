/* eslint-disable node/no-unpublished-import */
/* eslint-disable node/no-missing-import */
import { expect } from "chai";
import { hexlify } from "ethers/lib/utils";
import { ethers } from "hardhat";
import { ZkEvmVerifierV1 } from "../typechain-types";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import fs from "fs";

// require("@nomiclabs/hardhat-waffle")

describe("Verifier Test.", async () => {
    let deployer: SignerWithAddress;
    let zkEvmVerifier: ZkEvmVerifierV1;

    // let plonk_verifier_path = "./test/test_data/attr30/evm_verifier.bin";   // 用的是attr20的plonk verifier

    let attr_nums = [20, 30, 50];
    // let current_attr_num = 20;

    // beforeEach(async () => {
    //     [deployer] = await ethers.getSigners();

    //     let plonk_verifier_path = `./test/test_data/attr${current_attr_num}/evm_verifier.bin`;

    //     const bytecode = hexlify(fs.readFileSync(plonk_verifier_path));
    //     const tx = await deployer.sendTransaction({ data: bytecode });
    //     const receipt = await tx.wait();

    //     const ZkEvmVerifierV1 = await ethers.getContractFactory("ZkEvmVerifierV1", deployer);
    //     zkEvmVerifier = await ZkEvmVerifierV1.deploy(receipt.contractAddress);
    //     await zkEvmVerifier.deployed();
    // });

    for (let attr_num of attr_nums) {
        it (`attr_num: ${attr_num}`, async () => {
            
            // 部署合约
            [deployer] = await ethers.getSigners();

            let plonk_verifier_path = `./test/test_data/VerifierCorrectness/attr${attr_num}/evm_verifier.bin`;

            const bytecode = hexlify(fs.readFileSync(plonk_verifier_path));
            const tx = await deployer.sendTransaction({ data: bytecode });
            const receipt = await tx.wait();

            const ZkEvmVerifierV1 = await ethers.getContractFactory("ZkEvmVerifierV1", deployer);
            zkEvmVerifier = await ZkEvmVerifierV1.deploy(receipt.contractAddress);
            await zkEvmVerifier.deployed();

            // 加载测试数据，开始测试
            const proof = hexlify(fs.readFileSync(`./test/test_data/VerifierCorrectness/attr${attr_num}/proof_batch_agg.data`));
            const instances = fs.readFileSync(`./test/test_data/VerifierCorrectness/attr${attr_num}/pi_batch_agg.data`);

            const publicInputHash = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                publicInputHash[i] = instances[i * 32 + 31];
            }

            // verify ok
            await zkEvmVerifier.verify(proof, publicInputHash);
            console.log("Gas Usage:", (await zkEvmVerifier.estimateGas.verify(proof, publicInputHash)).toString());

            // verify failed
            await expect(zkEvmVerifier.verify(proof, publicInputHash.reverse())).to.be.reverted;
        });
    }



    // it("attr20", async () => {
    //     const proof = hexlify(fs.readFileSync(`./test/test_data/attr20/proof_batch_agg.data`));
    //     const instances = fs.readFileSync(`./test/test_data/attr20/pi_batch_agg.data`);

    //     const publicInputHash = new Uint8Array(32);
    //     for (let i = 0; i < 32; i++) {
    //         publicInputHash[i] = instances[i * 32 + 31];
    //     }

    //     // verify ok
    //     await zkEvmVerifier.verify(proof, publicInputHash);
    //     console.log("Gas Usage:", (await zkEvmVerifier.estimateGas.verify(proof, publicInputHash)).toString());

    //     // verify failed
    //     await expect(zkEvmVerifier.verify(proof, publicInputHash.reverse())).to.be.reverted;
    // });
});

