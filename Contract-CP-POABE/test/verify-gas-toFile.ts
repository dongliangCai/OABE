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

    // let attr_nums = [10, 20, 30, 40, 50, 60];
    // 5-60,step=5
    let attr_nums = Array.from({length: Math.floor((60-5)/5) + 1}, (_, i) => i * 5 + 5);
    console.log(attr_nums);
    // let attr_nums = [50];

    let gasUsed = {
        attrNums:   attr_nums,   // index -> attr_num
        ZKPVerify:     new Array(attr_nums.length)
    };      // ZKPVerify[i]是属性数目为attrNums[i]时的ZKP verify的gas消耗

    let test_data_path = "./test/test_data/GasTest/";

    for (let attr_num of attr_nums) {
        it (`attr_num: ${attr_num}`, async () => {
            
            // 部署合约
            [deployer] = await ethers.getSigners();

            let plonk_verifier_path = test_data_path + `attr${attr_num}/evm_verifier.bin`;

            const bytecode = hexlify(fs.readFileSync(plonk_verifier_path));
            const tx = await deployer.sendTransaction({ data: bytecode });
            const receipt = await tx.wait();

            const ZkEvmVerifierV1 = await ethers.getContractFactory("ZkEvmVerifierV1", deployer);
            zkEvmVerifier = await ZkEvmVerifierV1.deploy(receipt.contractAddress);
            await zkEvmVerifier.deployed();

            // 加载测试数据，开始测试
            const proof = hexlify(fs.readFileSync(test_data_path + `attr${attr_num}/proof_batch_agg.data`));
            const instances = fs.readFileSync(test_data_path + `attr${attr_num}/pi_batch_agg.data`);

            const publicInputHash = new Uint8Array(32);
            for (let i = 0; i < 32; i++) {
                publicInputHash[i] = instances[i * 32 + 31];
            }

            // verify ok
            await zkEvmVerifier.verify(proof, publicInputHash);
            let gas = await zkEvmVerifier.estimateGas.verify(proof, publicInputHash);
            console.log("Gas Usage:", gas.toString());
            gasUsed.ZKPVerify[attr_nums.indexOf(attr_num)] = gas.toNumber();

            // verify failed
            await expect(zkEvmVerifier.verify(proof, publicInputHash.reverse())).to.be.reverted;
        });
    }

    // 测试结束，把gas消耗写入文件
    after(() => {
        console.log("----------------------------------------------------");
        console.log("Gas Used for ZKP Verify:");
        console.log(gasUsed);

        try {
            const jsonString = JSON.stringify(gasUsed, null, 2);
            fs.writeFileSync(test_data_path + "zkpVerify_gas_used.json", jsonString);
        } catch (err) {
            console.error("Error writing JSON to file:", err);
        }
    });

});

