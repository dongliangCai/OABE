import { expect } from "chai";
import { hexlify } from "ethers/lib/utils";
import { ethers } from "hardhat";
import { UploadCTandTKtest } from "../typechain-types";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import fs from "fs";

describe("upload CT and TK test", async () => {
    let deployer: SignerWithAddress;
    let contract: UploadCTandTKtest;

    // 5-60,step=5
    let attr_nums = Array.from({length: Math.floor((60-5)/5) + 1}, (_, i) => i * 5 + 5);
    // let attr_nums = [50];

    let gasUsed = {
        attrNums:   attr_nums,   // index -> attr_num
        uploadCT:   new Array(attr_nums.length),
        uploadTK:   new Array(attr_nums.length),
        // uploadCTandTK:  new Array(attr_nums.length),
        uploadSum:  new Array(attr_nums.length)
    }

    beforeEach(async () => {
        // 部署合约
        [deployer] = await ethers.getSigners();
        const contractFactory = await ethers.getContractFactory("UploadCTandTKtest", deployer);
        contract = (await contractFactory.deploy()) as UploadCTandTKtest;
        await contract.deployed();
    });

    function generateBytes32Array(size: number): string[] {
        const result: string[] = [];
        for (let i = 0; i < size; i++) {
            // 生成随机的 bytes32 数据
            const randomBytes32 = ethers.utils.hexlify(ethers.utils.randomBytes(32));
            result.push(randomBytes32);
        }
        return result;
    }

    for (let attr_num of attr_nums) {
        it (`attr_num: ${attr_num}`, async () => {
            // 生成测试数据，开始测试
            // const CT = ethers.utils.randomBytes(32 * (4 * attr_num + 4));
            // const TK = ethers.utils.randomBytes(32 * (4 * attr_num + 8));

            const CT = generateBytes32Array(4 * attr_num + 4);
            const TK = generateBytes32Array(4 * attr_num + 8);

            console.log("length of TK:", TK.length);
            console.log("type of TK:", typeof TK);
            console.log("length of TK[0]:", TK[0].length);
            console.log("type of TK[0]:", typeof TK[0]);

            let tx = await contract.uploadCT(CT);
            let script = await tx.wait();
            let gas = script.gasUsed;
            console.log("Gas Usage(upload CT):", gas.toString());
            gasUsed.uploadCT[attr_nums.indexOf(attr_num)] = gas.toNumber();

            tx = await contract.uploadTK(TK);
            script = await tx.wait();
            gas = script.gasUsed;
            console.log("Gas Usage(upload TK):", gas.toString());
            gasUsed.uploadTK[attr_nums.indexOf(attr_num)] = gas.toNumber();

            // tx = await contract.uploadCTandTK(CT, TK);
            // script = await tx.wait();
            // gas = script.gasUsed;
            // console.log("Gas Usage(upload CT and TK):", gas.toString());
            // gasUsed.uploadCTandTK[attr_nums.indexOf(attr_num)] = gas.toNumber();

            gasUsed.uploadSum[attr_nums.indexOf(attr_num)] = gasUsed.uploadCT[attr_nums.indexOf(attr_num)] + gasUsed.uploadTK[attr_nums.indexOf(attr_num)];
        });
    }

    after(() => {
        console.log("----------------------------------------------------");
        console.log("Gas Used for upload CT and TK:");
        console.log(gasUsed);

        try {
            const jsonString = JSON.stringify(gasUsed, null, 2);
            fs.writeFileSync("./test/uploadCTandTK_gas_used.json", jsonString);
        } catch (err) {
            console.error("Error writing JSON to file:", err);
        }
    });

});