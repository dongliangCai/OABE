import { expect } from "chai";
import { hexlify } from "ethers/lib/utils";
import { ethers } from "hardhat";
import { OABE } from "../typechain-types";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import fs from "fs";

describe("Gas Test. For each function.", async () => {
    const ONE_DAY_IN_SECONDS = 24 * 60 * 60; // 一天的秒数
    const ONE_HOUR_IN_SECONDS = 60 * 60; // 一小时的秒数

    let attr_nums = [10, 20, 30, 40, 50, 60];

    // let OABEContract: Contract;
    let deployer: SignerWithAddress;
    let OABEContract: OABE;
    let DU: SignerWithAddress;
    let DCS: SignerWithAddress;        // 提交结果
    let challenger: SignerWithAddress;

    let gasUsed: Map<string, number>[] = new Array(attr_nums.length);    // gasUsed[i]表示attr_nums[i]的gas消耗
    for (let i = 0; i < attr_nums.length; i++) {
        gasUsed[i] = new Map<string, number>();
    }

    beforeEach(async () => {
        [deployer, DU, DCS, challenger] = await ethers.getSigners();
    });

    async function depolyContract(attrNum: number) {
        // 部署ZKP verifier合约
        let plonk_verifier_path = `./test/test_data/GasTest/attr${attrNum}/evm_verifier.bin`;
    
        const bytecode = hexlify(fs.readFileSync(plonk_verifier_path));
        const tx = await deployer.sendTransaction({ data: bytecode });
        const receipt = await tx.wait();
    
        // 要先部署ArrayUtils，然后链接这个库，才能部署OABE
        const ArrayUtils = await ethers.getContractFactory("ArrayUtils");
        const arrayUtils = await ArrayUtils.deploy();
        await arrayUtils.deployed();
    
        // const OABEFactory = await ethers.getContractFactory("OABE", deployer);
        const OABEFactory = await ethers.getContractFactory("OABE", {
            libraries: {
                ArrayUtils: arrayUtils.address
            },
            signer: deployer});
        OABEContract = await OABEFactory.deploy(receipt.contractAddress);
        await OABEContract.deployed();
    }

    async function registerDCS(attrIndex: number) {
        let tx = await OABEContract.connect(DCS).registerDCS({value: ethers.utils.parseEther("5.0")});
        let receipt = await tx.wait();
        let funcName = "registerDCS";
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
    }

    async function createTask(attrIndex: number, taskIds: any[]) {
        for (let i = 0; i < taskIds.length; i++) {
            const _dataHash = ethers.utils.randomBytes(32);
            taskIds[i] = _dataHash;
            let tx = await OABEContract.connect(DU).createTask( _dataHash, {value: ethers.utils.parseEther("1.0")} );
            let receipt = await tx.wait();
            let funcName = "createTask-" + (i+1).toString();
            gasUsed[attrIndex].set(funcName, receipt.gasUsed);
            console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
        }
    }

    async function submitResult(attrIndex: number, taskIds: readonly any[]) {
        for (let i = 0; i < taskIds.length; i++) {
            let tx = await OABEContract.connect(DCS).submitResult(taskIds[i], ethers.utils.randomBytes(32));
            let receipt = await tx.wait();
            let funcName = "submitResult-" + (i+1).toString();
            gasUsed[attrIndex].set(funcName, receipt.gasUsed);
            console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
        }
    }

    async function challenge(attrIndex: number, taskIds: readonly any[]) {
        for (let i = 1; i < taskIds.length; i++) {      // task[0]是happy case，不需要challenge
            let tx = await OABEContract.connect(challenger).challenge(taskIds[i], {value: ethers.utils.parseEther("1.0")});
            let receipt = await tx.wait();
            let funcName = "challenge-" + (i+1).toString();
            gasUsed[attrIndex].set(funcName, receipt.gasUsed);
            console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
        }
    }

    async function proveWrong(attrIndex: number, taskIds: readonly any[], toProveTaskIndex: number) {
        await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
        const proof = hexlify(fs.readFileSync(`./test/test_data/GasTest/attr${attr_nums[attrIndex]}/proof_batch_agg.data`));
        const instances = fs.readFileSync(`./test/test_data/GasTest/attr${attr_nums[attrIndex]}/pi_batch_agg.data`);

        const publicInputHash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            publicInputHash[i] = instances[i * 32 + 31] + 1;    // 多+1，导致publicInputHash不对，应该不能通过验证
        }

        let tx = await OABEContract.connect(DCS).prove(taskIds[toProveTaskIndex], proof, publicInputHash);
        let receipt = await tx.wait();
        let funcName = "proveWrong-" + (toProveTaskIndex+1).toString();
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);  
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
    }

    async function proveRight(attrIndex: number, taskIds: readonly any[], toProveTaskIndex: number) {
        await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
        const proof = hexlify(fs.readFileSync(`./test/test_data/GasTest/attr${attr_nums[attrIndex]}/proof_batch_agg.data`));
        const instances = fs.readFileSync(`./test/test_data/GasTest/attr${attr_nums[attrIndex]}/pi_batch_agg.data`);

        const publicInputHash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            publicInputHash[i] = instances[i * 32 + 31];    // 应该能通过验证
        }

        let tx = await OABEContract.connect(DCS).prove(taskIds[toProveTaskIndex], proof, publicInputHash);
        let receipt = await tx.wait();
        let funcName = "proveRight-" + (toProveTaskIndex+1).toString();
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);  
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
    }

    async function claimTaskReward(attrIndex: number, taskIds: readonly any[], toClaimTaskIndex: number) {
        let tx = await OABEContract.connect(DCS).claimTaskReward(taskIds[toClaimTaskIndex]);
        let receipt = await tx.wait();
        let funcName = "claimTaskReward-" + (toClaimTaskIndex+1).toString();
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
    }

    async function claimChallengeReward(attrIndex: number, taskIds: readonly any[], toClaimTaskIndex: number) {
        let tx = await OABEContract.connect(challenger).claimChallengeReward(taskIds[toClaimTaskIndex]);
        let receipt = await tx.wait();
        let funcName = "claimChallengeReward-" + (toClaimTaskIndex+1).toString();
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);
    }
    
    async function unregisterDCS(attrIndex: number) {
        let tx = await OABEContract.connect(DCS).unregisterDCS();
        let receipt = await tx.wait();
        let funcName = "unregisterDCS";
        gasUsed[attrIndex].set(funcName, receipt.gasUsed);
        console.log(`[${funcName}] Gas Used: `, receipt.gasUsed);    
    }

    // 调用上面的测试函数进行完整测试
    // for (let attr_num of attr_nums) {
    for (let i = 0; i < attr_nums.length; i++) {
        let attr_num = attr_nums[i];
        it("Gas Test for attr " + attr_num.toString(), async () => {
            // 0. 准备工作，部署合约
            console.log("depolyContract...");
            await depolyContract(attr_num);

            // 1. registerDCS
            console.log("registerDCS...");
            await registerDCS(i);

            // 2. createTask【创建4个，1个happy case，3个challenge case，包括不提交proof(claim challenge reward)、提交错误proof(challengeSuccess)、提交正确proof(challengeFail)】
            console.log("createTask...");
            let taskIds = new Array(4);
            await createTask(i, taskIds);

            // 3. submitResult
            console.log("submitResult...");
            await submitResult(i, taskIds);
            // 过一小时
            await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);

            // 4. challenge【task2,3,4】
            console.log("challenge...");
            await challenge(i, taskIds);
            // 过一小时
            await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);

            // 5. prove【错误task3，正确task4】
            console.log("prove...");
            await proveWrong(i, taskIds, 2);
            await proveRight(i, taskIds, 3);

            // 过一天一小时，从而超出challenge和prove的deadline
            await ethers.provider.send("evm_increaseTime", [ONE_DAY_IN_SECONDS + ONE_HOUR_IN_SECONDS]);

            // 6. claimTaskReward【task1】
            console.log("claimTaskReward...");
            await claimTaskReward(i, taskIds, 0);

            // 7. claimChallengeReward【task2】
            console.log("claimChallengeReward...");
            await claimChallengeReward(i, taskIds, 1);

            // 8. unregisterDCS
            console.log("unregisterDCS...");
            await unregisterDCS(i);
        });
    }

    // 全部测试结束，处理gasUsed
    after(() => {
        console.log("----------------------------------------------------");
        console.log("Gas Used for each function:");
        for (let i = 0; i < attr_nums.length; i++) {
            console.log(`attr${attr_nums[i]}:`);
            for (let [key, value] of gasUsed[i].entries()) {
                console.log(" ", key, value);
            }
        }
    });
});