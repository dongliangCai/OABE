import { expect } from "chai";
import { hexlify } from "ethers/lib/utils";
import { ethers } from "hardhat";
import { OABE } from "../typechain-types";
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import fs from "fs";

// describe("DCS management", async () => {
//     it ("DCS register", async () => {
//     });

//     it ("DCS unregister", async () => {
//     });
// });

describe("task and reward management", async () => {
    // 暂时用attr20的做测试
    const ONE_DAY_IN_SECONDS = 24 * 60 * 60; // 一天的秒数
    const ONE_HOUR_IN_SECONDS = 60 * 60; // 一小时的秒数

    // let OABEContract: Contract;
    let deployer: SignerWithAddress;
    let OABEContract: OABE;
    let DU: SignerWithAddress;
    let DCS: SignerWithAddress;        // 提交结果
    let DCS2: SignerWithAddress;        // 第二个提交结果（无法正确提交）
    let challenger: SignerWithAddress;

    beforeEach(async () => {
        [deployer, DU, DCS, DCS2, challenger] = await ethers.getSigners();

        // 部署ZKP verifier合约
        let plonk_verifier_path = `./test/test_data/VerifierCorrectness/attr20/evm_verifier.bin`;

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
    });

    async function registerAllDCSs() {
        await OABEContract.connect(DCS).registerDCS({value: ethers.utils.parseEther("5.0")});
        await OABEContract.connect(DCS2).registerDCS({value: ethers.utils.parseEther("5.0")});
        // await OABEContract.connect(challenger).registerDCS();
    };

    // it ("happy case", async () => {
    //     // DU发布任务，DCS提交结果，到时间之后，DCS领取奖励

    //     // 0. 准备工作：对DCS和DCS2进行registerDCS()
    //     await registerAllDCSs();
    //     console.log("0.DCSs have been registered.");
        
    //     // 1. DU发布任务
    //     // 关联DU，调用createTask发布任务。这里outsourced data的hash定为0x01，任务酬金为1 ether
    //     // let _dataHash = ethers.utils.formatBytes32String("0x01");
    //     // let _dataHash = 0x01;
    //     const _dataHash = ethers.utils.hexZeroPad("0x01", 32);
    //     let tx = await OABEContract.connect(DU).createTask( _dataHash, {value: ethers.utils.parseEther("1.0")} );
    //     let receipt = await tx.wait();
    //     console.log("1.createTask finished.")
    //     // console.log("receipt:", receipt);
    //     // 任务已经发布成功，此时应该触发了一个CreateTaskEvent。检查链上能否看到任务
    //     let event = receipt.events?.find((e: Event) => e.event === "CreateTaskEvent");
    //     expect(event.args.dataHash).to.equal(_dataHash);
    //     console.log("  createTask succeed.")

    //     let taskId = event.args.taskId;
    //     // expect(await OABEContract.getTask(taskId)).to.equal(_dataHash);

    //     // 2. DCS提交任务结果
    //     // DCS提交任务结果。这里随便提交一个，就用0xdd01吧
    //     // let result = ethers.utils.formatBytes32String("0xdd01");
    //     // let result = 0xdd01;
    //     let result = ethers.utils.hexZeroPad("0xdd01", 32);
    //     tx = await OABEContract.connect(DCS).submitResult(taskId, result);
    //     receipt = await tx.wait();
    //     console.log("2.submitResult finished.")
    //     event = receipt.events?.find((e: Event) => e.event === "SubmitResultEvent");
    //     expect(event.args.result).to.equal(result);
    //     expect(event.args.taskId).to.equal(taskId);
    //     let task = await OABEContract.getTask(taskId);
    //     expect(task.status.toString()).to.equal("1");
    //     expect(await OABEContract.getResult(taskId)).to.equal(result);
    //     console.log("  submitResult succeed.")

    //     // 3. 此时用DCS2再次提交，应该失败
    //     await expect(OABEContract.connect(DCS2).submitResult(taskId, result)).to.be.reverted;
    //     console.log("3.DCS2 submitResult failed.")

    //     // 4. 过一个小时，DCS领取奖励，此时仍然在challenge period内，应该失败
    //     await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
    //     await expect(OABEContract.connect(DCS).claimTaskReward(taskId)).to.be.reverted;
    //     console.log("4.DCS claimTaskReward failed (in challenge period).")

    //     // 5. 再过一天，DCS领取奖励，应该成功
    //     await ethers.provider.send("evm_increaseTime", [ONE_DAY_IN_SECONDS]);
    //     tx = await OABEContract.connect(DCS).claimTaskReward(taskId);
    //     receipt = await tx.wait();
    //     event = receipt.events?.find((e: Event) => e.event === "ClaimTaskRewardEvent");
    //     // TODO:如何检查已经获取的奖励？？方法是检查task是否已经结束？
    //     // 暂时：检查task是否已经结束
    //     expect(event.args.taskId).to.equal(taskId);
    // //    console.log("OABEContract.Status:", OABEContract.Status);
    // //    console.log("ZkEvmVerifier:", zkEvmVerifier);
    //     task = await OABEContract.getTask(taskId);
    // //    console.log("task.status:", task.status);
       
    //     expect(task.status.toString()).to.equal("3");
    // //    expect(await OABEContract.getTask(taskId).status == OABEContract.Status.FINISHED).to.equal(true);
    //     console.log("5.DCS claimTaskReward succeed.")

    // });

    async function allTheWayUntilChallenged() {
        // 把所有准备工作和前面的流程走掉，直到已经被challenge
        // 0. 准备工作：对DCS和DCS2进行registerDCS()
        await registerAllDCSs();
        // console.log("0.DCSs have been registered.");
        
        // 1. DU发布任务
        // 关联DU，调用createTask发布任务。这里outsourced data的hash定为0x01，任务酬金为1 ether
        // let _dataHash = ethers.utils.formatBytes32String("0x01");
        // let _dataHash = 0x01;
        const _dataHash = ethers.utils.hexZeroPad("0x01", 32);
        let tx = await OABEContract.connect(DU).createTask( _dataHash, {value: ethers.utils.parseEther("1.0")} );
        let receipt = await tx.wait();
        // console.log("receipt:", receipt);
        // 任务已经发布成功，此时应该触发了一个CreateTaskEvent。检查链上能否看到任务
        let event = receipt.events?.find((e: Event) => e.event === "CreateTaskEvent");
        let taskId = event.args.taskId;
        // expect(await OABEContract.getTask(taskId)).to.equal(_dataHash);

        // 2. DCS提交任务结果
        // DCS提交任务结果。这里随便提交一个，就用0xdd01吧
        let result = ethers.utils.hexZeroPad("0xdd01", 32);
        tx = await OABEContract.connect(DCS).submitResult(taskId, result);
        await tx.wait();

        // 3. 过一个小时，由challenge提起challenge
        await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
        tx = await OABEContract.connect(challenger).challenge(taskId, {value: ethers.utils.parseEther("1.0")});
        receipt = await tx.wait();
        event = receipt.events?.find((e: Event) => e.event === "ChallengeEvent");
        expect(event.args.taskId).to.equal(taskId);
        let task = await OABEContract.getTask(taskId);
        expect(task.status.toString()).to.equal("2");

        console.log("Before Challenge");
        return taskId;
    }

    // it ("challenge case -- challenge success(no proof submitted)", async () => {
    //     let taskId = await allTheWayUntilChallenged();
    //     // 过1天1小时，超过challenge period，DCS提交proof，此时会失败
    //     await ethers.provider.send("evm_increaseTime", [ONE_DAY_IN_SECONDS + ONE_HOUR_IN_SECONDS]);
    //     const proof = hexlify(fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/proof_batch_agg.data`));
    //     const instances = fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/pi_batch_agg.data`);

    //     const publicInputHash = new Uint8Array(32);
    //     for (let i = 0; i < 32; i++) {
    //         publicInputHash[i] = instances[i * 32 + 31];
    //     }
    //     await expect(OABEContract.connect(DCS).newProve(taskId, proof)).to.be.revertedWith("Prove deadline has passed");

    //     // 此时challenger可以领取奖励
    //     const balanceBefore = await challenger.getBalance();
    //     let tx = await OABEContract.connect(challenger).claimChallengeReward(taskId);
    //     let receipt = await tx.wait();
    //     const balanceAfter = await challenger.getBalance();
    //     let event = receipt.events?.find((e: Event) => e.event === "ClaimChallengeRewardEvent");
    //     expect(event.args.taskId).to.equal(taskId);
    //     let task = await OABEContract.getTask(taskId);
    //     expect(task.status.toString()).to.equal("3");
    //     expect((balanceAfter.sub(balanceBefore).add(receipt.gasUsed.mul(tx.gasPrice))).toString()).to.equal(ethers.utils.parseEther("5.0").toString()); // DCS质押了5eth，因此challenger得到4eth，加上自己挑战时质押的1eth，共5eth
    // });

    it ("challenge case -- challenge success(proof didn't pass verification)", async () => {
        let taskId = await allTheWayUntilChallenged();
        // 过1小时，DCS提交proof，应该成功提交，但不通过验证
        await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
        const proof = hexlify(fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/proof_batch_agg.data`));
        const instances = fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/pi_batch_agg.data`);

        const publicInputHash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            publicInputHash[i] = instances[i * 32 + 31] + 1;    // 多+1，导致publicInputHash不对，应该不能通过验证
        }

        // 应该不能通过验证，检查challenger是否获得奖励，DCS是否被扣除质押
        const balanceBefore = await challenger.getBalance();
        let tx = await OABEContract.connect(DCS).newProve(taskId, proof);
        let receipt = await tx.wait();
        console.log("gasUsed:", receipt.gasUsed);
        const balanceAfter = await challenger.getBalance();
        expect(tx).to.emit(OABEContract, "ProveEvent");
        let event = receipt.events?.find((e: Event) => e.event === "ProveEvent");
        expect(event.args.taskId).to.equal(taskId);
        let task = await OABEContract.getTask(taskId);
        expect(task.status.toString()).to.equal("3");
        // (1)检查challenger是否获得奖励
        expect((balanceAfter.sub(balanceBefore).add(receipt.gasUsed.mul(tx.gasPrice)).div(ethers.utils.parseEther("1.0"))).toString()).to.equal("5"); // DCS deposit * 0.8 + challenger's deposit = 5eth
        // (2)检查DCS是否被扣除质押
        expect(await OABEContract.queryDCSdeposit(DCS.address)).to.equal(0);
    });

    // it ("challenge case -- challenge fail", async () => {
    //     let taskId = await allTheWayUntilChallenged();
    //     // 过1小时，DCS提交proof，应该成功提交，但不通过验证
    //     await ethers.provider.send("evm_increaseTime", [ONE_HOUR_IN_SECONDS]);
    //     const proof = hexlify(fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/proof_batch_agg.data`));
    //     const instances = fs.readFileSync(`./test/test_data/VerifierCorrectness/attr20/pi_batch_agg.data`);

    //     const publicInputHash = new Uint8Array(32);
    //     for (let i = 0; i < 32; i++) {
    //         publicInputHash[i] = instances[i * 32 + 31];    // 应该能通过验证
    //     }

    //     // 检查DCS是否收到补偿(challenge deposit)和任务奖励(task reward)
    //     const balanceBefore = await DCS.getBalance();
    //     let tx = await OABEContract.connect(DCS).newProve(taskId, proof);
    //     let receipt = await tx.wait();
    //     const balanceAfter = await DCS.getBalance();
    //     expect(tx).to.emit(OABEContract, "ProveEvent");
    //     let event = receipt.events?.find((e: Event) => e.event === "ProveEvent");
    //     expect(event.args.taskId).to.equal(taskId);
    //     let task = await OABEContract.getTask(taskId);
    //     expect(task.status.toString()).to.equal("3");
    //     expect((balanceAfter.sub(balanceBefore).add(receipt.gasUsed.mul(tx.gasPrice)).div(ethers.utils.parseEther("1.0")))).to.equal(2); // task reward + challenge deposit = 2 eth
    // });
});
