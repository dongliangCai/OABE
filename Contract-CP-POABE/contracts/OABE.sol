// 这里重新整理和设计一下，把原来的代码做一个重构

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {IOABE} from "./interfaces/IOABE.sol";
import {ArrayUtils} from "./libraries/ArrayUtils.sol";
// import "./libraries/ArrayUtils.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

// 流程
// 【问题：TK需要传到链上吗？】
// 1. DataUser发布任务。createTask【是一段哈希值，对密文的哈希。密文存储在cloud上，任何人看到这个task后可以到cloud上依据该hash请求到密文】
// 2. DecryptionCloudServer(DCS)提交结果。submitResult【任何人可以在链上看到任务内容，然后到cloud上请求密文，之后就可以自己计算出结果。谁先算出结果，就提交到链上，这个任务就算被他领去了】
// 3. Challenger质疑。challenge【质疑者需要质押一定的token，如果质疑成功，质疑者可以获得一定的奖励，否则质疑者的token会被处罚】
// 4. DCS提交证明。proveState【DCS需要提交zkproof，证明自己的结果是正确的。如果zkproof验证通过，DCS可以获得一定的奖励，否则DCS的token会被处罚】

// DCS管理
// 1. DCS注册。registerDCS
// 2. DCS注销。unregisterDCS

// 任务管理【这部分暂时不要】
// 1. DataUser结束任务。endTask【这个可以不实现，毕竟我们不是做可用的系统，这些功能不影响论文的关键设计】
// 2. anybody查询任务。queryTask【这个其实也可以没有hhh，不影响关键设计】

// 奖励管理
// 1. DCS领取奖励。claimTaskReward->正常流程走完，且没有被challenge
// 2. Challenger领取奖励。claimChallengeReward->challenge成功（未按时提交proof）【20%给DataUser，80%给Challenger】
// 3. DCS获取challenge奖励。【指challenge成功（proof验证不通过）。在proveState中自动进行，若zkproof通过验证】
// （辅助函数）
// 1. _challengeFail()。challenge失败，处分challenge质押的资产。在proveState中proof通过验证时调用
// 2. _challengeSuccess()。challenge成功，处分server质押的资产。在proveState中proof未通过验证时，以及claimChallengeReward中调用


contract OABE is IOABE {
    /*************
     * Data Struct *
     *************/
    // 这里是任务的数据结构，之后整理到接口文件里
    // struct Task {
    //     // TODO
    // }

    using ArrayUtils for ArrayUtils.RandomRemoveableArray;


    /*************
     * Constants *
     *************/
    // uint constant SUBMIT_PERIOD = 2 days;
    uint constant CHALLENGE_PERIOD = 1 days;
    uint constant PROVE_PERIOD = 1 days;

    uint constant MINIMAL_DCS_DEPOSIT = 1 ether;            // 注册成为外包计算员需要的质押金
    uint constant MINIMAL_CHALLENGE_DEPOSIT = 100000 wei;   // 发起challenge需要的质押金

    /// @notice The address of highly optimized plonk verifier contract.
    address public immutable PLONK_VERIFIER;

    mapping(bytes32 => Task) tasks;    // 任务id => 任务详情
    mapping(address => uint) DCSdeposits;   // 外包计算员地址 => 质押金额（单位wei）
    mapping(address => ArrayUtils.RandomRemoveableArray) pendingTasks;  // 外包计算员地址 => 正在处理的外包计算任务列表
    

    /***************
     * Constructor *
     ***************/
     constructor(address _verifier) {
        // TODO:这是morph的constructor，要做一些改动吗？
        PLONK_VERIFIER = _verifier;
    }

    /* constructor和其他什么？？ */
    // TODO: constructor

    /*************************
     * Public View Functions *
     *************************/
    
    /* 流程 */
    // 1. DataUser发布任务
    function createTask(bytes32 _dataHash) external payable returns (bytes32) {
        require(msg.value > 0, "Reward must be greater than 0");    // DataUser把发布任务时，需要把酬金转到合约账户
        bytes32 taskId = keccak256(abi.encodePacked(block.timestamp, msg.sender, msg.value, _dataHash));  // 随机生成任务id

        tasks[taskId] = Task({
            id: taskId,
            dataHash: _dataHash,
            reward: msg.value,
            // publishTime: block.timestamp,
            // acceptTime: 0,      // 任务被接受的时间
            // submitTime: 0,      // 提交外包计算结果的时间

            // acceptDeadline: block.timestamp + SUBMIT_PERIOD,  // 接受任务的截止时间
            // submitDeadline: 0,
            challengeDeadline: 0,

            status: Status.CREATED,  // 任务状态

            dataUser: msg.sender,       // 任务发起人地址
            DCS: address(0),           // 外包计算员地址

            result: 0,          // 任务结果，即解密得到的CT'（图中步骤6），由Decryption Cloud Server提交

            challenge: Challenge({
                challenger: address(0),     // 质疑者地址
                // challengeTime: 0,     // 质疑时间
                // challengeDeadline: 0, // 质疑截止时间
                deposit: 0,            // 质疑者支付的质押金

                proveDeadline: 0     // zk proof提交截止时间
                // proveTime: 0,          // zk proof提交时间

                // proof: new bytes(0),    // zk proof
                // publicInputHash: ""     // zk proof的hash
            })    // 质疑(challenge)的详情
        });

        emit CreateTaskEvent(_dataHash, taskId, msg.sender, msg.value);
        return taskId;
    }

    function getTask(bytes32 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }
    
    // 2. DecryptionCloudServer(DCS)提交结果
    function submitResult(bytes32 taskId, bytes32 _result) external {
        Task storage task = tasks[taskId];      // 指定storage，则task是指向tasks[taskId]的引用，可以通过task修改tasks[taskId]的值
        require(task.status == Status.CREATED, "Task is not created");
        require(DCSdeposits[msg.sender] >= MINIMAL_DCS_DEPOSIT, "DCS has no enough deposit");

        task.DCS = msg.sender;
        task.status = Status.SUBMITTED;
        task.result = _result;
        task.challengeDeadline = block.timestamp + CHALLENGE_PERIOD;

        pendingTasks[msg.sender].push(taskId);

        emit SubmitResultEvent(taskId, msg.sender, _result);
    }

    function getResult(bytes32 taskId) external view returns (bytes32) {
        return tasks[taskId].result;
    }

    // 3. Challenger质疑
    function challenge(bytes32 taskId) external payable {
        Task storage task = tasks[taskId];
        require(task.status == Status.SUBMITTED, "Task is not submitted");
        // require(msg.value >= MINIMAL_CHALLENGE_DEPOSIT, string(abi.encodePacked("Should deposit at least ", MINIMAL_CHALLENGE_DEPOSIT.toString(), " wei to challenge.")));
        require(msg.value >= MINIMAL_CHALLENGE_DEPOSIT, "Should deposit enough tokens to challenge.");
        require(block.timestamp <= task.challengeDeadline, "Challenge deadline has passed");

        task.challenge = Challenge({
            challenger: msg.sender,
            deposit: msg.value,
            proveDeadline: block.timestamp + PROVE_PERIOD
            // proof: new bytes(0),
            // publicInputHash: ""
        });

        task.status = Status.CHALLENGED;

        emit ChallengeEvent(taskId, msg.sender, msg.value);
    }

    // 4. DCS提交证明
    function prove(bytes32 taskId, bytes calldata _proof, bytes32 _publicInputHash) external {
        Task storage task = tasks[taskId];
        require(task.status == Status.CHALLENGED, "Task is not challenged");
        require(task.DCS == msg.sender, "Only DCS can prove");
        require(block.timestamp <= task.challenge.proveDeadline, "Prove deadline has passed");

        // task.challenge.proof = _proof;
        // task.challenge.publicInputHash = _publicInputHash;

        // 验证证明，如果验证通过，调用_challengeFail；否则，调用_challengeSuccess
        bool success = _verifyProof(_proof, _publicInputHash);
        if (success) {
            _challengeFail(taskId);
        } else {
            _challengeSuccess(taskId);
        }

        task.status = Status.FINISHED;
        pendingTasks[msg.sender].remove(taskId);

        emit ProveEvent(taskId, msg.sender, _proof, _publicInputHash);
    }

    function newProve(bytes32 taskId, bytes calldata _proof) external {
        // TODO：区别在于，publicInputHash是hash(hash(CT||TK||wi)||result)，它应该是合约自己计算得出的，而不是由DCS传入
        // _dataHash = hash(CT||TK||wi)可以从task中获取，_result是DCS提交的结果，也可以从task中获取
        Task storage task = tasks[taskId];
        require(task.status == Status.CHALLENGED, "Task is not challenged");
        require(task.DCS == msg.sender, "Only DCS can prove");
        require(block.timestamp <= task.challenge.proveDeadline, "Prove deadline has passed");

        bytes32 _publicInputHash = sha256(abi.encodePacked(task.dataHash, task.result));

        // task.challenge.proof = _proof;
        // task.challenge.publicInputHash = _publicInputHash;

        // 验证证明，如果验证通过，调用_challengeFail；否则，调用_challengeSuccess
        bool success = _verifyProof(_proof, _publicInputHash);
        if (success) {
            _challengeFail(taskId);
        } else {
            _challengeSuccess(taskId);
        }

        task.status = Status.FINISHED;
        pendingTasks[msg.sender].remove(taskId);

        emit ProveEvent(taskId, msg.sender, _proof, _publicInputHash);
    }

    /* DCS管理 */
    // 1. DCS注册
    function registerDCS() external payable {
        // require(DCSdeposits[msg.sender] + msg.value >= MINIMAL_DCS_DEPOSIT, string(abi.encodePacked("Should deposit at least ", MINIMAL_DCS_DEPOSIT.toString(), " wei to register as an DCS.")));
        require(DCSdeposits[msg.sender] + msg.value >= MINIMAL_DCS_DEPOSIT, "Should deposit enough tokens to register as an DCS.");
        DCSdeposits[msg.sender] += msg.value;

        emit RegisterDCSEvent(msg.sender);
    }

    // 2. DCS注销
    function unregisterDCS() external {
        require(pendingTasks[msg.sender].isEmpty(), "DCS has pending tasks");
        payable(msg.sender).transfer(DCSdeposits[msg.sender]);
        DCSdeposits[msg.sender] = 0;

        emit UnregisterDCSEvent(msg.sender);
    }

    function queryDCSdeposit(address DCSaddr) external view returns (uint) {
        return DCSdeposits[DCSaddr];
    }

    /* 奖励管理 */
    // 1. DCS领取奖励
    function claimTaskReward(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == Status.SUBMITTED, "Task is not submitted");
        require(block.timestamp > task.challengeDeadline, "Task is still in challenge period");
        require(task.DCS == msg.sender, "Only DCS who submitted the result can claim reward");

        payable(task.dataUser).transfer(task.reward);
        task.status = Status.FINISHED;
        pendingTasks[msg.sender].remove(taskId);

        emit ClaimTaskRewardEvent(taskId, msg.sender);
    }

    // 2. Challenger领取奖励
    function claimChallengeReward(bytes32 taskId) external {
        Task storage task = tasks[taskId];
        require(task.status == Status.CHALLENGED, "Task is not challenged");
        require(block.timestamp > task.challenge.proveDeadline, "Task is still in prove period");
        require(task.challenge.challenger == msg.sender, "Only challenger can claim reward");

        _challengeSuccess(taskId);

        emit ClaimChallengeRewardEvent(taskId, msg.sender);
    }


    /* 辅助函数 */

    // 挑战成功的结算函数。挑战成功的情况包括：1.超出挑战期还没有提交proof；2.proof验证不通过
    function _challengeSuccess(bytes32 taskId) internal {
        Task storage task = tasks[taskId];
        // 1. DCS的deposit被清空，其中80%归challenger，20%归任务发起人dataUser
        uint deposit = DCSdeposits[task.DCS];
        DCSdeposits[task.DCS] = 0;
        uint compensation = deposit * 2 / 10;
        uint challengReward = deposit * 8 / 10;
        // 2. 转账，challenger获得challengeReward并拿回challenge.deposit，dataUser获得compensation并拿回task.reward
        payable(task.challenge.challenger).transfer(challengReward + task.challenge.deposit);
        payable(task.dataUser).transfer(compensation + task.reward);
        // 3. 结束任务
        task.status = Status.FINISHED;
        pendingTasks[task.DCS].remove(taskId);
    }

    // 挑战失败的处理函数。挑战失败的情况为：挑战期内提交了proof，且proof验证通过
    function _challengeFail(bytes32 taskId) internal {
        Task storage task = tasks[taskId];
        // 1. DCS获得challenge.deposit和任务酬金task.reward
        payable(task.DCS).transfer(task.challenge.deposit + task.reward);
        // 2. 结束任务
        task.status = Status.FINISHED;
        pendingTasks[task.DCS].remove(taskId);
    }

    // 验证zk proof
    function _verifyProof(bytes calldata proof, bytes32 publicInputHash) internal view returns (bool) {
        address _verifier = PLONK_VERIFIER;
        bool success;

        // 这里是morph的注释。aggrProof被我改名为proof了
        // 1. the first 12 * 32 (0x180) bytes of `aggrProof` is `accumulator`
        // 2. the rest bytes of `aggrProof` is the actual `batch_aggregated_proof`
        // 3. each byte of the `public_input_hash` should be converted to a `uint256` and the
        //    1024 (0x400) bytes should inserted between `accumulator` and `batch_aggregated_proof`.
        assembly {
            let p := mload(0x40)
            calldatacopy(p, proof.offset, 0x180)    // 因为用的calldatacopy等函数是对calldata的操作，所以proof必须是calldata类型
            for {
                let i := 0
            } lt(i, 0x400) {
                i := add(i, 0x20)
            } {
                mstore(add(p, sub(0x560, i)), and(publicInputHash, 0xff))
                publicInputHash := shr(8, publicInputHash)
            }
            calldatacopy(add(p, 0x580), add(proof.offset, 0x180), sub(proof.length, 0x180))

            success := staticcall(gas(), _verifier, p, add(proof.length, 0x400), 0x00, 0x00)
        }

        return success;
    }
}