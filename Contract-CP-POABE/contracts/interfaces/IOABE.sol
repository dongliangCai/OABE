// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.24;

interface IOABE {
    /***********
     * Structs *
     ***********/

    enum Status {CREATED, SUBMITTED, CHALLENGED, FINISHED}

    struct Task {
        bytes32 id;

        bytes32 dataHash;   // 任务的数据哈希
        uint reward;

        uint challengeDeadline;

        Status status;

        address dataUser;
        address DCS;

            // cipherText: "",      // 由Storage Cloud上传的需要解密的密文
            // result: "",          // 任务结果，即解密得到的CT'（图中步骤6），由Decryption Cloud Server提交

        bytes32 result;    // 外包解密的结果。即论文中的T

        Challenge challenge;
    }

    struct Challenge {
        address challenger;
        uint deposit;

        uint proveDeadline;     // zk proof提交截止时间

        // bytes proof;                // zk proof
        // bytes32 publicInputHash;    // zk proof的hash
    }

    /***********
     * Errors *
     ***********/

    // /// @notice error zero address
    // error ErrZeroAddress();

    /**********
     * Events *
     **********/
    
    event CreateTaskEvent(bytes32 indexed dataHash, bytes32 indexed taskId, address indexed dataUser, uint reward);
    event SubmitResultEvent(bytes32 indexed taskId, address indexed DCS, bytes32 result);
    event ChallengeEvent(bytes32 indexed taskId, address indexed challenger, uint deposit);
    event ProveEvent(bytes32 indexed taskId, address indexed DCS, bytes proof, bytes32 publicInputHash);

    event RegisterDCSEvent(address indexed DCS);
    event UnregisterDCSEvent(address indexed DCS);

    event ClaimTaskRewardEvent(bytes32 indexed taskId, address indexed DCS);
    event ClaimChallengeRewardEvent(bytes32 indexed taskId, address indexed challenger);

    
    /*************************
     * Public View Functions *
     *************************/

    /*****************************
     * Public Mutating Functions *
     *****************************/

    /* 流程 */
    // 1. DataUser发布任务
    function createTask(bytes32 _dataHash) external payable returns (bytes32) ;
    // 2. DecryptionCloudServer(DCS)提交结果
    function submitResult(bytes32 taskId, bytes32 _result) external ;
    // 3. Challenger质疑
    function challenge(bytes32 taskId) external payable ;
    // 4. DCS提交证明
    function prove(bytes32 taskId, bytes memory proof, bytes32 _publicInputHash) external ;

    /* DCS管理 */
    // 1. DCS注册
    function registerDCS() external payable ;
    // 2. DCS注销
    function unregisterDCS() external ;

    /* 奖励管理 */
    // 1. DCS领取奖励
    function claimTaskReward(bytes32 taskId) external ;
    // 2. Challenger领取奖励
    function claimChallengeReward(bytes32 taskId) external ;


    /* 辅助函数 */
    // 辅助函数都是internal的，不能写在interface里，所以这里没有，都在具体实现的.sol里

    // // 挑战成功的结算函数。挑战成功的情况包括：1.超出挑战期还没有提交proof；2.proof验证不通过
    // function _challengeSuccess(bytes32 taskId) internal ;

    // // 挑战失败的处理函数。挑战失败的情况为：挑战期内提交了proof，且proof验证通过
    // function _challengeFail(bytes32 taskId) internal ;

    // // 验证zk proof
    // function _verifyProof(bytes calldata proof, bytes32 publicInputHash) external view returns (bool);

}
