// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

// 这是用来测试向链上传递参数消耗的gas，用于测试参考论文的一个task需要消耗多少以太坊的gas
// （包括uploadTK和uploadCT两部分。ComputeMeta由cdl之后根据参考论文中的公式或meta compute的常数来估算）

contract UploadCTandTKtest {
    // bytes public CT;
    // bytes public TK;

    // // 上传CT和TK的函数
    // function uploadCT(bytes memory _CT) public {
    //     CT = _CT;
    // }

    // function uploadTK(bytes memory _TK) public {
    //     TK = _TK;
    // }

    bytes32[] public CT;
    bytes32[] public TK;

    // bytes32[] public newCT;
    // bytes32[] public newTK;

    function uploadCT(bytes32[] memory _CT) public {
        CT = _CT;
    }

    function uploadTK(bytes32[] memory _TK) public {
        TK = _TK;
    }

    // function uploadCTandTK(bytes32[] memory _CT, bytes32[] memory _TK) public {
    //     newCT = _CT;
    //     newTK = _TK;
    // }
}