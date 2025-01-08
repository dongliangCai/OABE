// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library ArrayUtils {
    struct RandomRemoveableArray {
        bytes32[] taskList;
        mapping(bytes32 => uint) taskIndex;    // taskId => index
    }

    function push(RandomRemoveableArray storage self, bytes32 taskId) public {
        if (self.taskIndex[taskId] == 0) {
            self.taskList.push(taskId);
            self.taskIndex[taskId] = self.taskList.length;
        }
    }

    function remove(RandomRemoveableArray storage self, bytes32 taskId) public {
        if (self.taskIndex[taskId] != 0) {
            uint index = self.taskIndex[taskId] - 1;
            bytes32 lastTaskId = self.taskList[self.taskList.length - 1];

            self.taskList[index] = lastTaskId;
            self.taskIndex[lastTaskId] = index + 1;

            self.taskList.pop();
            delete self.taskIndex[taskId];
        }
    }

    function isEmpty(RandomRemoveableArray storage self) public view returns (bool) {
        return self.taskList.length == 0;
    }
}