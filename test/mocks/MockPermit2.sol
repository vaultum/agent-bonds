// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockPermit2 {
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    mapping(address => mapping(address => mapping(address => uint160))) public allowanceByOwnerTokenSpender;

    function permit(address owner, PermitSingle calldata permitSingle, bytes calldata) external {
        require(block.timestamp <= permitSingle.sigDeadline, "permit_expired");
        require(permitSingle.spender == msg.sender, "spender_mismatch");
        allowanceByOwnerTokenSpender[owner][permitSingle.details.token][permitSingle.spender] = permitSingle.details
            .amount;
    }

    function transferFrom(address from, address to, uint160 amount, address token) external {
        uint160 allowed = allowanceByOwnerTokenSpender[from][token][msg.sender];
        require(allowed >= amount, "insufficient_allowance");
        allowanceByOwnerTokenSpender[from][token][msg.sender] = allowed - amount;
        IERC20(token).transferFrom(from, to, amount);
    }
}
