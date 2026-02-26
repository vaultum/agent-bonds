// SPDX-License-Identifier: CC0-1.0
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    uint8 private immutable _tokenDecimals;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        _tokenDecimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function decimals() public view override returns (uint8) {
        return _tokenDecimals;
    }

    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        uint8,
        bytes32,
        bytes32
    ) external {
        require(block.timestamp > validAfter, "authorization_not_yet_valid");
        require(block.timestamp < validBefore, "authorization_expired");
        require(!authorizationState[from][nonce], "authorization_already_used");
        authorizationState[from][nonce] = true;
        _transfer(from, to, value);
    }
}
