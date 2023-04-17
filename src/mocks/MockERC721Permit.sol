// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "../../src/ERC721Permit.sol";

contract MockERC721Permit is ERC721Permit {
    constructor(string memory _name, string memory _symbol) ERC721(_name, _symbol) {}

    function mint(uint256 tokenId) public {
        _mint(msg.sender, tokenId);
    }
}
