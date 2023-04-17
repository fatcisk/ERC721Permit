// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {ERC721Permit, MockERC721Permit} from "../src/mocks/MockERC721Permit.sol";

contract ERC721PermitTest is Test {
    MockERC721Permit token;

    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    struct _TestArgs {
        address owner;
        address spender;
        uint256 tokenId;
        uint256 deadline;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 privateKey;
        uint256 nonce;
    }

    function setUp() public {
        token = new MockERC721Permit("NFTToken", "NFTT");
    }

    function _testArgs() internal pure returns (_TestArgs memory args) {
        args.privateKey = 0xA11CE;
        args.owner = vm.addr(0xA11CE);
        args.spender = address(1);
        args.tokenId = 1;
        args.deadline = 1681705905;
    }

    function _signPermit(_TestArgs memory args) internal view {
        bytes32 innerHash =
            keccak256(abi.encode(PERMIT_TYPEHASH, args.owner, args.spender, args.tokenId, args.nonce, args.deadline));
        bytes32 domainSeparator = token.DOMAIN_SEPARATOR();
        bytes32 outerHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, innerHash));
        (args.v, args.r, args.s) = vm.sign(args.privateKey, outerHash);
    }

    function _checkPermitEmitsAprovalEvent(_TestArgs memory args) internal {
        vm.expectEmit(true, true, true, true);
        emit Approval(args.owner, args.spender, args.tokenId);
    }

    function _checkApprovedAndNonce(_TestArgs memory args) internal {
        assertEq(token.getApproved(args.tokenId), args.spender);
        assertEq(token.nonces(args.tokenId), args.nonce + 1);
    }

    function _permit(_TestArgs memory args) internal {
        token.permit(args.owner, args.spender, args.tokenId, args.deadline, args.v, args.r, args.s);
    }

    function _mintToken(_TestArgs memory args) internal {
        vm.prank(args.owner);
        token.mint(args.tokenId);
    }

    function testPermit(uint256) public {
        _TestArgs memory args = _testArgs();

        _mintToken(args);

        _signPermit(args);

        _checkPermitEmitsAprovalEvent(args);

        _permit(args);

        _checkApprovedAndNonce(args);
    }

    function testUsePermit(uint256) public {
        _TestArgs memory args = _testArgs();

        _mintToken(args);

        _signPermit(args);

        _permit(args);

        vm.prank(args.spender);
        vm.expectEmit(true, true, true, true);
        emit Transfer(args.owner, address(2), args.tokenId);
        token.transferFrom(args.owner, address(2), args.tokenId);

        assertEq(token.ownerOf(args.tokenId), address(2));
    }

    function testPermitReplayReverts(uint256) public {
        _TestArgs memory args = _testArgs();

        _mintToken(args);

        _signPermit(args);

        _checkPermitEmitsAprovalEvent(args);

        _permit(args);

        vm.expectRevert(ERC721Permit.InvalidPermit.selector);
        _permit(args);
    }

    function testBadDeadlineReverts(uint256) public {
        _TestArgs memory args = _testArgs();

        _mintToken(args);

        _signPermit(args);

        vm.expectRevert(ERC721Permit.InvalidPermit.selector);
        args.deadline += 1;
        _permit(args);
    }

    function testPastDeadlineReverts(uint256) public {
        _TestArgs memory args = _testArgs();

        _mintToken(args);

        _signPermit(args);

        vm.expectRevert(ERC721Permit.PermitExpired.selector);
        vm.warp(args.deadline + 1);
        _permit(args);
    }

    function testBadNonceReverts(uint256) public {
        _TestArgs memory args = _testArgs();
        args.nonce = 99;

        _mintToken(args);

        _signPermit(args);

        vm.expectRevert(ERC721Permit.InvalidPermit.selector);
        _permit(args);
    }
}
