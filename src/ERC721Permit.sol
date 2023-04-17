// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "../src/IERC721Permit.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

abstract contract ERC721Permit is IERC721Permit, ERC721 {
    uint256 private constant NONCES_SEED = 0x79385023;

    error InvalidPermit();
    error PermitExpired();
    error InvalidOwner();

    function permit(
        address owner,
        address spender,
        uint256 tokenId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        bytes32 ds = DOMAIN_SEPARATOR();
        assembly {
          let m := mload(0x40) // grab the free memory pointer.
          // revert if the block timestamp is greater than 'deadline.
          if gt(timestamp(), deadline) {
            mstore(0x00, 0x1a15a3cc) // bytes4(keccak256("PermitExpired()"))
            revert(0x1c, 0x04)
          }
          // retrive the nonce slot and its value
          mstore(0x00, tokenId)
          mstore(0x20, NONCES_SEED)
          let nonceSlot := keccak256(0x00, 0x40)
          let nonceValue := sload(nonceSlot)
          // increment the nonce and store it
          sstore(nonceSlot, add(nonceValue, 1))
          // clean garbage allocations
          owner := shr(96, shl(96, owner))
          spender := shr(96, shl(96, spender))
          // prepare the digest.
          // `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`.
          mstore(m, 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9)
          mstore(add(m, 0x20), owner)
          mstore(add(m, 0x40), spender)
          mstore(add(m, 0x60), tokenId)
          mstore(add(m, 0x80), nonceValue)
          mstore(add(m, 0xa0), deadline)
          mstore(0, 0x1901)
          mstore(0x20, ds)
          mstore(0x40, keccak256(m, 0xc0))
          // build ecrecover calldata
          mstore(0, keccak256(0x1e, 0x42))
          mstore(0x20, and(0xff, v)) //little bit masking here
          mstore(0x40, r)
          mstore(0x60, s)
          pop(staticcall(gas(), 1, 0, 0x80, 0x20, 0x20))

          if iszero(eq(mload(returndatasize()), owner)) {
              mstore(0x00, 0xddafbaef) // `InvalidPermit()`.
              revert(0x1c, 0x04)
          }
        }

        if(!_isApprovedOrOwner(owner, tokenId)) revert InvalidOwner();
        _approve(spender, tokenId);
    }

    // return current token nonce
    function nonces(uint256 tokenId) public view returns (uint256 res) {
        assembly {
          mstore(0x00, tokenId)
          mstore(0x20, NONCES_SEED)
          res := sload(keccak256(0x00, 0x40))
        }
    }

    // return EIP712 DOMAIN_SEPARATOR
    function DOMAIN_SEPARATOR() public view returns (bytes32 result) {
        assembly {
          result := mload(0x40) // get the free memory pointer
        }
        bytes32 hashedName = keccak256(bytes(name()));
        assembly {
          let m := result
          // keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)').
          mstore(m, 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f)
          mstore(add(m, 0x20), hashedName)
          // allocate the version => keccak256(bytes('1')).
          mstore(add(m, 0x40), 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6)
          mstore(add(m, 0x60), chainid())
          mstore(add(m, 0x80), address())
          result := keccak256(m, 0xa0) //hash the next 160 bytes (0xa0) starting from 'm'.
        }
    }

    // override from ERC721 to include the interface of this EIP
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return
            interfaceId == type(IERC721Permit).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
