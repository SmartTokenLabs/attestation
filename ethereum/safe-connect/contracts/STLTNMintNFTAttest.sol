// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./libraries/VerifyNFTAttestation.sol";

contract STLTNMintNFTAttest is ERC20, ERC20Burnable, Ownable {

    using ECDSA for bytes32;

    address public baycAddr = 0x3d8a0fB32b0F586FdC10447c22F477979dc526ec;

    address public constant attestorAddr = 0xe761Eb6e829DE49deaB008120733c1E35Acf77DB;

    // TODO: TokenId based minting limit
    // uint256 public mintLimit = 100000 * 1000000000000000000;
    // mapping(uint256 => uint256) private minted;

    constructor(address nftAddress) ERC20("TNMint", "TNM") {
        baycAddr = nftAddress;
    }

    function ownerMint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    // Mint using attestation proving ownership of NFT/s
    function mint(
        bytes memory attestation,
        address to,
        uint256 amount
    ) public {
        AttestedToken[] memory attestedTokens = VerifyNFTAttestation.verify(attestation, attestorAddr);

        if (attestedTokens.length > 0 && attestedTokens[0].addr != baycAddr){
            revert("Invalid NFT attestation :-(");
        }

        /*if (!checkMintLimit(nftAddress)) {
            revert("Sorry you can not have more :-(");
        }
        minted[nftAddress] += amount;*/

        _mint(to, amount);
    }

    /*function checkMintLimit(address addr) private view returns (bool) {
        return minted[addr] < mintLimit;
    }*/
}
