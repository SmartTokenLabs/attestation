// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./libraries/VerifyAddressAttestation.sol";

contract STLTNMint is ERC20, ERC20Burnable, Ownable {

    using ECDSA for bytes32;

    //address public constant baycAddr = 0x3d8a0fB32b0F586FdC10447c22F477979dc526ec;
    address public baycAddr = 0x3d8a0fB32b0F586FdC10447c22F477979dc526ec;

    uint256 public mintLimit = 100000 * 1000000000000000000;
    mapping(address => uint256) private minted;

    address public constant attestorAddr = 0xe761Eb6e829DE49deaB008120733c1E35Acf77DB;

    constructor(address nftAddress) ERC20("TNMint", "TNM") {
        baycAddr = nftAddress;
    }

    function ownerMint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }

    function setMintLimit(uint256 amount) public onlyOwner {
        mintLimit = amount;
    }

    // Mint using attestation proving ownership of NFT holding address
    function mintAttest(
        bytes memory attestation,
        address to,
        uint256 amount
    ) public {
        address attestedAddress = VerifyAddressAttestation.verify(attestation, attestorAddr);

        mint(attestedAddress, to, amount);
    }

    // Mint using signed challenge
    function mintSig(
        bytes memory challenge,
        bytes memory signature,
        address to,
        uint256 amount
    ) public {
        (address sigAddress, ECDSA.RecoverError err) = verifySignature(challenge, signature);

        if (err != ECDSA.RecoverError.NoError){
            revert("Signature Error :-(");
        }

        mint(sigAddress, to, amount);
    }

    function verifySignature(bytes memory data, bytes memory signature) private pure returns(address, ECDSA.RecoverError) {
        return ECDSA.toEthSignedMessageHash(data)
        .tryRecover(signature);
    }

    // Mint directly using NFT holding address
    function mint(address to, uint256 amount) public {
        mint(msg.sender, to, amount);
    }

    function mint(
        address nftAddress,
        address to,
        uint256 amount
    ) private {
        if (!checkOwnership(nftAddress)) {
            revert("Address does not own required token :-(");
        }

        // TODO: check limit/quota
        if (!checkMintLimit(nftAddress)) {
            revert("Sorry you can not have more :-(");
        }

        minted[nftAddress] += amount;

        _mint(to, amount);
    }

    function checkMintLimit(address addr) private view returns (bool) {
        return minted[addr] < mintLimit;
    }

    function checkOwnership(address addr) private view returns (bool) {
        IERC721 dc = IERC721(baycAddr);

        return dc.balanceOf(addr) > 0;
    }
}
