// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import "hardhat/console.sol";
import "./interface/IVerifyTicket.sol";

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract AttestationMintableEnumerable is ERC721Enumerable, Ownable {
    using Address for address;
    using Strings for uint256;
    
    // address payable private _contractCreator;
     
    string  constant JSON_FILE = ".json";
    string  constant _alchemyURI = "https://alchemynft.io/";
    
    address _attestorKey;
    address _issuerKey;
    address _verificationAddress;
   
    event GenerateTokenId(address indexed addr, uint256 indexed id);
    event GenerateCommitment(address indexed addr, uint256 indexed id);
  
    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor (address verificationAddress, address attestorKey, address issuerKey) ERC721("Proof of Ticket","TICKET") Ownable(){
        _verificationAddress = verificationAddress;
        _attestorKey = attestorKey;
        _issuerKey = issuerKey;
    }

    function updateVericationAddress(address newVerifyAddress) public onlyOwner
    {
        _verificationAddress = newVerifyAddress;
    }

    function updateAttestationKeys(address newattestorKey, address newIssuerKey) public onlyOwner
    {
        _attestorKey = newattestorKey;
        _issuerKey = newIssuerKey;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "AttestationMintable: URI query for nonexistent token");
        return string(abi.encodePacked(_alchemyURI, block.chainid.toString(), "/", contractAddress(), "/", tokenId.toString(), JSON_FILE));
    }
    
    function mintUsingAttestation(bytes memory attestation) public returns (uint256 tokenId) {
        address subject;
        bytes memory tokenBytes;
        bool timeStampValid;
        IVerifyTicket verifier = IVerifyTicket(_verificationAddress);
        (subject, tokenBytes,, timeStampValid) = verifier.verifyTicketAttestation(attestation, _attestorKey, _issuerKey);
        tokenId = bytesToUint(tokenBytes);
        require(subject != address(0) && tokenId != 0 && timeStampValid, "Attestation not valid");
        _mint(subject, tokenId);
    }
    
    function burn(uint256 tokenId) public {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "AttestationMintable: Burn caller is not owner nor approved");
        _burn(tokenId);
    }
    
    //Truncates if input is greater than 32 bytes; we only handle 32 byte values.
    function bytesToUint(bytes memory b) private pure returns (uint256 conv)
    {
        if (b.length < 0x20) //if b is less than 32 bytes we need to pad to get correct value
        {
            bytes memory b2 = new bytes(32);
            uint startCopy = 0x20 + 0x20 - b.length;
            assembly
            {
                let bcc := add(b, 0x20)
                let bbc := add(b2, startCopy)
                mstore(bbc, mload(bcc))
                conv := mload(add(b2, 32))
            }
        }
        else
        {
            assembly
            {
                conv := mload(add(b, 32))
            }
        }
    }

    function contractAddress() internal view returns (string memory) {
        return Strings.toHexString(uint160(address(this)), 20);
    }
    
    function endContract() external payable onlyOwner
    {
        selfdestruct(payable(owner()));
    }

}