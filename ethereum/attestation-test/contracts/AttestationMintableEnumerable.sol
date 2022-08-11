// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";

import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Context.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import "hardhat/console.sol";
import "./library/VerifyAttestation.sol";

/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract AttestationMintableEnumerable is ERC721Enumerable, Ownable, VerifyAttestation {
    using Address for address;
    using Strings for uint256;
    
    // address payable private _contractCreator;
     
    string  constant JSON_FILE = ".json";
    string  constant _alchemyURI = "https://alchemynft.io/";
    
    address _attestorKey;
    address _issuerKey;
   
    event GenerateTokenId(address indexed addr, uint256 indexed id);
    event GenerateCommitment(address indexed addr, uint256 indexed id);
  
    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor (address attestorKey, address issuerKey) ERC721("Proof of Ticket","TICKET") Ownable(){
        _attestorKey = attestorKey;
        _issuerKey = issuerKey;
    }

    function updateAttestationKeys(address newattestorKey, address newIssuerKey) public onlyOwner {
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
        (subject, tokenBytes,, timeStampValid) = verifyTicketAttestation(attestation, _attestorKey, _issuerKey);
        tokenId = bytesToUint(tokenBytes);
        require(subject != address(0) && tokenId != 0 && timeStampValid, "Attestation not valid");
        _mint(subject, tokenId);
    }
    
    function burn(uint256 tokenId) public {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "AttestationMintable: Burn caller is not owner nor approved");
        _burn(tokenId);
    }
    
    function contractAddress() internal view returns (string memory) {
        return Strings.toHexString(uint160(address(this)), 20);
    }
    
    function endContract() external payable onlyOwner
    {
        selfdestruct(payable(owner()));
    }
}