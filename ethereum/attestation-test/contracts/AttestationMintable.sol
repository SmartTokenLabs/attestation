// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./library/VerifyAttestation.sol";

contract AttestationMintable is ERC721, Ownable, VerifyAttestation {
    using Address for address;
    using Strings for uint256;
    
    string private _conference_id = "55";

    string private constant JSON_FILE = ".json";
    string private constant __baseURI = "https://alchemynft.io/";
    
    address _attestorKey;
    address _issuerKey;
    
    constructor (address attestorKey, address issuerKey) ERC721("Proof of Ticket", "TICKET") {
        _attestorKey = attestorKey;
        _issuerKey = issuerKey;
    }

    function contractURI() public view returns(string memory) {
        return string(abi.encodePacked(__baseURI, "contract/", symbol(), JSON_FILE));
    }

    function updateAttestationKeys(address newattestorKey, address newIssuerKey) public onlyOwner {
        _attestorKey = newattestorKey;
        _issuerKey = newIssuerKey;
    }

    function updateConferenceID(string memory newConferenceID) public onlyOwner {
        _conference_id = newConferenceID;
    }

    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "AttestationMintable: invalid token ID");
        return string(abi.encodePacked(__baseURI, block.chainid.toString(), "/", contractAddress(), "/", tokenId.toString(), JSON_FILE));
    }

    function verify(bytes memory attestation) public view returns (address attestor, address ticketIssuer, address subject, bytes memory ticketId, bytes memory conferenceId, bool attestationValid){
        ( attestor, ticketIssuer, subject, ticketId, conferenceId, attestationValid) = _verifyTicketAttestation(attestation);
    }
    
    function mintUsingAttestation(bytes memory attestation) public returns (uint256 tokenId) {
        address subject;
        bytes memory tokenBytes;
        bytes memory conferenceBytes;
        bool timeStampValid;

        (subject, tokenBytes, conferenceBytes, timeStampValid) = verifyTicketAttestation(attestation, _attestorKey, _issuerKey);
        tokenId = bytesToUint(tokenBytes);
        //Use the following line if conferenceId is in use
        //require(subject != address(0) && tokenId != 0 && timeStampValid && compareStrings(conferenceBytes, _conference_id), "Attestation not valid");
        require(subject != address(0) && tokenId != 0 && timeStampValid, "Attestation not valid");
        require(tokenBytes.length < 33, "TokenID overflow");
        _mint(subject, tokenId);
    }
    
    function burn(uint256 tokenId) public {
        require(_exists(tokenId), "AttestationMintable: URI query for nonexistent token");
        require(_isApprovedOrOwner(_msgSender(), tokenId), "AttestationMintable: Burn caller is not owner nor approved");
        _burn(tokenId);
    }
    
    function contractAddress() internal view returns (string memory) {
        return Strings.toHexString(uint160(address(this)), 20);
    }
    
    function endContract() public payable onlyOwner {
        selfdestruct(payable(owner()));
    }

    function compareStrings(bytes memory s1, string memory s2) private pure returns(bool) {
        return keccak256(abi.encodePacked(s1)) == keccak256(abi.encodePacked(s2));
    }
}