// SPDX-License-Identifier: MIT
/* Retort contract for handling offer commitment and 'transmogrification' of NFTs */
/* AlphaWallet 2021 */

pragma solidity ^0.8.4;

struct NFToken { 
        address tokenAddr;
        uint256 tokenId;
        uint256 count;
        bytes auth; // authorisation; null if underlying contract doesn't support it
}

interface IVerifyAttestation {
    function verifyNFTAttestation(bytes memory attestation, address attestorAddress, address sender) external pure returns(NFToken[] memory tokens, string memory identifier, address payable subject, bool isValid);
    function verifyNFTAttestation(bytes memory attestation) external pure returns(NFToken[] memory tokens, string memory identifier, address payable subject, address attestorAddress);
    function verifyIDAttestation(bytes memory attestation) external pure returns(string memory identifier, address payable subject, address attestorAddress);
    function getNFTAttestationTimestamp(bytes memory attestation) external pure returns(string memory startTime, string memory endTime);
    function checkAttestationValidity(bytes memory nftAttestation, NFToken[] memory commitmentNFTs,
        string memory commitmentIdentifier, address attestorAddress, address sender) external pure returns(bool passedVerification, address payable subjectAddress);
    function checkAttestationValidity(bytes memory attestation, string memory identifier, address attestorAddress) 
        external pure returns(bool passedVerification, address payable subjectAddress);
}
