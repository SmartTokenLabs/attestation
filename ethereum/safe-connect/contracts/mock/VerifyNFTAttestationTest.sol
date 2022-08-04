// SPDX-License-Identifier: MIT

pragma solidity ^0.8.5;

import "../libraries/VerifyNFTAttestation.sol";

contract VerifyNFTAttestationTest {
    function verify(bytes memory attestation, address attestorAddr) public view returns (AttestedToken[] memory) {
        return VerifyNFTAttestation.verify(attestation, attestorAddr);
    }

    function verifyTest(bytes memory attestation, address attestorAddr) external returns (AttestedToken[] memory) {
        return VerifyNFTAttestation.verifyTest(attestation, attestorAddr);
    }

    function numberOfTokens(bytes memory nftBytes) public view returns (uint) {
        return VerifyNFTAttestation.numberOfTokens(nftBytes);
    }

    function decodeTokens(bytes memory nftBytes) public view returns (AttestedToken[] memory) {
        return VerifyNFTAttestation.decodeTokens(nftBytes);
    }
}
