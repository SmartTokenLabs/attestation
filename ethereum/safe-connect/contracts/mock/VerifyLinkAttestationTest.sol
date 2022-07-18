// SPDX-License-Identifier: MIT

pragma solidity ^0.8.5;

import "../libraries/VerifyLinkAttestation.sol";

contract VerifyLinkAttestationTest {
    function verifyAddressAttestation(bytes memory attestation, address attestorAddr) public view returns (address) {
        return VerifyLinkAttestation.verifyAddressAttestation(attestation, attestorAddr);
    }

    function verifyAddressAttestationTest(bytes memory attestation, address attestorAddr) external returns (address) {
        return VerifyLinkAttestation.verifyAddressAttestationTest(attestation, attestorAddr);
    }
}
