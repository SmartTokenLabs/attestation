// SPDX-License-Identifier: MIT

pragma solidity ^0.8.5;

import "../libraries/VerifyAddressAttestation.sol";

contract VerifyAddressAttestationTest {
    function verify(bytes memory attestation, address attestorAddr) public view returns (address) {
        return VerifyAddressAttestation.verify(attestation, attestorAddr);
    }

    function verifyTest(bytes memory attestation, address attestorAddr) external returns (address) {
        return VerifyAddressAttestation.verifyTest(attestation, attestorAddr);
    }
}
