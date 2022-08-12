// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./SolRsaVerify.sol";
import "./LinkAttestUtils.sol";
import "hardhat/console.sol";

library VerifyAddressAttestation {
    using ECDSA for bytes32;

    function verifyTest(bytes memory attestation, address attestorAddr) internal view returns (address attestedAddress) {
        address linkedAddress;

        (attestedAddress, linkedAddress) = decodeAttestation(attestation, attestorAddr);

    }

    function verify(bytes memory attestation, address attestorAddr) internal view returns (address attestedAddress) {
        address linkedAddress;

        (attestedAddress, linkedAddress) = decodeAttestation(attestation, attestorAddr);

        if (msg.sender != linkedAddress){
            revert("Linked address does not match sender :-(");
        }
    }

    function decodeAttestation(bytes memory attestation, address attestorAddr)
        internal
        view
        returns (address attestedAddress, address linkedAddress)
    {
        uint256 length;
        uint256 hashIndex;
        uint256 decodeIndex;

        bytes memory curBytes;
        bytes memory sigData;

        bytes memory pubKeyModulus;
        bytes memory pubKeyExponent;

        // Main header (Signed link attestation)
        // // original code
        // (length, hashIndex, ) = decodeLength(attestation, 0); // (total length, primary header)
        (, hashIndex, ) = LinkAttestUtils.decodeLength(attestation, 0); // (total length, primary header)

        // Link attestation structure
        (length, decodeIndex, ) = LinkAttestUtils.decodeLength(attestation, hashIndex);

        bytes memory linkEncoded = LinkAttestUtils.copyDataBlock(attestation, hashIndex, (length + decodeIndex) - hashIndex); // Encoded data for link attestation

        (length, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // linked ethereum address

        linkedAddress = LinkAttestUtils.bytesToAddress(curBytes);

        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // Linked attestation


        (attestedAddress, pubKeyModulus, pubKeyExponent) = decodeAddressAttestation(curBytes, attestorAddr);

        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // validity

        LinkAttestUtils.validateExpiry(curBytes);

        // TODO: Check for context field
        //(length, curBytes, decodeIndex, ) = decodeElement(attestation, decodeIndex); // context

        (, decodeIndex, ) = LinkAttestUtils.decodeLength(attestation, decodeIndex); // object identifier
        (, , decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex);

        (, sigData, decodeIndex) = LinkAttestUtils.decodeElementOffset(attestation, decodeIndex, 1); // Signature


        if (SolRsaVerify.pkcs1Sha256VerifyRaw(linkEncoded, sigData, pubKeyExponent, pubKeyModulus) != 0) {
            revert("RSA verification failed :-(");
        }
    }

    function decodeAddressAttestation(bytes memory attestation, address attestorAddr)
        internal
        view
        returns (
            address attestedAddress,
            bytes memory pubKeyModulus,
            bytes memory pubKeyExponent
        )
    {
        uint256 length;
        uint256 hashIndex;
        uint256 decodeIndex;

        bytes memory curBytes;
        bytes memory sigData;

        (, hashIndex, ) = LinkAttestUtils.decodeLength(attestation, 0); // (total length, primary header)


        // Address attestation structure
        (length, decodeIndex, ) = LinkAttestUtils.decodeLength(attestation, hashIndex);

        bytes memory addressEncoded = LinkAttestUtils.copyDataBlock(attestation, hashIndex, (length + decodeIndex) - hashIndex); // Encoded data for address attestation

        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // subject public key (public key of link attestation signature)


        (pubKeyModulus, pubKeyExponent) = LinkAttestUtils.decodeRsaPublicKey(curBytes);

        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // Attested ethereum address

        attestedAddress = LinkAttestUtils.bytesToAddress(curBytes);


        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // validity

        LinkAttestUtils.validateExpiry(curBytes);

        // TODO: Check for context field
        //(, , decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // context

        (, decodeIndex, ) = LinkAttestUtils.decodeLength(attestation, decodeIndex); // Algorithm info
        (, , decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex);

        (, sigData, decodeIndex) = LinkAttestUtils.decodeElementOffset(attestation, decodeIndex, 1); // Signature

        address recoveredAddress = keccak256(addressEncoded).recover(sigData);

        if (recoveredAddress != attestorAddr) {
            revert("Signature key does not match attestor key :-(");
        }
    }

}
