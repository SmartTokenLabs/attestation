// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./SolRsaVerify.sol";
import "./LinkAttestUtils.sol";
import "hardhat/console.sol";

library VerifyNFTAttestation {
    using ECDSA for bytes32;

    function verifyTest(bytes memory attestation, address attestorAddr) internal view returns (AttestedToken[] memory attestedTokens) {
        address linkedAddress;

        (attestedTokens, linkedAddress) = decodeAttestation(attestation, attestorAddr);

    }

    function verify(bytes memory attestation, address attestorAddr) internal view returns (AttestedToken[] memory attestedTokens) {
        address linkedAddress;

        (attestedTokens, linkedAddress) = decodeAttestation(attestation, attestorAddr);

        if (msg.sender != linkedAddress){
            revert("Linked address does not match sender :-(");
        }
    }

    function decodeAttestation(bytes memory attestation, address attestorAddr)
        internal
        view
        returns (AttestedToken[] memory tokens, address linkedAddress)
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


        (tokens, pubKeyModulus, pubKeyExponent) = decodeAddressAttestation(curBytes, attestorAddr);

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
            AttestedToken[] memory tokens,
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

        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // Attested tokens

        tokens = decodeTokens(curBytes);


        (, curBytes, decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex); // validity

        LinkAttestUtils.validateExpiry(curBytes);

        // TODO: Check for context field
        //(length, curBytes, decodeIndex, ) = decodeElement(attestation, decodeIndex); // context


        (, decodeIndex, ) = LinkAttestUtils.decodeLength(attestation, decodeIndex); // Algorithm info
        (, , decodeIndex, ) = LinkAttestUtils.decodeElement(attestation, decodeIndex);

        (, sigData, decodeIndex) = LinkAttestUtils.decodeElementOffset(attestation, decodeIndex, 1); // Signature

        address recoveredAddress = keccak256(addressEncoded).recover(sigData);

        if (recoveredAddress != attestorAddr) {
            revert("Signature key does not match attestor key :-(");
        }
    }

    function decodeTokens(bytes memory tokensBytes) public view returns (AttestedToken[] memory tokens) {

        uint256 tokenIndex = 0;
        uint256 length;
        uint256 fieldIndex;
        bytes memory token;
        bytes memory curBytes;
        uint index = 0;

        uint numTokens = numberOfElements(tokensBytes);

        tokens = new AttestedToken[](numTokens);

        while (tokenIndex < tokensBytes.length){

            // Sequence of token data
            (length, token, tokenIndex, ) = LinkAttestUtils.decodeElement(tokensBytes, tokenIndex);

            (, curBytes, fieldIndex, ) = LinkAttestUtils.decodeElement(token, 0); // Address
            AttestedToken memory tok = AttestedToken(LinkAttestUtils.bytesToAddress(curBytes), 0, new uint[](0));

            (, curBytes, fieldIndex, ) = LinkAttestUtils.decodeElement(token, fieldIndex); // Chain ID
            tok.chainId = LinkAttestUtils.bytesToUint(curBytes);

            if (fieldIndex < length){
                (, curBytes, fieldIndex, ) = LinkAttestUtils.decodeElement(token, fieldIndex); // Token IDs
                tok.tokenIds = decodeTokenIds(curBytes);
            }

            tokens[index] = tok;

            index++;
        }
    }

    function decodeTokenIds(bytes memory tokenIdBytes) public view returns (uint[] memory tokenIds){

        uint idIndex = 0;
        uint curIndex = 0;
        bytes memory curBytes;
        uint numIds = numberOfElements(tokenIdBytes);

        tokenIds = new uint[](numIds);

        while (curIndex < tokenIdBytes.length){

            (, curBytes, curIndex, ) = LinkAttestUtils.decodeElement(tokenIdBytes, curIndex); // Token ID
            tokenIds[idIndex] = LinkAttestUtils.bytesToUint(curBytes);

            idIndex++;
        }

    }

    function numberOfElements(bytes memory tokensBytes) public view returns (uint num){

        uint256 index = 0;
        uint256 length;
        num = 0;

        while (index < tokensBytes.length){
            (length, ,) = LinkAttestUtils.decodeLength(tokensBytes, index);
            num++;

            index += length + 2; // +2 for the sequence header, which is not included in length
        }
    }
}

struct AttestedToken {
    address addr;
    uint chainId;
    uint[] tokenIds;
}
