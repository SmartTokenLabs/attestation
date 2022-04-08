/* Attestation decode and validation */
/* AlphaWallet 2021 */
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "./VerifyTicket.sol";

contract VerifyTicketLegacy is VerifyTicket {

    constructor() VerifyTicket() {}

    function decodeCommitment (bytes memory attestation, uint256 decodeIndex) internal pure override returns (bytes memory commitment) {

        (commitment, ) = recoverCommitment(attestation, decodeIndex); 
    }
}