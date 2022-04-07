// SPDX-License-Identifier: MIT
/* Retort contract for handling offer commitment and 'transmogrification' of NFTs */
/* AlphaWallet 2021 */

pragma solidity ^0.8.4;

interface IVerifyTicket {
    function verifyTicketAttestation(bytes memory attestation) public view returns(address attestor, address ticketIssuer, address payable subject, bytes memory ticketId, bytes memory conferenceId, bool timeStampValid);
    function checkAttestationTimestamp(bytes memory attestation) public view returns(bool timeStampValid);
}
