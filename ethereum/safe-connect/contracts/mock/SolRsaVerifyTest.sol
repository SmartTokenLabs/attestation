// SPDX-License-Identifier: MIT

pragma solidity ^0.8.5;

import "../libraries/SolRsaVerify.sol";

contract SolRsaVerifyTest {
    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _data to verify
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return 0 if success, >0 otherwise
     */
    function pkcs1Sha256VerifyRawTest(
        bytes memory _data,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (uint256) {
        return SolRsaVerify.pkcs1Sha256VerifyRaw(_data, _s, _e, _m);
    }

    /** @dev Verifies a PKCSv1.5 SHA256 signature
     * @param _sha256 is the sha256 of the data
     * @param _s is the signature
     * @param _e is the exponent
     * @param _m is the modulus
     * @return 0 if success, >0 otherwise
     */
    function pkcs1Sha256Verify(
        bytes32 _sha256,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) public view returns (uint256) {
        return SolRsaVerify.pkcs1Sha256Verify(_sha256, _s, _e, _m);
    }

    function pkcs1Sha256VerifyRawTestGasEstimate(
        bytes memory _data,
        bytes memory _s,
        bytes memory _e,
        bytes memory _m
    ) external returns (uint256) {
        return SolRsaVerify.pkcs1Sha256VerifyRaw(_data, _s, _e, _m);
    }
}
