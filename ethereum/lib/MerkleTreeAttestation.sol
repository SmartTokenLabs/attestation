pragma solidity ^0.4.17;
pragma experimental ABIEncoderV2;
import "../merkle";

/* Test data TODO: redo it with hmac

    Attestation memory country;
    country.key = "c";     \63 Country
    country.value = "SG"; /* \53\47 Singapore
    salt = 0xc257274276a4e539741ca11b590b9447b26a8051;
    merklePath  = {
        0x5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03,
        0xe258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317
    }

    expected_root_hash = 0xe07c2eae216a596ad2d4b7dbff488899d651f367abea039ecb13e98c212e1a2c

/*

Leaf node hash:

$ echo 00: 63 53 47 c2 57 27 42 76 a4 e5 39 74 1c a1 1b 59 0b 94 47 b2 6a 80 51 | xxd -r -c 32 | sha256sum
eeab27f00a1460a4409643abbe705d0d67b8ea4b9027130e2672904f76e824da

Level 1 hash:
$ (echo 00: eeab27f00a1460a4409643abbe705d0d67b8ea4b9027130e2672904f76e824da;      echo 20: 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03) | xxd -g 32 -c 32 -r | sha256sum
5da0fe7145fda91d4516cb3619b3463fd9318c3475d5f578fd3d1fc189084bbe

Level 2 hash:
$ (echo 00: 5da0fe7145fda91d4516cb3619b3463fd9318c3475d5f578fd3d1fc189084bbe;      echo 20: e258d248fda94c63753607f7c4494ee0fcbe92f1a76bfdac795c9d84101eb317) | xxd -g 32 -c 32 -r | sha256sum
e07c2eae216a596ad2d4b7dbff488899d651f367abea039ecb13e98c212e1a2c

*/

    /* TODO: 1) make a cheap hmac (with XOR) and use it here in place of the sha256 */

contract MerkleTreeAttestation {
    mapping(address => Attestation[]) records;

    struct Attestation
    {
        bytes32[] merklePath;
        bool valid;
        uint8 v;
        bytes32 r;
        bytes32 s;
        address attestor;
        address recipient;
        bytes32 salt;
        bytes32 key;
        bytes32 val;
    }

    function validate(Attestation attestation) public view returns(bool)
    {
        bytes32 keyValHashed = sha256(abi.encodePacked(
            attestation.key,
            attestation.val,
            attestation.salt)
        );
        require(keyValHashed == attestation.merklePath[0]);
        require(msg.sender == attestation.recipient);
        address signer = ecrecover(keyValHashed, attestation.v, attestation.r, attestation.s);
        require(signer == attestation.attestor);
        for(uint i = 0; i < attestation.merklePath.length - 2; i++)
        {
            require( attestation.merklePath[i + 2] ==
            sha256(
                abi.encodePacked(
                    attestation.merklePath[i],
                    attestation.merklePath[i + 1])
                )
            );
        }
        return true;
    }

}
