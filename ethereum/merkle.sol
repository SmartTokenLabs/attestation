contract merkle {

    address[] attestors;

    constructor(address[] validAttestors)
    {
        attestors = validAttestors;
    }

    function doMerkle(
        bytes32[] hashes,
        bytes32 attribute,
        bytes32 value,
        uint8 v,
        bytes32 r,
        bytes32 s) returns(bool)
    {
        bytes32 salt = hashes[0];
        bytes32 hashOfAttributeValuePair = sha256(abi.encodePacked(salt, attribute, value));
        require(hashOfAttributeValuePair == hashes[1]);
        for(uint i = 2; i < hashes.length - 1; i++)
        {
            //hash the previous one with the next one and see if it matches
            bytes32 hashToValidate = sha256(abi.encodePacked(hashes[i - 1], hashes[i]));
            require(hashToValidate == hashes[i + 1]);
        }
        address signer = ecrecover(hashes[hashes.length - 1], v, r, s);
        for(i = 0; i < attestors.length; i++)
        {
            if(signer == attestors[i]) return true;
        }
        return false;
    }

}
