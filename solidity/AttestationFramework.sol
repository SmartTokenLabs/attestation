pragma solidity ^0.4.17;
pragma experimental ABIEncoderV2;
contract AttestationFramework
{
    
    address[] authorities;
    
    struct Attestation 
    {
        bytes32[] attestationSaltedMerkleTree;
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
    
    mapping(address => Attestation[]) records;
    
    constructor(address[] initialAuthorities) public
    {
        authorities = initialAuthorities;
    }
    
    function addAuthority(address newAuthority) public
    {
        bool isAuthorised = AttestationFramework.isAuthorised(msg.sender);
        require(isAuthorised);
        authorities.push(newAuthority);
    }
    
    function isAuthorised(address attestor) internal view returns(bool) 
    {
        for(uint i = 0; i < authorities.length; i++) 
        {
            if(attestor == authorities[i]) 
            {
                return true;
            }
        }
        return false;
    }
    
    function setAttestation(Attestation attestation) public 
    {
        require(AttestationFramework.isAuthorised(msg.sender));
        require(attestation.attestor == msg.sender);
        require(validateMerkle(attestation));
        records[attestation.recipient].push(attestation);
    }
    
    function revokeAttestation(Attestation attestation) public view
    {
        require(msg.sender == attestation.attestor);
        attestation.valid = false;
    }
    
    function validateMerkle(Attestation attestation) public view returns(bool) 
    {
        bytes32 keyValHashed = keccak256(abi.encodePacked(
            attestation.key, 
            attestation.val, 
            attestation.salt)
        );
        require(keyValHashed == attestation.attestationSaltedMerkleTree[0]);
        require(msg.sender == attestation.recipient);
        address signer = ecrecover(keyValHashed, attestation.v, attestation.r, attestation.s);
        require(signer == attestation.attestor);
        for(uint i = 0; i < attestation.attestationSaltedMerkleTree.length - 2; i++) 
        {
            require( attestation.attestationSaltedMerkleTree[i + 2] == 
            keccak256(
                abi.encodePacked(
                    attestation.attestationSaltedMerkleTree[i], 
                    attestation.attestationSaltedMerkleTree[i + 1])
                )
            );
            
        }
        return true;
    }
          
}
