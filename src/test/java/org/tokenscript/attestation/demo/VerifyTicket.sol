/* Attestation decode and validation */
/* AlphaWallet 2021 */

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2; 

contract VerifyAttestation {
    address payable owner;

    bytes1 constant BOOLEAN_TAG         = bytes1(0x01);
    bytes1 constant INTEGER_TAG         = bytes1(0x02);
    bytes1 constant BIT_STRING_TAG      = bytes1(0x03);
    bytes1 constant OCTET_STRING_TAG    = bytes1(0x04);
    bytes1 constant NULL_TAG            = bytes1(0x05);
    bytes1 constant OBJECT_IDENTIFIER_TAG = bytes1(0x06);
    bytes1 constant EXTERNAL_TAG        = bytes1(0x08);
    bytes1 constant ENUMERATED_TAG      = bytes1(0x0a); // decimal 10
    bytes1 constant SEQUENCE_TAG        = bytes1(0x10); // decimal 16
    bytes1 constant SET_TAG             = bytes1(0x11); // decimal 17
    bytes1 constant SET_OF_TAG          = bytes1(0x11);

    bytes1 constant NUMERIC_STRING_TAG  = bytes1(0x12); // decimal 18
    bytes1 constant PRINTABLE_STRING_TAG = bytes1(0x13); // decimal 19
    bytes1 constant T61_STRING_TAG      = bytes1(0x14); // decimal 20
    bytes1 constant VIDEOTEX_STRING_TAG = bytes1(0x15); // decimal 21
    bytes1 constant IA5_STRING_TAG      = bytes1(0x16); // decimal 22
    bytes1 constant UTC_TIME_TAG        = bytes1(0x17); // decimal 23
    bytes1 constant GENERALIZED_TIME_TAG = bytes1(0x18); // decimal 24
    bytes1 constant GRAPHIC_STRING_TAG  = bytes1(0x19); // decimal 25
    bytes1 constant VISIBLE_STRING_TAG  = bytes1(0x1a); // decimal 26
    bytes1 constant GENERAL_STRING_TAG  = bytes1(0x1b); // decimal 27
    bytes1 constant UNIVERSAL_STRING_TAG = bytes1(0x1c); // decimal 28
    bytes1 constant BMP_STRING_TAG      = bytes1(0x1e); // decimal 30
    bytes1 constant UTF8_STRING_TAG     = bytes1(0x0c); // decimal 12

    bytes1 constant CONSTRUCTED_TAG     = bytes1(0x20); // decimal 28

    bytes1 constant LENGTH_TAG          = bytes1(0x30);
    bytes1 constant VERSION_TAG         = bytes1(0xA0);
    bytes1 constant COMPOUND_TAG        = bytes1(0xA3);

    uint256 constant IA5_CODE = uint256(bytes32("IA5")); //tags for disambiguating content
    uint256 constant DEROBJ_CODE = uint256(bytes32("OBJID"));
    
    event Value(uint256 indexed val);
    event RtnStr(bytes val);
    event RtnS(string val);

    uint256 constant curveOrderBitLength = 254;
    uint256 constant curveOrderBitShift = 256 - curveOrderBitLength;
    uint256 constant pointLength = 65;

    uint256 callCount;

    constructor()
    {
        owner = payable(msg.sender);
        callCount = 0;
    }

    struct Length {
        uint decodeIndex;
        uint length;
    }

    function verifyTicketAttestation(bytes memory attestation) public pure returns(address payable subject, bytes memory ticketId, address issuer, address attestor)
    {
        bytes memory attestationData;
        bytes memory preHash;

        uint256 decodeIndex = 0;
        uint256 length = 0;
        uint256 messageLength = 0;
        uint256 hashIndex = 0;

        /*
        Attestation structure:
            Length, Length
            - Version,
            - Serial,
            - Signature type,
            - Issuer Sequence,
            - Validity Time period Start, finish
        */

        (length, decodeIndex) = decodeLength(attestation, 1); //924

        (length, hashIndex) = decodeLength(attestation, decodeIndex+1); //168

        (messageLength, decodeIndex) = decodeLength(attestation, hashIndex+1); //1F

        preHash = copyDataBlock(attestation, hashIndex, (messageLength + decodeIndex) - hashIndex);
        
        (length, decodeIndex) = decodeLength(attestation, decodeIndex + messageLength + 1);

        (length, attestationData, decodeIndex) = decodeElementOffset(attestation, decodeIndex + length, 1); // Signature
        
        //pull issuer key
        issuer = recoverSigner(keccak256(preHash), attestationData);
        
        (subject, attestor) = verifyPublicAttestation(attestation, decodeIndex);
        
        (length, decodeIndex) = decodeLength(preHash, 1);
        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1);
        (length, ticketId, decodeIndex) = decodeElement(preHash, decodeIndex + length); // public key
    }
    
    function verifyPublicAttestation(bytes memory attestation, uint256 nIndex) private pure returns(address payable subject, address attestorAddress)
    {
        bytes memory attestationData;
        bytes memory preHash;

        uint256 decodeIndex = 0;
        uint256 length = 0;

        /*
        Attestation structure:
            Length, Length
            - Version,
            - Serial,
            - Signature type,
            - Issuer Sequence,
            - Validity Time period Start, finish
        */
        
        (length, nIndex) = decodeLength(attestation, nIndex+1); //nIndex is start of prehash
        
        (length, decodeIndex) = decodeLength(attestation, nIndex+1); // length of prehash is decodeIndex (result) - nIndex

        //obtain pre-hash
        preHash = copyDataBlock(attestation, nIndex, (decodeIndex + length) - nIndex);

        nIndex = (decodeIndex + length); //set pointer to read data after the pre-hash block

        (length, decodeIndex) = decodeLength(preHash, 1); //read pre-hash header

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1); // Version

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Serial

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Signature type (9) 1.2.840.10045.2.1

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Issuer Sequence (14) [[2.5.4.3, ALX]]], (Issuer: CN=ALX)
        
        //TODO: Read and check validity times
        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Timestamp  
        
        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // ID ref  
        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // User Key block
        
        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1); // read ZK block length
        
        (length, attestationData, decodeIndex) = decodeElementOffset(preHash, decodeIndex + length, 2); // public key
        
        subject = payable(publicKeyToAddress(attestationData));

        (length, decodeIndex) = decodeLength(attestation, nIndex + 1); // Signature algorithm ID (9) 1.2.840.10045.2.1
        
        (length, attestationData, nIndex) = decodeElementOffset(attestation, decodeIndex + length, 1); // Signature (72) : #0348003045022100F1862F9616B43C1F1550156341407AFB11EEC8B8BB60A513B346516DBC4F1F3202204E1B19196B97E4AECD6AE7E701BF968F72130959A01FCE83197B485A6AD2C7EA

        //return attestorPass && subjectPass && identifierPass;
        attestorAddress = recoverSigner(keccak256(preHash), attestationData);
    }
    
    function getAttestationTimestamp(bytes memory attestation) public pure returns(string memory startTime, string memory endTime)
    {
        uint256 length = 0;
        uint256 decodeIndex = 0;

        /*
        Attestation structure:
            Length, Length
            - Version,
            - Serial,
            - Signature type,
            - Issuer Sequence,
            - Validity Time period Start, finish
        */
        
        (length, decodeIndex) = decodeLength(attestation, 1); // 924

        (length, decodeIndex) = decodeLength(attestation, decodeIndex+1); // 168
        
        (length, decodeIndex) = decodeLength(attestation, decodeIndex+length+1); // 576
        
        (length, decodeIndex) = decodeLength(attestation, decodeIndex+1); // 493

        (length, decodeIndex) = decodeLength(attestation, decodeIndex + 1); // Version

        (length, decodeIndex) = decodeLength(attestation, decodeIndex + 1 + length); // Serial

        (length, decodeIndex) = decodeLength(attestation, decodeIndex + 1 + length); // Signature type (9) 1.2.840.10045.2.1

        (length, decodeIndex) = decodeLength(attestation, decodeIndex + 1 + length); // Issuer Sequence (14) [[2.5.4.3, ALX]]], (Issuer: CN=ALX)
        
        (length, decodeIndex) = decodeLength(attestation, decodeIndex + 1 + length); // Time sequence header
        
        bytes memory timeData;
        (length, timeData, decodeIndex) = decodeElement(attestation, decodeIndex);
        startTime = copyStringBlock(timeData);
        (length, timeData, decodeIndex) = decodeElement(attestation, decodeIndex);
        endTime = copyStringBlock(timeData);
    }
    
    function uint2str(uint _i) internal pure returns (string memory _uintAsString) {
        if (_i == 0) {
            return "0";
        }
        uint j = _i;
        uint len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint k = len;
        while (_i != 0) {
            k = k-1;
            uint8 temp = (48 + uint8(_i - _i / 10 * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }
    
    function publicKeyToAddress(bytes memory publicKey) pure internal returns(address keyAddr)
    {
        bytes32 keyHash = keccak256(publicKey);
        bytes memory scratch = new bytes(32);
            
        assembly { 
            mstore(add(scratch, 32), keyHash)
            mstore(add(scratch, 12), 0)
            keyAddr := mload(add(scratch, 32))
        }
    }

    function recoverSigner(bytes32 hash, bytes memory signature) internal pure returns(address signer)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        return ecrecover(hash, v, r, s);
    }

    function splitSignature(bytes memory sig)
        internal pure returns (bytes32 r, bytes32 s, uint8 v)
    {
        require(sig.length == 65, "invalid signature length");

        assembly {

        // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
        // second 32 bytes
            s := mload(add(sig, 64))
        // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }
    }
    
    function decodeDERData(bytes memory byteCode, uint dIndex) internal pure returns(bytes memory data, uint256 index, uint256 length)
    {
        return decodeDERData(byteCode, dIndex, 0);
    }

    function copyDataBlock(bytes memory byteCode, uint dIndex, uint length) internal pure returns(bytes memory data)
    {
        uint256 blank = 0;
        uint256 index = dIndex;

        uint dStart = 0x20 + index;
        uint cycles = length / 0x20;
        uint requiredAlloc = length;

        if (length % 0x20 > 0) //optimise copying the final part of the bytes - remove the looping
        {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank
        }

        data = new bytes(requiredAlloc);

        assembly {
            let mc := add(data, 0x20) //offset into bytes we're writing into
            let cycle := 0

            for
            {
                let cc := add(byteCode, dStart)
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } {
                mstore(mc, mload(cc))
            }
        }

        //finally blank final bytes and shrink size
        if (length % 0x20 > 0)
        {
            uint offsetStart = 0x20 + length;
            assembly
            {
                let mc := add(data, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
            //now shrink the memory back
                mstore(data, length)
            }
        }
    }
    
    function copyStringBlock(bytes memory byteCode) internal pure returns(string memory stringData)
    {
        uint256 blank = 0; //blank 32 byte value
        uint256 length = byteCode.length;

        uint cycles = byteCode.length / 0x20;
        uint requiredAlloc = length;

        if (length % 0x20 > 0) //optimise copying the final part of the bytes - to avoid looping with single byte writes
        {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank, so we don't smack the next stack entry
        }

        stringData = new string(requiredAlloc);

        //copy data in 32 byte blocks
        assembly {
            let cycle := 0

            for
            {
                let mc := add(stringData, 0x20) //pointer into bytes we're writing to
                let cc := add(byteCode, 0x20)   //pointer to where we're reading from
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } {
                mstore(mc, mload(cc))
            }
        }

        //finally blank final bytes and shrink size (part of the optimisation to avoid looping adding blank bytes1)
        if (length % 0x20 > 0)
        {
            uint offsetStart = 0x20 + length;
            assembly
            {
                let mc := add(stringData, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
                //now shrink the memory back so the returned object is the correct size
                mstore(stringData, length)
            }
        }
    }

    function decodeDERData(bytes memory byteCode, uint dIndex, uint offset) internal pure returns(bytes memory data, uint256 index, uint256 length)
    {
        index = dIndex + 1;

        (length, index) = decodeLength(byteCode, index);
        
        if (offset <= length)
        {
            uint requiredLength = length - offset;
            uint dStart = index + offset;

            data = copyDataBlock(byteCode, dStart, requiredLength);
        }

        index += length;
    }

    function decodeElement(bytes memory byteCode, uint decodeIndex) internal pure returns(uint256 length, bytes memory content, uint256 newIndex)
    {
        (content, newIndex, length) = decodeDERData(byteCode, decodeIndex);
    }

    function decodeElementOffset(bytes memory byteCode, uint decodeIndex, uint offset) internal pure returns(uint256 length, bytes memory content, uint256 newIndex)
    {
        (content, newIndex, length) = decodeDERData(byteCode, decodeIndex, offset);
    }

    function decodeLength(bytes memory byteCode, uint decodeIndex) internal pure returns(uint256 length, uint256 newIndex)
    {
        uint codeLength = 1;
        length = 0;
        newIndex = decodeIndex;

        if ((byteCode[newIndex] & 0x80) == 0x80)
        {
            codeLength = uint8((byteCode[newIndex++] & 0x7f));
        }

        for (uint i = 0; i < codeLength; i++)
        {
            length |= uint(uint8(byteCode[newIndex++] & 0xFF)) << ((codeLength - i - 1) * 8);
        }
    }

    function decodeIA5String(bytes memory byteCode, uint256[] memory objCodes, uint objCodeIndex, uint decodeIndex) internal pure returns(Status memory)
    {
        uint length = uint8(byteCode[decodeIndex++]);
        bytes32 store = 0;
        for (uint j = 0; j < length; j++) store |= bytes32(byteCode[decodeIndex++] & 0xFF) >> (j * 8);
        objCodes[objCodeIndex++] = uint256(store);
        Status memory retVal;
        retVal.decodeIndex = decodeIndex;
        retVal.objCodeIndex = objCodeIndex;

        return retVal;
    }
    
    function mapTo256BitInteger(bytes memory input) internal pure returns(uint256 res)
    {
        bytes32 idHash = keccak256(input);
        res = uint256(idHash);
    }
    
    struct Status {
        uint decodeIndex;
        uint objCodeIndex;
    }

    function endContract() public payable
    {
        if(msg.sender == owner)
        {
            selfdestruct(owner);
        }
        else revert();
    }
}