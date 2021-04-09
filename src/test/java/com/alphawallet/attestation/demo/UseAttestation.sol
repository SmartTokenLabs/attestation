/* Attestation decode and validation */
/* AlphaWallet 2021 */

pragma solidity ^0.6.0;

contract UseAttestation {
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

    address constant validAttestorAddress = 0x5f7bFe752Ac1a45F67497d9dCDD9BbDA50A83955; //fixed issuer address

    event Value(uint256 indexed val);
    event RtnStr(bytes val);
    event RtnS(string val);

    uint256 callCount;
    uint256 constant pointLength = 65;

    constructor() public
    {
        owner = msg.sender;
        callCount = 0;
    }

    struct Length {
        uint decodeIndex;
        uint length;
    }

    //Payable variant of the attestation function for testing
    function testAttestationCall(bytes memory attestation) public returns(bool)
    {
        (address subjectAddress, address attestorAddress) = decodeAttestation(attestation);

        if (attestorAddress == validAttestorAddress && msg.sender == subjectAddress)
        {
            callCount++;
            return true;
        }
        else
        {
            return false;
        }
    }

    function decodeAttestation(bytes memory proof) public pure returns(address subjectAddress, address attestorAddress)
    {
        bytes memory attestationData;
        bytes memory preHash;

        uint256 nIndex = 1;
        uint256 decodeIndex = 0;
        uint256 length = 0;

        //decodeElement(bytes memory byteCode, uint decodeIndex) private pure returns(uint newIndex, bytes memory content, uint256 length)

        /*
        Attestation structure:
            Length, Length
            - Version,
            - Serial,
            - Signature type,
            - Issuer Sequence,
            - Validity Time period Start, finish
            - 
            
        */

        (length, nIndex) = decodeLength(proof, nIndex); //nIndex is start of prehash

        (length, decodeIndex) = decodeLength(proof, nIndex+1); // length of prehash is decodeIndex (result) - nIndex

        //obtain pre-hash
        preHash = copyDataBlock(proof, nIndex, (decodeIndex + length) - nIndex);

        nIndex = (decodeIndex + length); //set pointer to read data after the pre-hash block

        (length, decodeIndex) = decodeLength(preHash, 1); //read pre-hash header

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1); // Version 

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Serial

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Signature type (9) 1.2.840.10045.2.1

        (length, decodeIndex) = decodeLength(preHash, decodeIndex + 1 + length); // Issuer Sequence (14) [[2.5.4.3, ALX]]], (Issuer: CN=ALX)

        (length, attestationData, decodeIndex) = decodeElement(preHash, decodeIndex + length); // Validity Time (34) (Start, End) 32303231303331343030303835315A, 32303231303331343031303835315A
        //TODO: Read and check validity times

        (length, attestationData, decodeIndex) = decodeElementOffset(preHash, decodeIndex, 13); // Subject Address (53) (Type: 2.5.4.3, Addr: 30 78 30 37 31 0x071 ...) 11

        subjectAddress = address(asciiToUintAsm(attestationData));

        //(length, attestationData, decodeIndex) = decodeElement(preHash, decodeIndex); // Subject public key info (307) (not of any use to contract)

        //(length, attestationData, decodeIndex) = decodeElement(preHash, decodeIndex); // Contract info (7) [42, 1337]

        //(length, attestationData, decodeIndex) = decodeElement(preHash, decodeIndex); // Exention data (87) [1.3.6.1.4.1.1466.115.121.1.40, TRUE, #0415fd25179e47ea9fe36d52332ddcf03f3b5a578d662458d633e90549219c0d4d196698e2e33afe85a8a707cb08fab2ded1514a8639ab87ef6c1c0efc6ebd62b4]

        (length, attestationData, nIndex) = decodeElement(proof, nIndex); // Signature algorithm ID (9) 1.2.840.10045.2.1

        (length, attestationData, nIndex) = decodeElementOffset(proof, nIndex, 1); // Signature (72) : #0348003045022100F1862F9616B43C1F1550156341407AFB11EEC8B8BB60A513B346516DBC4F1F3202204E1B19196B97E4AECD6AE7E701BF968F72130959A01FCE83197B485A6AD2C7EA

        bytes32 hash = keccak256(preHash);

        //recover Signature
        attestorAddress = recoverSigner(hash, attestationData);
    }

    function recoverSigner(bytes32 hash, bytes memory signature) private pure returns(address signer)
    {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);

        return ecrecover(hash, v, r, s);
    }

    function splitSignature(bytes memory sig)
    public pure returns (bytes32 r, bytes32 s, uint8 v)
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

    // Solidity hex ascii to uint conversion (eg 0x30373038 is 0x0708)
    function asciiToUint(bytes memory asciiData) public pure returns(uint256 val)
    {
        //first convert to bytes
        bytes memory hexData = new bytes(32);
        uint256 offset = 32 - (asciiData.length/2);

        for (uint256 i = 0; i < 20; i++)
        {
            uint8 element1 = uint8(asciiData[i*2]) - 0x30;
            uint8 element2 = uint8(asciiData[i*2 + 1]) - 0x30;
            if (element1 > 0x9) element1 -= 7;
            if (element2 > 0x9) element2 -= 7;
            hexData[i+offset] = bytes1((element1 << 4) | (element2));
        }

        assembly
        {
            val := mload(add(hexData, 32))
        }
    }

    // Optimised hex ascii to uint conversion (eg 0x30373038 is 0x0708)
    function asciiToUintAsm(bytes memory asciiData) public pure returns(uint256 asciiValue)
    {
        bytes memory hexData = new bytes(32);
        bytes1 b1;
        bytes1 b2;
        bytes1 sum;

        assembly {
            let index := 0        // current write index, we have to count upwards to avoid an unsigned 0xFFFFFF infinite loop ..
            let topIndex := 0x27  // final ascii to read
            let bIndex := 0x20    // write index into bytes array we're using to build the converted number

            for
            {
                let cc := add(asciiData, topIndex) // start reading position in the ascii data
            } lt(index, topIndex) {
                index := add(index, 0x02) // each value to write is two bytes
                cc := sub(cc, 0x02)
                bIndex := sub(bIndex, 0x01) // index into scratch buffer
            } {
                //build top nibble of value
                b1 := and(mload(cc), 0xFF)
                if gt(b1, 0x39) { b1 := sub(b1, 0x07) } //correct for ascii numeric value
                b1 := sub(b1, 0x30)
                b1 := mul(b1, 0x10) //move to top nibble

                //build bottom nibble
                b2 := and(mload(add(cc, 0x01)), 0xFF)
                if gt(b2, 0x39) { b2 := sub(b2, 0x07) } //correct for ascii numeric value
                b2 := sub(b2, 0x30)

                //combine both nibbles
                sum := add(b1, b2)

                //write the combined byte into the scratch buffer
                // - note we have to point 32 bytes ahead as 'sum' uint8 value is at the end of a 32 byte register
                let hexPtr := add(hexData, bIndex)
                mstore(hexPtr, sum)
            }

            mstore(hexData, 0x20)   // patch the variable size info we corrupted in the mstore
                                    // NB: we may not need to do this, we're only using this buffer as a memory scratch
                                    // However EVM stack cleanup unwind may break, TODO: determine if it's safe to remove
            asciiValue := mload(add(hexData, 32)) // convert to uint
        }
    }

    function decodeDERData(bytes memory byteCode, uint dIndex) public pure returns(bytes memory data, uint256 index, uint256 length)
    {
        return decodeDERData(byteCode, dIndex, 0);
    }

    function copyDataBlock(bytes memory byteCode, uint dIndex, uint length) public pure returns(bytes memory data)
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

    function decodeDERData(bytes memory byteCode, uint dIndex, uint offset) public pure returns(bytes memory data, uint256 index, uint256 length)
    {
        index = dIndex + 1;

        (length, index) = decodeLength(byteCode, index);

        uint requiredLength = length - offset;
        uint dStart = index + offset;

        data = copyDataBlock(byteCode, dStart, requiredLength);

        index += length;
    }

    function decodeElement(bytes memory byteCode, uint decodeIndex) private pure returns(uint256 length, bytes memory content, uint256 newIndex)
    {
        if (byteCode[decodeIndex] == LENGTH_TAG || byteCode[decodeIndex] == VERSION_TAG || byteCode[decodeIndex] == INTEGER_TAG ||
        byteCode[decodeIndex] == COMPOUND_TAG || byteCode[decodeIndex] == BIT_STRING_TAG)
        {
            (content, newIndex, length) = decodeDERData(byteCode, decodeIndex);
        }
        else
        {
            (length, newIndex) = decodeLength(byteCode, decodeIndex + 1); //don't attempt to read content
            newIndex += length;
        }
    }

    function decodeElementOffset(bytes memory byteCode, uint decodeIndex, uint offset) private pure returns(uint256 length, bytes memory content, uint256 newIndex)
    {
        (content, newIndex, length) = decodeDERData(byteCode, decodeIndex, offset);
    }

    function decodeLength(bytes memory byteCode, uint decodeIndex) private pure returns(uint256 length, uint256 newIndex)
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

    function decodeIA5String(bytes memory byteCode, uint256[] memory objCodes, uint objCodeIndex, uint decodeIndex) private pure returns(Status memory)
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

    function concat4Fixed(
        bytes memory _bytes1,
        bytes memory _bytes2,
        bytes memory _bytes3,
        bytes memory _bytes4
    )
    internal
    pure
    returns (bytes memory join)
    {
        join = new bytes(pointLength*4); //in this case, we know how large the end result will be

        assembly {

        // Maintain a memory counter for the current write location in the
        // temp bytes array by adding the 32 bytes for the array length to
        // the starting location.
            let mc := add(join, 0x20)
        // Stop copying when the memory counter reaches the length of the
        // first bytes array.
            let end := add(mc, pointLength)

            for {
            // Initialize a copy counter to the start of the _bytes1 data,
            // 32 bytes into its memory.
                let cc := add(_bytes1, 0x20)
            } lt(mc, end) {
            // Increase both counters by 32 bytes each iteration.
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
            // Write the _bytes1 data into the tempBytes memory 32 bytes
            // at a time.
                mstore(mc, mload(cc))
            }

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, pointLength)

            for {
                let cc := add(_bytes2, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, pointLength)

            for {
                let cc := add(_bytes3, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, pointLength)

            for {
                let cc := add(_bytes4, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }
        }
    }

    // Concat3 which requires the three inputs to be 65 bytes length each
    // Doesn't perform any padding - could an EC coordinate be less than 32 bytes? If so, the mapTo256BigInteger result will be incorrect
    function concat3Fixed(
        bytes memory _bytes1,
        bytes memory _bytes2,
        bytes memory _bytes3
    )
    internal
    pure
    returns (bytes memory join)
    {
        join = new bytes(pointLength*3); //in this case, we know how large the end result will be

        assembly {

        // Maintain a memory counter for the current write location in the
        // temp bytes array by adding the 32 bytes for the array length to
        // the starting location.
            let mc := add(join, 0x20)
        // Stop copying when the memory counter reaches the length of the
        // first bytes array.
            let end := add(mc, pointLength)

            for {
            // Initialize a copy counter to the start of the _bytes1 data,
            // 32 bytes into its memory.
                let cc := add(_bytes1, 0x20)
            } lt(mc, end) {
            // Increase both counters by 32 bytes each iteration.
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
            // Write the _bytes1 data into the tempBytes memory 32 bytes
            // at a time.
                mstore(mc, mload(cc))
            }

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, pointLength)

            for {
                let cc := add(_bytes2, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, pointLength)

            for {
                let cc := add(_bytes3, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }
        }
    }
}