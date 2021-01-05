/* Attestation decode and validation */
/* AlphaWallet 2020 */

pragma solidity ^0.6.0;

contract DerDecode {
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

    uint256 constant IA5_CODE = uint256(bytes32("IA5")); //tags for disambiguating content
    uint256 constant DEROBJ_CODE = uint256(bytes32("OBJID"));

    uint256 constant public fieldSize = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant public curveOrder = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    event Value(uint256 indexed val);
    event RtnStr(bytes val);
    event RtnS(string val);
    
    uint256[2] private G = [ 12022136709705892117842496518378933837282529509560188557390124672992517127582,
                             6765325636686621066142015726326349598074684595222800743368698766652936798612 ];
                        
    uint256[2] private H = [ 12263903704889727924109846582336855803381529831687633314439453294155493615168,
                             1637819407897162978922461013726819811885734067940976901570219278871042378189 ];
                             
    uint256 constant curveOrderBitLength = 253;
    uint256 constant curveOrderBitShift = 255 - curveOrderBitLength;
                             
    bytes constant GPoint = abi.encodePacked(uint8(0x04), uint256(12022136709705892117842496518378933837282529509560188557390124672992517127582),
                  uint256(6765325636686621066142015726326349598074684595222800743368698766652936798612));
                                                                        
    uint256 callCount;
                             
    constructor() public
    {
        owner = msg.sender;
        callCount = 0;
    }

    struct Length {
        uint decodeIndex;
        uint length;
    }

    struct Exponent {
        bytes base;
        bytes riddle;
        bytes tPoint;
        uint256 challenge;
    }

    struct OctetString {
        uint decodeIndex;
        bytes byteCode;
    }

    //Payable variant of the attestation function for testing
    function decodeAttestationPayable(bytes memory attestation) public returns(bool)
    {
        if (decodeAttestation(attestation))
        {
            callCount++;
            return true;
        }
        else
        {
            return false;
        }
    }
    
    //Payable variant of the attestation function for testing
    function verifyEqualityProofPayable(bytes memory com1, bytes memory com2, bytes memory proof) public returns(bool)
    {
        if (verifyEqualityProof(com1, com2, proof))
        {
            callCount++;
            return true;
        }
        else
        {
            return false;
        }
    }
    
    function verifyEqualityProof(bytes memory com1, bytes memory com2, bytes memory proof) public view returns(bool)
    {
        Length memory len;
        OctetString memory octet;
        Exponent memory pok;
        
        len = decodeLength(proof, 1);
        octet.decodeIndex = len.decodeIndex;
        
        octet = decodeOctetString(proof, octet.decodeIndex);
        pok.base = octet.byteCode;
        octet = decodeOctetString(proof, octet.decodeIndex);
        pok.riddle = octet.byteCode;
        octet = decodeOctetString(proof, octet.decodeIndex);
        pok.challenge = bytesToUint(octet.byteCode);
        octet = decodeOctetString(proof, octet.decodeIndex);
        pok.tPoint = octet.byteCode;
        
        uint256[2] memory lhs;
        uint256[2] memory rhs;
        uint256[2] memory base;
        (lhs[0], lhs[1]) = extractXYFromPoint(com1);
        (rhs[0], rhs[1]) = extractXYFromPoint(com2);
        (base[0], base[1]) = extractXYFromPoint(pok.base);

        rhs = ecInv(rhs);
        
        uint256[2] memory riddle = ecAdd(lhs, rhs);
        uint256[2] memory checkPoint;
        (checkPoint[0], checkPoint[1]) = extractXYFromPoint(pok.riddle);
        
        //Verify proof matches the commitments
        if (!ecEquals(checkPoint, riddle))
        {
            revert();
        }
        
        //Ensure base is correct
        if (!ecEquals(base, H))
        {
            revert();
        }

        bytes memory cArray = concat5(GPoint, pok.base, com1, com2, pok.tPoint); 
        uint256 c = mapToCurveMultiplier(cArray);
        
        lhs = ecMul(pok.challenge, base[0], base[1]);
        if (lhs[0] == 0 && lhs[1] == 0) { revert(); } //early revert to avoid spending more gas
        
        //ECPoint riddle multiply by proof (component hash)
        rhs = ecMul(c, riddle[0], riddle[1]);
        if (rhs[0] == 0 && rhs[1] == 0) { revert(); } //early revert to avoid spending more gas
        
        //Add result of riddle.multiply(c) to point
        (checkPoint[0], checkPoint[1]) = extractXYFromPoint(pok.tPoint);
        rhs = ecAdd(rhs, checkPoint);
        
        return ecEquals(lhs, rhs);
    }
    
    function ecEquals(uint256[2] memory ecPoint1, uint256[2] memory ecPoint2) private view returns(bool)
    {
        return (ecPoint1[0] == ecPoint2[0] && ecPoint1[1] == ecPoint2[1]);
    }

    function decodeAttestation(bytes memory attestation) public view returns(bool)
    {
        Length memory len;
        Exponent memory pok;
        OctetString memory octet;

        require(attestation[0] == (CONSTRUCTED_TAG | SEQUENCE_TAG));

        len = decodeLength(attestation, 1);
        octet.decodeIndex = len.decodeIndex;

        //decode parts
        octet = decodeOctetString(attestation, octet.decodeIndex);
        pok.base = octet.byteCode;
        octet = decodeOctetString(attestation, octet.decodeIndex);
        pok.riddle = octet.byteCode;
        octet = decodeOctetString(attestation, octet.decodeIndex);
        pok.challenge = bytesToUint(octet.byteCode);
        octet = decodeOctetString(attestation, octet.decodeIndex);
        pok.tPoint = octet.byteCode;

        //Calculate LHS ECPoint
        (uint256 x, uint256 y) = extractXYFromPoint(pok.base);
        uint256[2] memory lhs = ecMul(pok.challenge, x, y);
        
        if (lhs[0] == 0 && lhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //Calculate RHS ECPoint
        (x, y) = extractXYFromPoint(pok.riddle);
        
        //The hand optimised concat4 is more optimal than using abi.encodePacked (checked the gas costs of both)
        bytes memory cArray = concat4(GPoint, pok.base, pok.riddle, pok.tPoint);
        uint256 c = mapToCurveMultiplier(cArray);
        
        //ECPoint riddle muliply by component hash
        uint256[2] memory rhs = ecMul(c, x, y);
        
        if (rhs[0] == 0 && rhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //Add result of riddle.multiply(c) to point
        (x, y) = extractXYFromPoint(pok.tPoint);
        uint256[2] memory tPointCoords = [x, y];
        rhs = ecAdd(rhs, tPointCoords);
        
        return ecEquals(lhs, rhs);
    }

    function ecMul(uint256 s, uint256 x, uint256 y) public view
        returns (uint256[2] memory retP)
    {
        bool success;
        // With a public key (x, y), this computes p = scalar * (x, y).
        uint256[3] memory i = [x, y, s];
        
        assembly 
        {
            // call ecmul precompile
            // inputs are: x, y, scalar
            success := staticcall (not(0), 0x07, i, 0x60, retP, 0x40)
        }
        
        if (!success)
        {
            retP[0] = 0;
            retP[1] = 0;
        }
    }
  
    function ecInv(uint256[2] memory point) private view 
        returns (uint256[2] memory invPoint)
    {
        invPoint[0] = point[0];
        int256 n = int256(fieldSize) - int256(point[1]);
        n = n % int256(fieldSize);
        if (n < 0) { n += int256(fieldSize); }
        invPoint[1] = uint256(n);
    }
    
    function ecAdd(uint256[2] memory p1, uint256[2] memory p2) public view
        returns (uint256[2] memory retP)
    {
        bool success;
        uint256[4] memory i = [p1[0], p1[1], p2[0], p2[1]];
        
        assembly 
        {
            // call ecadd precompile
            // inputs are: x1, y1, x2, y2
            success := staticcall (not(0), 0x06, i, 0x80, retP, 0x40)
        }
        
        if (!success)
        {
            retP[0] = 0;
            retP[1] = 0;
        }
    }
    
    function extractXYFromPoint(bytes memory data) public pure returns (uint256 x, uint256 y)
    {
        bytes32 xBytes;
        bytes32 yBytes;
        assembly 
        {
            xBytes := mload(add(data, 0x21)) //copy from 33rd byte because first 32 bytes are array length, then 1st byte of data is the 0x04; 
            yBytes := mload(add(data, 0x41)) //65th byte as x value is 32 bytes.
        }
        
        x = uint256(xBytes);
        y = uint256(yBytes);
    }
    
    function extractXYFromPoint2(bytes memory data) public pure returns (uint256 x, uint256 y)
    {
        bytes32 xBytes;
        bytes32 yBytes;
        assembly 
        {
            xBytes := mload(add(data, 0x21)) //copy from 33rd byte because first 32 bytes are array length, then 1st byte of data is the 0x04; 
            yBytes := mload(add(data, 0x41)) //65th byte as x value is 32 bytes.
        }
        
        x = uint256(xBytes);
        y = uint256(yBytes);
    }

    function mapToCurveMultiplier(bytes memory input) public pure returns(uint256 res)
    {
        bytes memory nextInput = input;
        do
        {
            bytes32 idHash = keccak256(nextInput);
            res = uint256(idHash) >> curveOrderBitShift;
            if (res < curveOrder) //avoid generating the next value unless necessary
            {
                break;
            }
            else
            {
                nextInput = abi.encodePacked(idHash);
            }
        }
        while (res >= curveOrder);
    }

    //Optimised for input bytes size to be 32; so far we don't see any other byte size
    function bytesToUint(bytes memory b) public pure returns (uint256)
    {
        if (b.length == 32) //optimised for 32 byte values
        {
            bytes32 temp;
            assembly 
            {
                temp := mload(add(b, 32))
            }
            return uint256(temp);
        }
        else
        {
            uint256 number = 0;
            for(uint i = 0; i < b.length; i++)
            {
                number = number + uint(uint8(b[i]))*(2**(8*(b.length-(i+1))));
            }
            return number;
        }
    }

    //Optimise the 32 byte copy. 
    //We could optimise slightly further by assuming the Octet string is always 65 bytes and completely unroll the assembly loop. 
    function decodeOctetString(bytes memory byteCode, uint decodeIndex) private pure returns(OctetString memory data)
    {
        data.decodeIndex = decodeIndex;
        Length memory len;

        require (byteCode[data.decodeIndex++] == OCTET_STRING_TAG);

        len = decodeLength(byteCode, data.decodeIndex);
        data.decodeIndex = len.decodeIndex;   

        uint dStart = 0x20 + data.decodeIndex;
        bytes memory tempBytes = new bytes(len.length);
        uint cycles = len.length / 0x20;

        assembly {
            let mc := add(tempBytes, 0x20) //structure offset for uint plus byte size entry
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
        
        data.decodeIndex += cycles * 0x20;
        uint remainder = len.length % 0x20;
        for (uint i = 0; i < remainder; i++)
        {
            tempBytes[i+cycles*0x20] = byteCode[data.decodeIndex++];
        }
        
        data.byteCode = tempBytes;
    }

    function decodeLength(bytes memory byteCode, uint decodeIndex) private pure returns(Length memory)
    {
        uint codeLength = 1;
        Length memory retVal;
        retVal.length = 0;
        retVal.decodeIndex = decodeIndex;

        if ((byteCode[retVal.decodeIndex] & 0x80) == 0x80)
        {
            codeLength = uint8((byteCode[retVal.decodeIndex++] & 0x7f));
        }

        for (uint i = 0; i < codeLength; i++)
        {
            retVal.length |= uint(uint8(byteCode[retVal.decodeIndex++] & 0xFF)) << ((codeLength - i - 1) * 8);
        }

        return retVal;
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

    function decodeObjectIdentifier(bytes memory byteCode, uint256[] memory objCodes, uint objCodeIndex, uint decodeIndex) private pure returns(Status memory)
    {
        uint length = uint8(byteCode[decodeIndex++]);

        Status memory retVal;

        //1. decode leading pair
        uint subIDEndIndex = decodeIndex;
        uint256 subId;

        while ((byteCode[subIDEndIndex] & 0x80) == 0x80)
        {
            require(subIDEndIndex < byteCode.length);
            subIDEndIndex++;
        }

        uint subidentifier = 0;
        for (uint i = decodeIndex; i <= subIDEndIndex; i++)
        {
            subId = uint256(uint8(byteCode[i] & 0x7f)) << ((subIDEndIndex - i) * 7);
            subidentifier |= subId;
        }

        if (subidentifier < 40)
        {
            objCodes[objCodeIndex++] = 0;
            objCodes[objCodeIndex++] = subidentifier;
        }
        else if (subidentifier < 80)
        {
            objCodes[objCodeIndex++] = 1;
            objCodes[objCodeIndex++] = subidentifier - 40;
        }
        else
        {
            objCodes[objCodeIndex++] = 2;
            objCodes[objCodeIndex++] = subidentifier - 80;
        }

        subIDEndIndex++;

        while (subIDEndIndex < (decodeIndex + length) && byteCode[subIDEndIndex] != 0)
        {
            subidentifier = 0;
            uint256 subIDStartIndex = subIDEndIndex;

            while ((byteCode[subIDEndIndex] & 0x80) == 0x80)
            {
                require(subIDEndIndex < byteCode.length);
                subIDEndIndex++;
            }
            subidentifier = 0;
            for (uint256 j = subIDStartIndex; j <= subIDEndIndex; j++)
            {
                subId = uint256(uint8(byteCode[j] & 0x7f)) << ((subIDEndIndex - j) * 7);
                subidentifier |= subId;
            }
            objCodes[objCodeIndex++] = subidentifier;
            subIDEndIndex++;
        }

        decodeIndex += length;

        retVal.decodeIndex = decodeIndex;
        retVal.objCodeIndex = objCodeIndex;

        return retVal;
    }

    function endContract() public payable
    {
        if(msg.sender == owner)
        {
            selfdestruct(owner);
        }
        else revert();
    }
    
    //Most optimal 4 byte array variable length concatenate. If sizes of the inputs are static we can optimise this even further
    function concat4(
        bytes memory _bytes1,
        bytes memory _bytes2,
        bytes memory _bytes3,
        bytes memory _bytes4
    )
    internal
    pure
    returns (bytes memory)
    {
        bytes memory tempBytes;

        assembly {
        // Get a location of some free memory and store it in tempBytes as
        // Solidity does for memory variables.
            tempBytes := mload(0x40)

        // Store the length of the first bytes array at the beginning of
        // the memory for tempBytes.
            let length := mload(_bytes1)
            let totalLength := length
            mstore(tempBytes, length)

        // Maintain a memory counter for the current write location in the
        // temp bytes array by adding the 32 bytes for the array length to
        // the starting location.
            let mc := add(tempBytes, 0x20)
        // Stop copying when the memory counter reaches the length of the
        // first bytes array.
            let end := add(mc, length)

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

        // Add the length of _bytes2 to the current length of tempBytes
        // and store it as the new length in the first 32 bytes of the
        // tempBytes memory.
            length := mload(_bytes2)
            mstore(tempBytes, add(length, mload(tempBytes)))

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_bytes2, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }


        // Add the length of _bytes3 to the current length of tempBytes
        // and store it as the new length in the first 32 bytes of the
        // tempBytes memory.
            length := mload(_bytes3)
            mstore(tempBytes, add(length, mload(tempBytes)))    

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_bytes3, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }
            
        // Add the length of _bytes4 to the current length of tempBytes
        // and store it as the new length in the first 32 bytes of the
        // tempBytes memory.
            length := mload(_bytes4)
            mstore(tempBytes, add(length, mload(tempBytes)))    

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_bytes4, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

        // Update the free-memory pointer by padding our last write location
        // to 32 bytes: add 31 bytes to the end of tempBytes to move to the
        // next 32 byte block, then round down to the nearest multiple of
        // 32. If the sum of the length of the two arrays is zero then add
        // one before rounding down to leave a blank 32 bytes (the length block with 0).
            mstore(0x40, and(
            add(add(end, iszero(end)), 31),
            not(31) // Round down to the nearest 32 bytes.
            ))
        }

        return tempBytes;
    }
    
    function concat5(
        bytes memory _bytes1,
        bytes memory _bytes2,
        bytes memory _bytes3,
        bytes memory _bytes4,
        bytes memory _bytes5
    )
    internal
    pure
    returns (bytes memory)
    {
        bytes memory tempBytes;

        assembly {
        // Get a location of some free memory and store it in tempBytes as
        // Solidity does for memory variables.
            tempBytes := mload(0x40)

        // Store the length of the first bytes array at the beginning of
        // the memory for tempBytes.
            let length := mload(_bytes1)
            let totalLength := length
            mstore(tempBytes, length)

        // Maintain a memory counter for the current write location in the
        // temp bytes array by adding the 32 bytes for the array length to
        // the starting location.
            let mc := add(tempBytes, 0x20)
        // Stop copying when the memory counter reaches the length of the
        // first bytes array.
            let end := add(mc, length)

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

        // Add the length of _bytes2 to the current length of tempBytes
        // and store it as the new length in the first 32 bytes of the
        // tempBytes memory.
            length := mload(_bytes2)
            mstore(tempBytes, add(length, mload(tempBytes)))

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_bytes2, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }


        // Add the length of _bytes3 to the current length of tempBytes
        // and store it as the new length in the first 32 bytes of the
        // tempBytes memory.
            length := mload(_bytes3)
            mstore(tempBytes, add(length, mload(tempBytes)))    

        // Move the memory counter back from a multiple of 0x20 to the
        // actual end of the _bytes1 data.
            mc := end
        // Stop copying when the memory counter reaches the new combined
        // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_bytes3, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }
            
        // bytes4
            length := mload(_bytes4)
            mstore(tempBytes, add(length, mload(tempBytes)))    

            mc := end
            end := add(mc, length)

            for {
                let cc := add(_bytes4, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }
            
            
        // bytes5 
            length := mload(_bytes5)
            mstore(tempBytes, add(length, mload(tempBytes)))    

            mc := end
            end := add(mc, length)

            for {
                let cc := add(_bytes5, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

        // Update the free-memory pointer by padding our last write location
        // to 32 bytes: add 31 bytes to the end of tempBytes to move to the
        // next 32 byte block, then round down to the nearest multiple of
        // 32. If the sum of the length of the two arrays is zero then add
        // one before rounding down to leave a blank 32 bytes (the length block with 0).
            mstore(0x40, and(
            add(add(end, iszero(end)), 31),
            not(31) // Round down to the nearest 32 bytes.
            ))
        }

        return tempBytes;
    }
}