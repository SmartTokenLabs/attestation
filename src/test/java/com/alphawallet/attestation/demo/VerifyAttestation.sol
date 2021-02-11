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

    uint256[2] private G = [ 21282764439311451829394129092047993080259557426320933158672611067687630484067,
    3813889942691430704369624600187664845713336792511424430006907067499686345744 ];

    uint256[2] private H = [ 10844896013696871595893151490650636250667003995871483372134187278207473369077,
    9393217696329481319187854592386054938412168121447413803797200472841959383227 ];

    uint256 constant curveOrderBitLength = 254;
    uint256 constant curveOrderBitShift = 256 - curveOrderBitLength;
    uint256 constant pointLength = 65;

    // We create byte arrays for these at construction time to save gas when we need to use them
    bytes constant GPoint = abi.encodePacked(uint8(0x04), uint256(21282764439311451829394129092047993080259557426320933158672611067687630484067),
        uint256(3813889942691430704369624600187664845713336792511424430006907067499686345744));

    bytes constant HPoint = abi.encodePacked(uint8(0x04), uint256(10844896013696871595893151490650636250667003995871483372134187278207473369077),
        uint256(9393217696329481319187854592386054938412168121447413803797200472841959383227));

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

    struct FullProofOfExponent {
        bytes riddle;
        bytes tPoint;
        uint256 challenge;
    }

    //Payable variant of the attestation function for testing
    function verifyAttestationRequestProofPayable(bytes memory attestation) public returns(bool)
    {
        if (verifyAttestationRequestProof(attestation))
        {
            callCount++;
            return true;
        }
        else
        {
            revert();
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
            revert();
        }
    }

    function verifyEqualityProof(bytes memory com1, bytes memory com2, bytes memory proof) public view returns(bool)
    {
        Length memory len;
        FullProofOfExponent memory pok;
        bytes memory attestationData;
        uint256 decodeIndex = 0;

        len = decodeLength(proof, 1);
        decodeIndex = len.decodeIndex;

        (attestationData, decodeIndex) = decodeOctetString(proof, decodeIndex);
        pok.challenge = bytesToUint(attestationData);
        (pok.tPoint, decodeIndex) = decodeOctetString(proof, decodeIndex);

        uint256[2] memory lhs;
        uint256[2] memory rhs;
        (lhs[0], lhs[1]) = extractXYFromPoint(com1);
        (rhs[0], rhs[1]) = extractXYFromPoint(com2);

        rhs = ecInv(rhs);

        uint256[2] memory riddle = ecAdd(lhs, rhs);

        bytes memory cArray = concat4Fixed(HPoint, com1, com2, pok.tPoint);
        uint256 c = mapToCurveMultiplier(cArray);

        lhs = ecMul(pok.challenge, H[0], H[1]);
        if (lhs[0] == 0 && lhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //ECPoint riddle multiply by proof (component hash)
        rhs = ecMul(c, riddle[0], riddle[1]);
        if (rhs[0] == 0 && rhs[1] == 0) { return false; } //early revert to avoid spending more gas

        uint256[2] memory point;
        (point[0], point[1]) = extractXYFromPoint(pok.tPoint);
        rhs = ecAdd(rhs, point);

        return ecEquals(lhs, rhs);
    }

    function ecEquals(uint256[2] memory ecPoint1, uint256[2] memory ecPoint2) private pure returns(bool)
    {
        return (ecPoint1[0] == ecPoint2[0] && ecPoint1[1] == ecPoint2[1]);
    }

    function verifyAttestationRequestProof(bytes memory attestation) public view returns(bool)
    {
        Length memory len;
        FullProofOfExponent memory pok;
        bytes memory attestationData;
        uint256 decodeIndex = 0;

        require(attestation[0] == (CONSTRUCTED_TAG | SEQUENCE_TAG));

        len = decodeLength(attestation, 1);
        decodeIndex = len.decodeIndex;

        //decode parts
        (pok.riddle, decodeIndex) = decodeOctetString(attestation, decodeIndex);
        (attestationData, decodeIndex) = decodeOctetString(attestation, decodeIndex);
        pok.challenge = bytesToUint(attestationData);
        (pok.tPoint, decodeIndex) = decodeOctetString(attestation, decodeIndex);

        //Calculate LHS ECPoint
        uint256[2] memory lhs = ecMul(pok.challenge, H[0], H[1]);
        uint256[2] memory check;

        if (lhs[0] == 0 && lhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //Calculate RHS ECPoint
        (check[0], check[1]) = extractXYFromPoint(pok.riddle);

        //The hand optimised concat4 is more optimal than using abi.encodePacked (checked the gas costs of both)
        bytes memory cArray = concat3Fixed(HPoint, pok.riddle, pok.tPoint);
        uint256 c = mapToCurveMultiplier(cArray);

        //ECPoint riddle muliply by component hash
        uint256[2] memory rhs = ecMul(c, check[0], check[1]);

        if (rhs[0] == 0 && rhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //Add result of riddle.multiply(c) to point
        (check[0], check[1]) = extractXYFromPoint(pok.tPoint);
        rhs = ecAdd(rhs, check);

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

    function ecInv(uint256[2] memory point) private pure
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
        assembly
        {
            x := mload(add(data, 0x21)) //copy from 33rd byte because first 32 bytes are array length, then 1st byte of data is the 0x04;
            y := mload(add(data, 0x41)) //65th byte as x value is 32 bytes.
        }
    }

    function mapTo256BitInteger(bytes memory input) public pure returns(uint256 res)
    {
        bytes32 idHash = keccak256(input);
        res = uint256(idHash);
    }

    // Note, this will return 0 if the shifted hash > curveOrder, which will cause the equate to fail
    function mapToCurveMultiplier(bytes memory input) public pure returns(uint256 res)
    {
        bytes memory nextInput = input;
        bytes32 idHash = keccak256(nextInput);
        res = uint256(idHash) >> curveOrderBitShift;
        if (res >= curveOrder)
        {
            res = 0;
        }
    }

    //Truncates if input is greater than 32 bytes; we only handle 32 byte values.
    function bytesToUint(bytes memory b) public pure returns (uint256 conv)
    {
        if (b.length < 0x20) //if b is less than 32 bytes we need to pad to get correct value
        {
            bytes memory b2 = new bytes(32);
            uint startCopy = 0x20 + 0x20 - b.length;
            assembly
            {
                let bcc := add(b, 0x20)
                let bbc := add(b2, startCopy)
                mstore(bbc, mload(bcc))
                conv := mload(add(b2, 32))
            }
        }
        else
        {
            assembly
            {
                conv := mload(add(b, 32))
            }
        }
    }

    function decodeOctetString(bytes memory byteCode, uint dIndex) public pure returns(bytes memory data, uint index)
    {
        Length memory len;
        uint256 blank = 0;
        index = dIndex;

        require (byteCode[index++] == OCTET_STRING_TAG);

        len = decodeLength(byteCode, index);
        index = len.decodeIndex;

        uint dStart = 0x20 + index;
        uint cycles = len.length / 0x20;
        uint requiredAlloc = len.length;

        if (len.length % 0x20 > 0) //optimise copying the final part of the bytes - remove the looping
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
        if (len.length % 0x20 > 0)
        {
            uint offsetStart = 0x20 + len.length;
            uint length = len.length;
            assembly
            {
                let mc := add(data, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
            //now shrink the memory back
                mstore(data, length)
            }
        }

        index += len.length;
    }

    function decodeLength(bytes memory byteCode, uint decodeIndex) private pure returns(Length memory retVal)
    {
        uint codeLength = 1;
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