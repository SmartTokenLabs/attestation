/* DER Decoding */
/* Stormbird 2018 */

pragma solidity ^0.4.20;
contract DerDecode
{
    address owner;

    bytes1 constant IA5_STRING_TAG = bytes1(22);
    bytes1 constant OBJECT_IDENTIFIER_TAG = bytes1(6);

    uint256 constant IA5_CODE = uint256(bytes32("IA5")); //tags for disambiguating content
    uint256 constant DEROBJ_CODE = uint256(bytes32("OBJID"));
    
    event Value(uint256 indexed val);
    event RtnStr(bytes val);
    event RtnS(string val);

    function DerDecode (

    ) public
    {
        owner = msg.sender;
    }

    function decodeDER(bytes byteCode) public view returns(uint256[])
    {
        uint256[] memory objCodes = new uint256[](40);
        Status memory data;
        uint objCodeIndex = 0;
        uint decodeIndex = 0;
        uint length = byteCode.length;
        
        //need decodeDERLength
        //first get tag of next object
        while (decodeIndex < (length - 2) && byteCode[decodeIndex] != 0)
        {
            //get tag
            bytes1 tag = byteCode[decodeIndex++];
            require((tag & 0x20) == 0); //assert primitive
            require((tag & 0xC0) == 0); //assert universal type

            if ((tag & 0x1f) == IA5_STRING_TAG)
            {
                objCodes[objCodeIndex++] = IA5_CODE;
                data = decodeIA5String(byteCode, objCodes, objCodeIndex, decodeIndex);
                objCodeIndex = data.objCodeIndex;
                decodeIndex = data.decodeIndex;
            }
            else if ((tag & 0x1f) == OBJECT_IDENTIFIER_TAG)
            {
                objCodes[objCodeIndex++] = DEROBJ_CODE;
                data = decodeObjectIdentifier(byteCode, objCodes, objCodeIndex, decodeIndex);
                objCodeIndex = data.objCodeIndex;
                decodeIndex = data.decodeIndex;
            }
        }
        
        uint256[] memory objCodesComplete = new uint256[](objCodeIndex);
        for (uint i = 0; i < objCodeIndex; i++) objCodesComplete[i] = objCodes[i];

        return objCodesComplete;
    }

    function decodeIA5String(bytes byteCode, uint256[] objCodes, uint objCodeIndex, uint decodeIndex) private view returns(Status)
    {
        uint length = uint(byteCode[decodeIndex++]);
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

    function decodeObjectIdentifier(bytes byteCode, uint256[] objCodes, uint objCodeIndex, uint decodeIndex) private view returns(Status)
    {
        uint length = uint(byteCode[decodeIndex++]);

        Status memory retVal;

        //1. decode leading pair
        uint subIDEndIndex = decodeIndex;
        
        while ((byteCode[subIDEndIndex] & 0x80) == 0x80)
        {
            require(subIDEndIndex < byteCode.length);
            subIDEndIndex++;
        }

        uint subidentifier = 0;
        for (uint i = decodeIndex; i <= subIDEndIndex; i++) 
        {
            uint256 subId = uint256(byteCode[i] & 0x7f) << ((subIDEndIndex - i) * 7);
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
                subId = uint256(byteCode[j] & 0x7f) << ((subIDEndIndex - j) * 7);
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

    function endContract() public
    {
        if(msg.sender == owner)
        {
            selfdestruct(owner);
        }
        else revert();
    }
}