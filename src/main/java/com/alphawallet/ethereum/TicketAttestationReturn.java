package com.alphawallet.ethereum;

import com.alphawallet.token.tools.Numeric;

public class TicketAttestationReturn
{
    private static final String ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
    private static final byte[] ZERO = Numeric.hexStringToByteArray("0x00");

    public String subjectAddress;
    public String issuerAddress;
    public String attestorAddress;
    public byte[] ticketId;
    public byte[] conferenceId;
    public boolean attestationValid;

    public TicketAttestationReturn()
    {
        subjectAddress = ZERO_ADDRESS;
        issuerAddress = ZERO_ADDRESS;
        attestorAddress = ZERO_ADDRESS;
        ticketId = ZERO;
        conferenceId = ZERO;
        attestationValid = false;
    }
}
