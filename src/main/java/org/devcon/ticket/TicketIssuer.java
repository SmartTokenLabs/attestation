package org.devcon.ticket;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.core.DERUtility;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

public class TicketIssuer {
    static SecureRandom rand = new SecureRandom();

    public static void main(String... args) throws java.io.IOException{
        int curveLength = AttestationCrypto.curveOrder.toString(2).length();
        /* secret shared between the issuer and the ticket holder */
        BigInteger sharedSecret = new BigInteger(curveLength, rand);
        if (sharedSecret.compareTo(AttestationCrypto.curveOrder) >= 0) {
            main(args);
            return;
        }

        if (args.length != 5) {
            System.err.println("Commandline Options:");
            System.err.println("{key.pem}\tPath to the PEM file that contains the issuer private key.");
            System.err.println("{mail}\tThe email address of the ticket owner.");
            System.err.println("{devconID}\tA string representing the Devcon ID.");
            System.err.println("{ticketID}\tAn integer ticket ID.");
            System.err.println("{ticketClass}\tAn integer representing the ticket class.");
        } else {
            String mail = args[1];
            String devconID = args[2];
            BigInteger ticketID = new BigInteger(args[3]);
            int ticketClass = Integer.parseInt(args[4]);
            Path keyFile = Paths.get(args[0]);
            byte[] dataCER = DERUtility.restoreBytes(Files.readAllLines(keyFile));
            ASN1InputStream asn1InputStream = new ASN1InputStream(dataCER);
            ASN1Primitive dataASN1 = asn1InputStream.readObject();
            asn1InputStream.close();
            // will throw up badly if dataASN1 is not instanceof ASN1Sequence
            AsymmetricCipherKeyPair issuerKeyPair= DERUtility.restoreRFC5915Key(dataASN1);
            Ticket ticket = new Ticket(mail, devconID, ticketID, ticketClass, issuerKeyPair, sharedSecret);
            String ticketInUrl = new String(Base64.getUrlEncoder().encode(ticket.getDerEncoding()));
            System.out.printf("?ticket=%s&secret=%s", ticketInUrl, sharedSecret.toString());
        }
    }
}
