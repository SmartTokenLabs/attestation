package org.devcon.ticket;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.tokenscript.attestation.IdentifierAttestation.AttestationType;
import org.tokenscript.attestation.core.AttestationCrypto;
import org.tokenscript.attestation.core.DERUtility;
import org.tokenscript.attestation.core.URLUtility;

public class Issuer {
    static SecureRandom rand = new SecureRandom();
    static AttestationCrypto crypto = new AttestationCrypto(rand);

    public static void main(String... args) {
        if (args.length != 5) {
            System.err.println("Commandline Options:");
            System.err.println("{key.pem}\tPath to the PEM file that contains the issuer's private elliptic curve key in RFC 5915 format.");
            System.err.println("{mail}\tThe email address of the ticket owner.");
            System.err.println("{devconID}\tA string representing the Devcon ID.");
            System.err.println("{ticketID}\tAn integer ticket ID.");
            System.err.println("{ticketClass}\tAn integer representing the ticket class.");
        } else {
            try {
                String mail = args[1];
                String devconID = args[2];
                BigInteger ticketID = new BigInteger(args[3]);
                int ticketClass = Integer.parseInt(args[4]);
                Path keyFile = Paths.get(args[0]);
                System.out.println(constructTicket(mail, devconID, ticketID, ticketClass, keyFile));
            } catch (Exception e) {
                System.err.println("Something went wrong. Please check the supplied arguments again and ensure that the private key is an elliptic curve key in RFC 5915 format.");
                throw new RuntimeException("Could not produce magic link", e);
            }
        }
    }

    static String constructTicket(String mail, String devconID, BigInteger ticketID, int ticketClass, Path keyFile) throws IOException {
        byte[] dataCER = DERUtility.restoreBytes(Files.readAllLines(keyFile));
        AsymmetricCipherKeyPair issuerKeyPair = DERUtility.restorePrivateKey(dataCER);

        BigInteger sharedSecret = crypto.makeSecret();
        Ticket ticket = new Ticket(mail, devconID, ticketID, ticketClass, issuerKeyPair,
            sharedSecret);
        if (!ticket.checkValidity()) {
            throw new RuntimeException(
                "Something went wrong and the constructed ticket could not be validated");
        }
        if (!ticket.verify()) {
            throw new RuntimeException(
                "Something went wrong and the constructed ticket could not be verified");
        }
        PublicIdentifierProof pok = new PublicIdentifierProof(crypto, ticket.getCommitment(),
            mail, AttestationType.EMAIL, sharedSecret);
        if (!pok.verify()) {
            throw new RuntimeException(
                "Something went wrong and the commitment in the ticket could not be verified according to the email.");
        }
        String ticketInUrl = ticket.getUrlEncoding();
        String pokInUrl = URLUtility.encodeData(pok.getInternalPok().getDerEncoding());
        return String.format("?ticket=%s&pok=%s&secret=%s&mail=%s", ticketInUrl, pokInUrl, sharedSecret.toString(), URLEncoder.encode(mail, StandardCharsets.UTF_8));
    }
}
