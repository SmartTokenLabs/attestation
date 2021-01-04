package org.devcon.ticket;

import com.alphawallet.attestation.core.AttestationCrypto;
import com.alphawallet.attestation.ticket.Ticket;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class Issuer {
    static SecureRandom rand = new SecureRandom();

    public static void main (String... args) throws java.lang.Exception{
        int curveLength = AttestationCrypto.curveOrder.toString(2).length();
        /* secret shared between the issuer and the ticket holder */
        BigInteger sharedSecret = new BigInteger(curveLength, rand);
        if (sharedSecret.compareTo(AttestationCrypto.curveOrder) >= 0)  {
            main(args);
            return;
        }

        if (args.length != 5) {
            System.err.println("Commandline Options:");
            System.err.println("{key.pem}\tPath to the PEM file that contains the issuer private key.");
            System.err.println("{mail}\tThe email address of the ticket owner.");
            System.err.println("{devconID}\tAn integer which is 6 for Devcon 6.");
            System.err.println("{ticketID}\tAn integer ticket ID.");
            System.err.println("{ticketClass}\tAn integer representing the ticket class.");
        } else {
            File keyFile = new File(args[0]);
            String mail = args[1];
            int devconID = Integer.parseInt(args[2]);
            BigInteger ticketID = new BigInteger(args[3]);
            int ticketClass = Integer.parseInt(args[4]);
            ECPrivateKey issuerKey = readPrivateKey(keyFile);
            //Ticket ticket = new Ticket(mail, devconID, ticketID, ticketClass, issuerKey, sharedSecret);
        }
    }
    static ECPrivateKey readPrivateKey(File file) throws Exception {
        KeyFactory factory = KeyFactory.getInstance("EC");

        try (FileReader keyReader = new FileReader(file);
             PemReader pemReader = new PemReader(keyReader)) {

            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
            return (ECPrivateKey) factory.generatePrivate(privKeySpec);
        }
    }
}
