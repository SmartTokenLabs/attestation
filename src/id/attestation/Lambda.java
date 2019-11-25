package id.attestation;

/**
 * The interface for using AWS Lambda to parse an ASN.1
 * message. Intended to be used as a bridge product until we have a
 * method to parse ASN.1 natively in iOS, which currently uses SWIFT
 * and therefore lack an ASN.1 parser.
 *
 * LOCAL TESTING
 *
 * Run the main method in the project's top level directory where test file 'message.dat' is.
 *
 * DEPLOYMENT
 *
 * To create a zip file for uploading lambda to AWS, do the following
 * while in the project's top level directory:
 *
 * $ rm     out/production/id-attestation/lambda.zip
 * $ zip -r out/production/id-attestation/lambda.zip lib
 * $ cd     out/production/id-attestation
 * $ zip -r lambda.zip     id/attestation
 *
 * The directory hierarchy expected for the zip file can be found here:
 * https://docs.aws.amazon.com/lambda/latest/dg/create-deployment-pkg-zip-java.html
 *
 * Read AWS documents on how to upload the zip file and create a function-name for invocation.
 *
 * TESTING DEPLOYMENT
 *
 *
 */

import com.amazonaws.services.lambda.runtime.Context;
import com.objsys.asn1j.runtime.*;
import id.attestation.shankai.Attestation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import static java.util.Base64.*;

public class Lambda {

    public static String parseShangkai(byte[] rawDER) {
        String filename = new String("message.dat");

        Exception exception = null;
        Attestation value = null;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        try {
            // Create an input file stream object
            java.io.FileInputStream ins = new java.io.FileInputStream(filename);

            // Create a decode buffer object
            Asn1BerDecodeBuffer decodeBuffer =
                    new Asn1BerDecodeBuffer(ins);
            // Read and decode the message
            value = new Attestation();
            value.decode(decodeBuffer);
            System.out.println(value.signatureValue);
            Asn1JsonOutputStream encodeStream;
            encodeStream = new Asn1JsonOutputStream(new java.io.OutputStreamWriter(stream));
            value.encode(encodeStream);
            encodeStream.close();
        } catch (Exception e) {
            exception = e;
        }
        if (exception == null) System.out.println("Decode was successful");
        else System.out.println("Decode failed");
        if (value != null) {
            value.print(System.out, exception == null ? "value" : "partial value", 0);
        }

        Asn1Util.closeRuntime();

        if (exception != null) {
            System.out.println(exception.getMessage());
            exception.printStackTrace();
            System.exit(1);
        }
        return stream.toString();

    }

    public String handleRequest(String CER, Context context) throws IOException {
        byte[] DER = getDecoder().decode(CER);
        return parseShangkai(DER);
    }

    public static void main(String args[]) throws IOException {
        // serve as a test-case

        String filename = new String("message.dat");

        boolean trace = true;

        // Process command line arguments
        if (args.length > 0) {
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("-v"))
                    Diag.instance().setEnabled(true);
                else if (args[i].equals("-i"))
                    filename = new String(args[++i]);
                else if (args[i].equals("-notrace")) trace = false;
                else {
                    System.out.println("usage: Reader [ -v ] [ -i <filename>");
                    System.out.println("   -v  verbose mode: print trace info");
                    System.out.println("   -i <filename>  " +
                            "read encoded msg from <filename>");
                    System.out.println("   -notrace  do not display trace info");
                    System.exit(1);
                }
            }
        }
        byte[] rawDER = Files.readAllBytes(Paths.get("message.dat"));
        System.out.println(parseShangkai(rawDER));
    }
}
