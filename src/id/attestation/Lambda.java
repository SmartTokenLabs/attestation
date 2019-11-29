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
 * $ pushd  out/production/id-attestation
 * $ zip -r lambda.zip     id/attestation
 *
 * The directory hierarchy expected for the zip file can be found here:
 * https://docs.aws.amazon.com/lambda/latest/dg/create-deployment-pkg-zip-java.html
 *
 * Read AWS documents on how to upload the zip file and create a function-name for invocation.
 *
 * TESTING DEPLOYMENT
 *
$ aws --profile china lambda invoke --function-name parseDER --payload "\"`base64 -w0 message.dat`\"" outfile
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
 * the resulting outfile should have the attestation in JSON.
 */

import com.amazonaws.services.lambda.runtime.Context;
import com.objsys.asn1j.runtime.*;
import id.attestation.shankai.Attestation;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import static java.util.Base64.*;

public class Lambda {

    public void parseShankai(InputStream ins, OutputStream outs, Context context) throws IOException{
        ByteBuffer DER;
        {
            byte[] json_input = new byte[ins.available()];
            ins.read(json_input);
            ins.close();
            ByteBuffer base64_encoded = ByteBuffer.wrap(json_input, 1, json_input.length - 2);

            // maybe through base64-encoded single string then decode it with:
            DER = getDecoder().decode(base64_encoded);
            // java.io.FileInputStream ins = new java.io.FileInputStream("message.dat");
            Attestation value = null;
            // Create a decode buffer object
        }

        // System.out.println(DER.array().length);

        {   // Read and decode the message
            Asn1BerDecodeBuffer decodeBuffer = new Asn1BerDecodeBuffer(DER.array());
            Attestation value = new Attestation();
            value.decode(decodeBuffer);
            Asn1JsonOutputStream encodeStream;
            encodeStream = new Asn1JsonOutputStream(new java.io.OutputStreamWriter(outs));
            value.encode(encodeStream);
            encodeStream.close();
            outs.close();
            /* To improve performance, AWS Lambda may choose to retain
             * an instance of your function and reuse it to serve a
             * subsequent request, rather than creating a new
             * copy. Therefore we do not close Asn1Util runtime, so the
             * reuse of this instance doesn't lead to a crash.
             */
            //Asn1Util.closeRuntime();
        }
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
        String base64_encoded = '"' + Base64.getEncoder().encodeToString(rawDER) + '"';
        InputStream ins = new ByteArrayInputStream(base64_encoded.getBytes());
        (new Lambda()).parseShankai(ins, System.out, null);
    }
}
