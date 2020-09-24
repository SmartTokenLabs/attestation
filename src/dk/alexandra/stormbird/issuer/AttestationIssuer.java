package dk.alexandra.stormbird.issuer;

import com.amazonaws.Request;
import com.amazonaws.services.lambda.runtime.*;

import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


// when updated and built, run this to deploy

// aws lambda update-function-code --function-name AttestationIssuer --zip-file fileb://build/distributions/blockchain-attestation.zip

// Handler value: example.Handler
public class AttestationIssuer implements RequestStreamHandler {
  Gson gson = new GsonBuilder().setPrettyPrinting().create();

  @Override
  public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) throws IOException
  {
    LambdaLogger logger = context.getLogger();
    BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("US-ASCII")));
    PrintWriter writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(outputStream, Charset.forName("US-ASCII"))));
    try
    {
      HashMap event = gson.fromJson(reader, HashMap.class);
      logger.log("STREAM TYPE: " + inputStream.getClass().toString());
      logger.log("EVENT TYPE: " + event.getClass().toString());
      if (((ArrayList) event.get("Errors")).size() == 0) {
        // Having Errors in the Response is not an error of this Lambda
        logger.log("Errors In the Response: " + gson.toJson(event.get("Errors")));
      }
      writer.write(gson.toJson(event));
      if (writer.checkError())
      {
        logger.log("WARNING: Writer encountered an error.");
      }
    }
    catch (IllegalStateException | JsonSyntaxException exception)
    {
      logger.log(exception.toString());
    }
    finally
    {
      reader.close();
      writer.close();
    }
  }

  public void handleTruliooVerifyResponse(InputStream inputStream, OutputStream outputStream, Context context) throws IOException
  {
    handleRequest(inputStream, outputStream, context);
  }
}