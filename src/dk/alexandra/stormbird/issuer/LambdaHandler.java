package dk.alexandra.stormbird.issuer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.LambdaLogger;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.util.Map;


// when updated and built, run this to deploy

// aws lambda update-function-code --function-name AttestationIssuer --zip-file fileb://build/distributions/blockchain-attestation.zip

// Handler value: example.Handler
public class LambdaHandler implements RequestHandler<Map<String,String>, String> {
  Gson gson = new GsonBuilder().setPrettyPrinting().create();
  @Override
  public String handleRequest(Map<String,String> event, Context context)
  {
    LambdaLogger logger = context.getLogger();
    String response = new String("200 OK");
    // log execution details
    logger.log("ENVIRONMENT VARIABLES: " + gson.toJson(System.getenv()));
    logger.log("CONTEXT: " + gson.toJson(context));
    // process event
    logger.log("EVENT: " + gson.toJson(event));
    for (Map.Entry<String, String> e: event.entrySet()) {
      logger.log(e.getKey() + ":" + e.getValue());
    }
    logger.log("EVENT TYPE: " + event.getClass().toString());
    return response;
  }
}
