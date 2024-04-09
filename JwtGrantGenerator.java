package no.difi.oauth2.utils;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.client5.http.fluent.Response;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.message.BasicClassicHttpResponse;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.*;
import org.json.JSONObject;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

public class JwtGrantGenerator {

    public static List<X509Certificate> fullChain = new ArrayList<>();
    private static PrivateKey privateKey;

    public static void main(String[] args) throws Exception {

        System.out.println("Password >>" + args[0] + "<<");

        // The certificate password is passed as the first argument
        load(args[0]);

        // Make a JWT from the certificate and private key loaded
        String jwt = makeJwt();
        System.out.println("Generated JWT-grant:");
        System.out.println(jwt);


        // I can take the created JWT and use a online parser to decode it. Like https://jwt.io/  All the information (header and payload) look correct

        // Send in JWT for authentication
        System.out.println("\nRetrieved token-response:");
        String tokenAnswer = makeTokenRequest(jwt);
        System.out.println(tokenAnswer);
        System.out.println("");


        // The JWT was accepted and an valid response was sent back. 
        // We can assume that the privat key loaded here in this code and the public key stored at digdir.no match and that the request in the JWT was accepted.
        // Result looks like this:
        /*
            {
                "access_token": "eyJraWQiOiJP...removed...onMRSItNCTC6",
                "token_type": "Bearer",
                "expires_in": 7199,
                "scope": "svv:kjoretoy/kjoretoyopplysninger"                          
            }                 
         */
        // Extract "access_token" from the JSON
        JSONObject jsonObj = new JSONObject(tokenAnswer);
        String accessToken = jsonObj.getString("access_token"); 


        // Use the access token to do a car lookup
        System.out.println("");
        System.out.println("Car info:");
        String carInfo = makeVehicleLookupRequest(accessToken);
        System.out.println(carInfo);

    }



    public static void load(String password) throws Exception {
        String keystoreType = "JKS";

        // This is the "virksomhetssertifikat" file recieved from Commfides. There where also two other files GSBildeler070324_Enc.p12 and GSBildeler070324_Sign.p12
        String keystoreFile = "C:\\GS\\virksomhetssertifikat\\2024\\GSBildeler070324_Auth.p12";
        String alias = "GS BILDELER AS";

        // Open a stream to the certificate file
        InputStream is = new FileInputStream(keystoreFile);

        // Create a key store
        KeyStore keyStore = KeyStore.getInstance(keystoreType);

        // Load the certificate into the store
        keyStore.load(is, password.toCharArray());

        // Close the file stream
        is.close();

        // Get the private key using the password
        privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray()); 

        if (privateKey == null) {
            throw new Exception("private key is null");
        }

        // Since we have a private key we can assume that loading the certificate using filepath, alias and password is correct.
        System.out.println("");
        System.out.println("");
        System.out.println("Private key:");        
        System.out.println("Algorithm:"+ privateKey.getAlgorithm());
        


        // Get the entire certificate chain
        Certificate[] chain = keyStore.getCertificateChain(alias);

        if (chain == null) {
            throw new Exception("Could not obtain the certificate chain.");
        }

        // Print out the chain
        System.out.println("");
        System.out.println("");
        System.out.println("Certificate Chain Details:");
        for (int i = 0; i < chain.length; i++) {
            if (chain[i] instanceof X509Certificate) {

                X509Certificate cert = (X509Certificate) chain[i];                
                System.out.println("Certificate " + (i + 1) + ":");
                System.out.println("Subject: " + cert.getSubjectDN());
                System.out.println("Issuer: " + cert.getIssuerDN());
                System.out.println("Serial Number: " + cert.getSerialNumber());
                System.out.println("Valid From: " + cert.getNotBefore());
                System.out.println("Valid To: " + cert.getNotAfter());
                System.out.println("Signature Algorithm: " + cert.getSigAlgName());
                System.out.println(); 

                fullChain.add(cert);
            } else {
                System.out.println("Certificate " + (i + 1) + " is not an instance of X509Certificate.");
            }
        }

        System.out.println("");
        System.out.println("");

    }



    private static String makeJwt() throws Exception {

        // Build an array of all cerificates in the chain. Each certificate is base64 encoded.
        List<Base64> certChain = new ArrayList<>();
        for (int i = 0; i < fullChain.size(); i++) {
            X509Certificate temp = fullChain.get(i);
            certChain.add(com.nimbusds.jose.util.Base64.encode(temp.getEncoded()));
        }

        // Build the header for the request
        // It contains the "Kid" = certificate identification and the certificate chain        
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        headerBuilder.keyID("81349d98-468a-455d-8691-eb34e5fe3194");
        headerBuilder.x509CertChain(certChain);
        JWSHeader jwtHeader = headerBuilder.build();

        // Then build the payload
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .audience("https://maskinporten.no/")
                .claim("resource", "https://akfell-datautlevering.atlas.vegvesen.no/kjoretoyoppslag/bulk/kjennemerke")
                .issuer("7eff488a-dbda-4eec-b52d-0900d11f8ba6")         // This identifes the API interface -> https://sjolvbetjening.samarbeid.digdir.no/integrations/7eff488a-dbda-4eec-b52d-0900d11f8ba6
                .claim("scope", "svv:kjoretoy/kjoretoyopplysninger")
                .claim("consumer_org", "980501515")
                .jwtID(UUID.randomUUID().toString()) // Must be unique for each grant
                .issueTime(new Date(Clock.systemUTC().millis() - 1000)) // Use UTC time!
                .expirationTime(new Date(Clock.systemUTC().millis() + 120000));

        JWTClaimsSet claims = builder.build();

        // The JWT is sign with the private key.
        // The public key has been uploaded to digdir.no with the kid: 81349d98-468a-455d-8691-eb34e5fe3194
        JWSSigner signer = new RSASSASigner(privateKey);
        SignedJWT signedJWT = new SignedJWT(jwtHeader, claims);
        signedJWT.sign(signer);

        // Return the JWT
        return signedJWT.serialize();
    }

    private static String makeTokenRequest(String jwt) {

        // Build the body parameters needed. Only two "grant_type" and "assertion"
        List<NameValuePair> body = Form.form()
                .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                .add("assertion", jwt)
                .build();
        try {
            // Post the request
            Response response = Request.post("https://maskinporten.no/token")
            .addHeader("Content-Type", "application/x-www-form-urlencoded")
            .bodyForm(body)
            .execute();

            // Parse and return response
            HttpEntity e = ((BasicClassicHttpResponse) response.returnResponse()).getEntity();
            return EntityUtils.toString(e);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    // This is where it fails
    private static String makeVehicleLookupRequest(String bearerToken) {

        // Build body. My car Volkswagen Transporter 2012 model
        String requestBody = "[{\"kjennemerke\": \"KT81427\"}]";
        try {
            // Add headers for content type and Authorization type to Bearer with token
            // Set the body string
            // Post and get result.
            // This fails on the "returnContent()" call with 401

            String response = Request
                    .post("https://akfell-datautlevering.atlas.vegvesen.no/kjoretoyoppslag/bulk/kjennemerke")
                    .addHeader("Authorization", "Bearer " + bearerToken)
                    .addHeader("Content-Type", "application/json")
                    .bodyString(requestBody, ContentType.APPLICATION_JSON)
                    .execute()
                    .returnContent()
                    .asString();

            return response;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


}
