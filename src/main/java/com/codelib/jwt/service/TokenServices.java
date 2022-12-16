package com.codelib.jwt.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.codelib.jwt.crypto.TokenCipher;
import com.codelib.jwt.management.TokenRevoker;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Provides REST stateless services to manage JWT token.
 */
@Path("/")
public class TokenServices {
    /**
     * Logger
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(TokenServices.class);

    /**
     * Accessor for HMAC key – Block serialization and storage as String
     * in JVM memory
     */
    private transient byte[] keyHMAC = null;

    /**
     * Accessor for ciphering key – Block serialization
     */
    private transient KeysetHandle keyCiphering = null;

    /**
     * Accessor for issuer ID – Block serialization
     */
    private transient String issuerID = null;

    /**
     * Random data generator
     */
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Handler for token ciphering
     */
    private final TokenCipher tokenCipher;

    /**
     * Handler for token revocation
     */
    private final TokenRevoker tokenRevoker;

    /**
     * Constructor – Load keys and issuer ID
     *
     * @throws Exception If any issue occur during keys loading or DB driver loading
     */
    public TokenServices() throws Exception {
        // Load keys from the configuration text/json files in
        // order to avoid to store keys as Strings in JVM memory
        this.keyHMAC = Files.readAllBytes(Paths.get("src", "main", "conf", "key-hmac.txt"));
        this.keyCiphering = CleartextKeysetHandle.read(JsonKeysetReader.withFile(Paths.get("src", "main", "conf", "key-ciphering.json").toFile()));

        // Load issuer ID from the configuration text file
        this.issuerID = Files.readAllLines(Paths.get("src", "main", "conf", "issuer-id.txt")).get(0);

        // Init token ciphering and revocation handlers
        this.tokenCipher = new TokenCipher();
        this.tokenRevoker = new TokenRevoker();
    }

    /**
     * Authenticate (simulation here) a user based on a login/password couple and
     * return a JWT token.
     *
     * @param request Incoming HTTP request
     * @param response HTTP response sent
     * @param login User login
     * @param password User password
     * @return An HTTP response containing the JWT token
     */
    @Path("authenticate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response authenticate(@Context HttpServletRequest request,
                                 @Context HttpServletResponse response,
                                 @FormParam("login") String login,
                                 @FormParam("password") String password) {
        // As it's an authentication simulation we explicitly ignore the password here
        JSONObject jsonObject = new JSONObject();
        Response resp;
        try {
            // Validate login parameter content to avoid malicious input
            if (Pattern.matches("[a-zA-Z0-9]{1,10}", login)) {
                // Generate a random string that will constitute a fingerprint for this user
                byte[] randomFgp = new byte[50];
                this.secureRandom.nextBytes(randomFgp);
                String userFingerprint = DatatypeConverter.printHexBinary(randomFgp);

                // Add the fingerprint in a hardened cookie – Add cookie manually because the SameSite attribute
                // is not supported by javax.servlet.http.Cookie class
                String fingerprintCookie = "__Secure-Fgp=" + userFingerprint + "; SameSite=Strict; HttpOnly; Secure";
                response.addHeader("Set-Cookie", fingerprintCookie);

                // Compute an SHA256 hash of the fingerprint in order to store the fingerprint hash (instead of the
                // raw value) in the token to prevent an XSS to be able to read the fingerprint and set the
                // expected cookie itself
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] userFingerprintDigest = messageDigest.digest(userFingerprint.getBytes(StandardCharsets.UTF_8));
                String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

                // Create the token with a validity of 15 minutes and client context (fingerprint) information
                Calendar calendar = Calendar.getInstance();
                Date now = calendar.getTime();
                calendar.add(Calendar.MINUTE, 15);
                Date expirationDate = calendar.getTime();
                Map<String, Object> headerClaims = new HashMap<>();
                headerClaims.put("typ", "JWT");
                String token = JWT.create().withSubject(login)
                        .withExpiresAt(expirationDate)
                        .withIssuer(this.issuerID)
                        .withIssuedAt(now)
                        .withNotBefore(now)
                        .withClaim("userFingerprint", userFingerprintHash)
                        .withHeader(headerClaims)
                        .sign(Algorithm.HMAC256(this.keyHMAC));

                // Cipher the token
                String cipheredToken = this.tokenCipher.cipherToken(token, this.keyCiphering);

                // Set token in data container
                jsonObject.put("token", cipheredToken);
                jsonObject.put("status", "Authentication successful!");
            } else {
                jsonObject.put("token", "-");
                jsonObject.put("status", "Invalid parameter provided!");
            }

            // Build response
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            LOGGER.error("Error occur during authentication", e);
            // Return a generic error message
            jsonObject.put("token", "-");
            jsonObject.put("status", "An error occur!");
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return resp;
    }

    /**
     * Validate a legitimacy of a call with a JWT.
     * Normally this code is not a service, but it's included in the application as a shared function
     * and used by all business services to validate the token before allowing any business processing.
     *
     * @param request Incoming HTTP request
     * @param authToken jwtToken
     * @return An HTTP response containing the validity status of the call
     */
    @Path("validate")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response validate(@Context HttpServletRequest request, @HeaderParam("Authorization") String authToken) {
        JSONObject jsonObject = new JSONObject();
        Response resp;
        try {
            // Retrieve the token
            String cipheredToken = authToken;
            if (cipheredToken != null) {
                // Remove the "bearer" string part
                cipheredToken = cipheredToken.split(" ")[1].trim();
            } else {
                throw new SecurityException("Token is mandatory!");
            }

            // Check if the token is not revoked
            if (this.tokenRevoker.isTokenRevoked(cipheredToken)) {
                jsonObject.put("status", "Token already revoked!");
            } else {
                // Retrieve the user fingerprint from the dedicated cookie
                String userFingerprint = null;
                if (request.getCookies() != null && request.getCookies().length > 0) {
                    List<Cookie> cookies = Arrays.stream(request.getCookies()).collect(Collectors.toList());
                    Optional<Cookie> cookie = cookies.stream().filter(c -> "__Secure-Fgp".equals(c.getName())).findFirst();
                    if (cookie.isPresent()) {
                        userFingerprint = cookie.get().getValue();
                    }
                }

                // Validate the user fingerprint and token parameters content to avoid malicious input
                System.out.println("FGP ==> " + userFingerprint);
                if (userFingerprint != null && Pattern.matches("[A-Z0-9]{100}", userFingerprint)) {
                    // Decipher the token
                    String token = this.tokenCipher.decipherToken(cipheredToken, this.keyCiphering);

                    // Compute an SHA256 hash of the received fingerprint in order to compare it
                    // to the fingerprint hash stored in the cookie
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] userFingerprintDigest = digest.digest(userFingerprint.getBytes(StandardCharsets.UTF_8));
                    String userFingerprintHash = DatatypeConverter.printHexBinary(userFingerprintDigest);

                    // Create a verification context for the token
                    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(this.keyHMAC))
                            .withIssuer(this.issuerID)
                            .withClaim("userFingerprint", userFingerprintHash)
                            .build();

                    // Verify the token
                    DecodedJWT decodedJWT = verifier.verify(token);

                    // Set token in data container
                    jsonObject.put("status", "Token OK - Welcome '" + decodedJWT.getSubject() + "'!");
                } else {
                    jsonObject.put("status", "Invalid parameter provided!");
                }
            }

            // Build response
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();

        } catch (JWTVerificationException e) {
            LOGGER.warn("Verification of the token failed", e);
            // Return info that validation failed
            jsonObject.put("status", "Invalid token!");
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        } catch (Exception e) {
            LOGGER.warn("Error during token validation", e);
            // Return a generic error message
            jsonObject.put("status", "An error occur!");
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return resp;
    }

    /**
     * Revoke the token (logout)
     *
     * @param authToken JWT token
     * @return An HTTP response containing the validity status of the call
     */
    @Path("revoke")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    public Response revoke(@HeaderParam("Authorization") String authToken) {
        JSONObject jsonObject = new JSONObject();
        Response resp;
        try {
            // Retrieve the token
            String cipheredToken = authToken;
            if (cipheredToken != null) {
                // Remove the "bearer" string part
                cipheredToken = cipheredToken.split(" ")[0].trim();

                // Revoke the token
                this.tokenRevoker.revokeToken(cipheredToken);
                jsonObject.put("status", "Token successfully revoked!");
            } else {
                throw new SecurityException("Token is mandatory!");
            }

            // Build reponse
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();

        } catch (Exception e) {
            LOGGER.warn("Error during token validation", e);
            // Return a generic error message
            jsonObject.put("status", "An error occur!");
            resp = Response.ok(jsonObject.toString(), MediaType.APPLICATION_JSON).build();
        }

        return resp;
    }
}
