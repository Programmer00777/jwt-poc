package com.codelib.jwt.management;

import com.codelib.jwt.constant.Constants;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Handle the revocation of the token (logout).
 * Use a DB in order to allow multiple instances to check for
 * revoked token and allow cleanup at centralized DB level.
 */
public class TokenRevoker {
    /**
     * Constructor – Load DB Driver
     *
     * @throws ClassNotFoundException If any issue occur during DB driver loading
     */
    public TokenRevoker() throws ClassNotFoundException {
        //FIXME: I use this way for the POC because I cannot achieve
        // to make the DataSource injection using @Resource run with the embedded Tomcat.
        Class.forName("org.h2.Driver");
    }

    /**
     * Verify if a digest encoded in HEX of the ciphered token is present
     * in the revocation table
     *
     * @param jwtInHex Token encoded in HEX
     * @return Presence flag
     * @throws Exception If any issue occur during communication with DB
     */
    public boolean isTokenRevoked(String jwtInHex) throws Exception {
        boolean tokenIsPresent = false;

        // Verify a parameter
        if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
            // Decode the ciphered token
            byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

            // Compute an SHA256 of the ciphered token
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] cipheredTokenDigest = digest.digest(cipheredToken);
            String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

            // Search token digest encoded in HEX in DB
            try (Connection con = DriverManager.getConnection(Constants.JDBC_URL)) {
                String query = "SELECT jwt_token_digest FROM revoked_token WHERE jwt_token_digest = ?";
                try (PreparedStatement preparedStatement = con.prepareStatement(query)) {
                    preparedStatement.setString(1, jwtTokenDigestInHex);
                    try (ResultSet resultSet = preparedStatement.executeQuery()) {
                        tokenIsPresent = resultSet.next();
                    }
                }
            }
        }

        return tokenIsPresent;
    }

    /**
     * Add a digest encoded in HEX of the ciphered token to the revocation token table
     *
     * @param jwtInHex Token encoded in HEX
     * @throws Exception If any issue occur during communication with DB
     */
    public void revokeToken(String jwtInHex) throws Exception {
        // Verify a parameter
        if (jwtInHex != null && !jwtInHex.trim().isEmpty()) {
            // Decode the ciphered token
            byte[] cipheredToken = DatatypeConverter.parseHexBinary(jwtInHex);

            // Compute an SHA256 of the ciphered token
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] cipheredTokenDigest = digest.digest(cipheredToken);
            String jwtTokenDigestInHex = DatatypeConverter.printHexBinary(cipheredTokenDigest);

            // Check if the token digest encoded in HEX is already in the DB and add it if it is absent
            if (!this.isTokenRevoked(jwtInHex)) {
                try (Connection con = DriverManager.getConnection(Constants.JDBC_URL)) {
                    String query = "INSERT INTO revoked_token(jwt_token_digest) VALUES(?)";
                    int insertedRecordCount;
                    try (PreparedStatement preparedStatement = con.prepareStatement(query)) {
                        preparedStatement.setString(1, jwtTokenDigestInHex);
                        insertedRecordCount = preparedStatement.executeUpdate();
                    }
                    if (insertedRecordCount != 1) {
                        throw new IllegalStateException("Number of inserted records is invalid, 1 expected but is "
                                                                                                + insertedRecordCount);
                    }
                }
            }
        }
    }
}
