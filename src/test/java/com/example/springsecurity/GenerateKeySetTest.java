package com.example.springsecurity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

class GenerateKeySetTest {

    @Test
    void verify() throws BadJOSEException, ParseException, JOSEException {
        var token = "test";

        var claimSet = SpringSecurityApplication.jwtProcessor.process(token, null);
        System.out.println(claimSet);
    }

    @Test
    void generateKeSetAndToken() throws JOSEException {
        var jwk1 = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        var jwk2 = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();
        var jwk3 = new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .keyID(UUID.randomUUID().toString())
                .generate();

        System.out.println(jwk1.toPrivateKey().toString());

        var jwks = "{\"keys\":[" + jwk2.toPublicJWK() + " , " + jwk1.toPublicJWK() + "]}";

        var claimSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .jwtID(UUID.randomUUID().toString())
                .claim("scp", "ROLE_USER, ROLE_ADMIN")
                .expirationTime(new Date(new Date().getTime() + 24 * 60 * 60 * 1000))
                .build();

        var signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(jwk1.getKeyID()).build(),
                claimSet
        );

        signedJWT.sign(new RSASSASigner(jwk1));
        var token = signedJWT.serialize();

        System.out.println("keyset:\n" + jwks);
        System.out.println("token:\n" + token);
    }
}
