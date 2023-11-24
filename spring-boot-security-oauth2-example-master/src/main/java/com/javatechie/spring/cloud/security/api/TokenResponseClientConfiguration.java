package com.javatechie.spring.cloud.security.api;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import lombok.var;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.function.Function;



@Configuration
public class TokenResponseClientConfiguration {
    private static Base64URL thumbprint;

    @Bean
    OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseCertificateClient() {
        Function<ClientRegistration, JWK> jwkResolver = (clientRegistration) -> {
            if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
                RSAPublicKey publicKey;
                try {
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    var is = Files.newInputStream(ResourceUtils.getFile("classpath:certs/server.crt").toPath());
                    X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);
                    thumbprint = computeSHA1Thumbprint(cer);
                    publicKey = (RSAPublicKey) cer.getPublicKey();
                    return new RSAKey.Builder(publicKey)
                            .privateKey(readPrivateKey(ResourceUtils.getFile("classpath:certs/server.key")))
                            .keyID(thumbprint.toString())
                            .build();
                } catch (CertificateException | IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return null;
        };
        OAuth2AuthorizationCodeGrantRequestEntityConverter requestEntityConverter =
                new OAuth2AuthorizationCodeGrantRequestEntityConverter();
        requestEntityConverter.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver));
        DefaultAuthorizationCodeTokenResponseClient tokenResponseClient =
                new DefaultAuthorizationCodeTokenResponseClient();
        tokenResponseClient.setRequestEntityConverter(requestEntityConverter);
        return tokenResponseClient;
    }

    private RSAPrivateKey readPrivateKey(File file) throws IOException {
        try (FileReader keyReader = new FileReader(file)) {
            PEMParser pemParser = new PEMParser(keyReader);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(((PEMKeyPair) pemParser.readObject()).getPrivateKeyInfo());
            return (RSAPrivateKey) converter.getPrivateKey(privateKeyInfo);
        }
    }

    private static Base64URL computeSHA1Thumbprint(final X509Certificate cert) {
        try {
            byte[] derEncodedCert = cert.getEncoded();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-1");
            return Base64URL.encode(sha256.digest(derEncodedCert));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            return null;
        }
    }
}