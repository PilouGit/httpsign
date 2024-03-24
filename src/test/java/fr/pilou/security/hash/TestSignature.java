package fr.pilou.security.hash;

import fr.pilou.security.httpsign.model.DerivedComponent;
import fr.pilou.security.httpsign.model.SignConfiguration;
import fr.pilou.security.httpsign.model.Signature;
import fr.pilou.security.httpsign.model.SignerAlgorithm;
import fr.pilou.security.httpsign.service.SigningResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SpringBootTest
public class TestSignature {
    @Autowired
    SigningResponse signingResponse;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;


    public void init() throws IOException {
        this.request=new MockHttpServletRequest();
        request.setMethod("POST");
        request.setRequestURI("/foo");
        request.addHeader("Host", "example.com");
        request.addHeader("Date", "Tue, 20 Apr 2021 02:07:55 GMT");
        request.addHeader("Content-Type", "application/json");
        request.addHeader("Content-Digest", "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
        request.addHeader("Example-Dict", "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid");
        request.addHeader("Content-Length", " 18");
        request.setContent("{\"hello\": \"world\"}".getBytes());

        this.response=new MockHttpServletResponse();
        response.addHeader("Date","Tue, 20 Apr 2021 02:07:56 GMT");
        response.addHeader("Content-Type","application/json");
        response.addHeader("Content-Digest","sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
        response.addHeader( "Content-Length","18");

        response.setStatus(200);
        response.getOutputStream().write("{\"hello\": \"world\"}".getBytes());
    }
    SignConfiguration getSignConfiguration()
    {
        SignConfiguration signConfiguration=new SignConfiguration();
        signConfiguration.getDerivedRequestComponentList().add(DerivedComponent.METHOD);
        signConfiguration.getDerivedResponseComponentList().add(DerivedComponent.STATUS);
        signConfiguration.getMandatoryRequestHeader().add("Date");
        signConfiguration.getMandatoryResponseHeader().add("Content-Digest");
        signConfiguration.getMandatoryResponseHeader().add("Date");
        Signature signature=new Signature();
        signature.setAlgorithm(SignerAlgorithm.ECDSA_SHA384);
        signature.setWithNonce(true);
        signature.setTimeBeforeExpiration(3L);
        signature.setKeyId(StringUtils.lowerCase(RandomStringUtils.randomAlphanumeric(5)));
        signConfiguration.setSignature(signature);
return signConfiguration;
    }
    public PrivateKey readPKCS8PrivateKey() throws Exception {
        File file=new File("/home/pilou/key.pem");
        String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());
        ;
        KeyFactory factory = KeyFactory.getInstance("EC","BC");

        String publicKeyPEM = key
                .replace("-----BEGIN EC PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END EC PRIVATE KEY-----", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (PrivateKey) factory.generatePublic(keySpec);

    }
    @Test
    public void verifySignature() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        init();

        Pair<String, String> result = this.signingResponse.signatureString(this.request, this.response,getSignConfiguration());
        System.err.println(result.getRight());
        String expectedREsult="\"@method\";req: POST\n" +
                "\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n" +
                "\"date\": Tue, 20 Apr 2021 02:07:56 GMT\n" +
                "\"date\";req: Tue, 20 Apr 2021 02:07:55 GMT\n" +
                "\"@signature-params\": (\"@method\";req \"content-digest\" \"date\" \"date\";req)";

        String key=result.getKey();
        System.err.println(key);

        java.security.Signature signature = java.security.Signature.getInstance("SHA384withECDSA");
        signature.initSign(readPKCS8PrivateKey());
        signature.update(key.getBytes(StandardCharsets.UTF_8));
        System.err.println(Base64.getEncoder().encodeToString(signature.sign()));
    }
}
