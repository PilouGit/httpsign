package fr.pilou.security.hash;

import fr.pilou.security.httpsign.model.DerivedComponent;
import fr.pilou.security.httpsign.model.SignConfiguration;
import fr.pilou.security.httpsign.model.Signature;
import fr.pilou.security.httpsign.model.SignerAlgorithm;
import fr.pilou.security.httpsign.service.SigningResponse;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;

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
        signature.setWithNonce(false);
        signature.setTimeBeforeExpiration(3L);
        signature.setKeyId(StringUtils.lowerCase(RandomStringUtils.randomAlphanumeric(5)));
        signConfiguration.setSignature(signature);
return signConfiguration;
    }
    @Test
    public void verifySignature() throws IOException {
        init();

        Pair<String, String> result = this.signingResponse.signatureString(this.request, this.response,getSignConfiguration());
        System.err.println(result.getRight());
        String expectedREsult="\"@method\";req: POST\n" +
                "\"content-digest\": sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:\n" +
                "\"date\": Tue, 20 Apr 2021 02:07:56 GMT\n" +
                "\"date\";req: Tue, 20 Apr 2021 02:07:55 GMT\n" +
                "\"@signature-params\": (\"@method\";req \"content-digest\" \"date\" \"date\";req)";

        System.err.println(result.getKey());
    }
}
