package fr.pilou.security.httpsign.service;

import fr.pilou.security.httpsign.model.DerivedComponent;
import fr.pilou.security.httpsign.model.SignConfiguration;
import fr.pilou.security.httpsign.model.Signature;
import fr.pilou.security.httpsign.model.SignerAlgorithm;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;

@Service
public class SignConfigurationService {
    @Bean
    @ConditionalOnMissingBean
    public SignConfiguration defaultSignConfiguration() {
        // This bean will only be created if no other bean of type MyService is already present.
        Signature signature=new Signature();
        signature.setAlgorithm(SignerAlgorithm.ECDSA_SHA384);
        signature.setWithNonce(false);
        signature.setTimeBeforeExpiration(3L);
        signature.setKeyId(StringUtils.lowerCase(RandomStringUtils.randomAlphanumeric(5)));
        SignConfiguration configuration=new SignConfiguration();
        configuration.getDerivedRequestComponentList().add(DerivedComponent.METHOD);
        configuration.getMandatoryResponseHeader().add("Content-Digest");
        configuration.setSignature(signature);
        return configuration;
    }
}
