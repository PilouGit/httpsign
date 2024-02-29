package fr.pilou.security.httpsign.service;

import fr.pilou.security.httpsign.exception.SignerException;
import fr.pilou.security.httpsign.model.DerivedComponent;
import fr.pilou.security.httpsign.model.SignConfiguration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.function.Function;
import java.util.stream.Collectors;


@Service
public class SigningResponse {

    protected final SigningResponseStringService service;
    protected final SignConfiguration signConfiguration;
    protected final SignerKeyStore signKeyStore;

    SigningResponse(@Autowired SigningResponseStringService service,
                    @Autowired SignConfiguration signConfiguration,
                    @Autowired SignerKeyStore signKeyStore)
    {
        this.service=service;
        this.signConfiguration=signConfiguration;
        this.signKeyStore=signKeyStore;
    }
    protected String getDerivedComponentValue(HttpServletRequest request, HttpServletResponse httpResponse,DerivedComponent component) throws MalformedURLException {
     return   switch (component)
        {
            case METHOD -> request.getMethod();
            case TARGET_URI -> request.getRequestURL().toString();
            case AUTHORITY -> (new URL(request.getRequestURL().toString())).getAuthority();
            case SCHEME -> request.getScheme();
            case STATUS -> Integer.toString(httpResponse.getStatus());
        };
    }

    protected Pair<String, String> signatureString(HttpServletRequest httpRequest, HttpServletResponse httpResponse)
    {

        HttpHeaders httpHeaders = httpResponse.getHeaderNames()
                .stream()
                .collect(Collectors.toMap(
                        Function.identity(),
                        h -> (httpResponse.getHeaders(h).stream().toList()),
                        (oldValue, newValue) -> newValue,
                        HttpHeaders::new
                ));
        java.util.Map<DerivedComponent,String> derivedComponentStringMap=new HashMap<DerivedComponent,String>();
        signConfiguration.getDerivedComponentList().forEach(
                derivedComponent -> {
                    try {
                        derivedComponentStringMap.put(derivedComponent,
                                getDerivedComponentValue(httpRequest,httpResponse,derivedComponent));
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                }
        );
        return service.createSigningString(signConfiguration.getMandatoryHeader(), httpHeaders,
                derivedComponentStringMap,
                signConfiguration.getSignature() );

    }
    public Pair<String, String> signResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws SignerException {
        Pair<String, String> signString=this.signatureString(httpRequest,httpResponse);
        return Pair.of(signString.getLeft(),this.signKeyStore.sign(this.signConfiguration.getSignature().getKeyId(),
                this.signConfiguration.getSignature().getAlgorithm(),signString.getRight()));

    }
}
