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
import org.springframework.util.CollectionUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;


@Service
public class SigningResponse {

    protected final SigningResponseStringService service;
    protected final SignerKeyStore signKeyStore;

    SigningResponse(@Autowired SigningResponseStringService service,
                    @Autowired SignerKeyStore signKeyStore)
    {
        this.service=service;
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

    private HttpHeaders fromHttpResponse(HttpServletResponse httpResponse)
    {
        return httpResponse.getHeaderNames()
                .stream()
                .collect(Collectors.toMap(
                        Function.identity(),
                        h -> (httpResponse.getHeaders(h).stream().toList()),
                        (oldValue, newValue) -> newValue,
                        HttpHeaders::new
                ));
    }
    private HttpHeaders fromHttpRequest(HttpServletRequest httpRequest)
    {
        Map<String, List<String>> valueMap=new HashMap<>();
        httpRequest.getHeaderNames().asIterator().forEachRemaining(h -> {
            List<String> value=valueMap.getOrDefault(h,new ArrayList<>());
            httpRequest.getHeaders(h).asIterator().forEachRemaining(value::add);
            valueMap.put(h.toLowerCase(),value);
        });
        return new HttpHeaders(CollectionUtils.toMultiValueMap(valueMap));
    }
    public Pair<String, String> signatureString(HttpServletRequest httpRequest, HttpServletResponse httpResponse,SignConfiguration signConfiguration)
    {

        HttpHeaders httpResponseHeaders =fromHttpResponse(httpResponse);
        HttpHeaders httpRequestHeaders = fromHttpRequest(httpRequest);
        
        java.util.Map<DerivedComponent,String> derivedComponentRequestStringMap=new EnumMap<>(DerivedComponent.class);
        java.util.Map<DerivedComponent,String> derivedComponentResponseStringMap=new EnumMap<>(DerivedComponent.class);
        signConfiguration.getDerivedRequestComponentList().forEach(
                derivedComponent -> {
                    try {
                        derivedComponentRequestStringMap.put(derivedComponent,
                                getDerivedComponentValue(httpRequest,httpResponse,derivedComponent));
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                }
        );
        signConfiguration.getDerivedResponseComponentList().forEach(
                derivedComponent -> {
                    try {
                        derivedComponentResponseStringMap.put(derivedComponent,
                                getDerivedComponentValue(httpRequest,httpResponse,derivedComponent));
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                }
        );
        return service.createSigningString(signConfiguration.getMandatoryRequestHeader()
                ,signConfiguration.getMandatoryResponseHeader(),
                httpRequestHeaders,httpResponseHeaders,
                derivedComponentRequestStringMap,derivedComponentResponseStringMap,
                signConfiguration.getSignature() );

    }
    public Pair<String, String> signResponse(HttpServletRequest httpRequest, HttpServletResponse httpResponse,SignConfiguration signConfiguration) throws SignerException {
        Pair<String, String> signString=this.signatureString(httpRequest,httpResponse,signConfiguration);
        return Pair.of(signString.getLeft(),this.signKeyStore.sign(signConfiguration.getSignature().getKeyId(),
                signConfiguration.getSignature().getAlgorithm(),signString.getRight()));

    }
}
