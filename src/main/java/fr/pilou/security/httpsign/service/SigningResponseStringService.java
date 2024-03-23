package fr.pilou.security.httpsign.service;

import fr.pilou.security.httpsign.model.DerivedComponent;
import fr.pilou.security.httpsign.model.Signature;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;


@Service
class SigningResponseStringService {



    private String escapeString(String key,boolean request)
    {
        StringBuilder builder=new StringBuilder();
        builder.append('"').append(StringUtils.lowerCase(key));
        if (request) builder.append("\";req");else builder.append('"');
        return builder.toString();
    }
    private long getUnixTimeStamp()
    {
        return System.currentTimeMillis()/1000;

    }

    public Pair<String, String> createSigningString(final List<String> requiredRequestHeaders,
                                                    final List<String> requiredResponseHeaders,
                                                    HttpHeaders requestHeaders,
                                                    HttpHeaders responseHeaders,

                                                    final Map<DerivedComponent,String> requestDerivatedComponent,
                                                    final Map<DerivedComponent,String> reponseDerivatedComponent,

                                                    Signature signature )
    {

        long creationTime=getUnixTimeStamp();
        long expirationTime=creationTime+signature.getTimeBeforeExpiration();
        String nonce=signature.isWithNonce()?  RandomStringUtils.randomAlphanumeric(10):"";

        StringBuilder builder=new StringBuilder();
        List<String> signatureParamsKey=new ArrayList<>();
        reponseDerivatedComponent.forEach((derivedComponent,value)->
        {
            String key= escapeString(derivedComponent.getDerivedComponentString(),false);
            builder.append(key).append(": ").append(value).append(StringUtils.LF);
            signatureParamsKey.add(key);
        });
        requestDerivatedComponent.forEach((derivedComponent,value)->
        {
            String key= escapeString(derivedComponent.getDerivedComponentString(),true);
            builder.append(key).append(": ").append(value).append(StringUtils.LF);
            signatureParamsKey.add(key);
        });
        requiredRequestHeaders.forEach(requiredHeader->
                {
                    String key= escapeString(requiredHeader,true);
                    builder.append(key).append(": ").append(requestHeaders.getFirst(requiredHeader.toLowerCase())).append(StringUtils.LF);
                    signatureParamsKey.add(key);
                }
        );
        requiredResponseHeaders.forEach(requiredHeader->
                {
                    String key= escapeString(requiredHeader,false);
                    builder.append(key).append(": ").append(responseHeaders.getFirst(requiredHeader.toLowerCase())).append(StringUtils.LF);
                    signatureParamsKey.add(key);
                }
        );

        String signatureParams=signParam(signatureParamsKey,signature,creationTime,expirationTime,nonce);

          return Pair.of(signatureParams,builder.append("\"@signature-params\": "+signatureParams).toString());
    }
    public String signParam(List<String> signatureParamsKey,
                            Signature signature,Long creationTime,Long expirationTime,
    String nonce)
    {
        StringBuilder signatureParams=new StringBuilder();
        signatureParams.append("(").append(StringUtils.join(signatureParamsKey,' ')).append(");");
        List<String> params=new ArrayList<>();
        params.add("alg="+ escapeString(signature.getAlgorithm().getPortableName(),false ));
        params.add("keyid="+ escapeString(signature.getKeyId(),false));
        params.add("created="+creationTime);
        params.add("expires="+expirationTime);
        if (signature.isWithNonce())
        {
            params.add("nonce="+nonce);

        }
        signatureParams.append(StringUtils.join(params,';'));
        return signatureParams.toString();

    }

}