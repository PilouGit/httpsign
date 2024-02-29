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


    private String escapeString(String key)
    {
        StringBuilder builder=new StringBuilder();
        builder.append('"').append(StringUtils.lowerCase(key)).append('"');
        return builder.toString();
    }
    private long getUnixTimeStamp()
    {
        return System.currentTimeMillis()/1000;

    }

    public Pair<String, String> createSigningString(final List<String> required, HttpHeaders headers,
                                                    final Map<DerivedComponent,String> derivatedValue,
                                                    Signature signature )
    {

        long creationTime=getUnixTimeStamp();
        long expirationTime=creationTime+signature.getTimeBeforeExpiration();
        String nonce=signature.isWithNonce()?  RandomStringUtils.randomAlphanumeric(10):"";

        StringBuilder builder=new StringBuilder();
        List<String> signatureParamsKey=new ArrayList<>();
        derivatedValue.forEach((derivedComponent,value)->
        {
            String key=escapeString(derivedComponent.getDerivedComponentString());
            builder.append(key).append(": ").append(value).append(StringUtils.LF);
            signatureParamsKey.add(key);
        });
        required.forEach(requiredHeader->
                {
                    String key=escapeString(requiredHeader);
                    builder.append(key).append(": ").append(headers.getFirst(requiredHeader)).append(StringUtils.LF);
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
        params.add("alg="+escapeString(signature.getAlgorithm().getPortableName()));
        params.add("keyid="+escapeString(signature.getKeyId()));
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