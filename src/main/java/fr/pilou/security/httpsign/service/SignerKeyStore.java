package fr.pilou.security.httpsign.service;

import fr.pilou.security.httpsign.exception.SignerException;
import fr.pilou.security.httpsign.model.SignerAlgorithm;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class SignerKeyStore {

    Map<String, KeyPair> keyPairMap=new HashMap<>();

    protected KeyPair createECCKeyPair() throws  SignerException {
    try {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"));

        return kpGen.generateKeyPair();
    } catch (NoSuchAlgorithmException| NoSuchProviderException| InvalidAlgorithmParameterException e)
        {
            throw new SignerException(e);
        }
    }
    public String publicKey(String keyId) throws SignerException {
        try {
            StringWriter privateKey=new StringWriter();
         JcaPEMWriter writer=new  JcaPEMWriter(privateKey);
        KeyPair keyPair=this.keyPairMap.get(keyId);
        if (keyPair==null) throw new SignerException("Key not found");
            writer.writeObject(keyPair.getPublic());
        writer.close();
        return privateKey.toString();
        } catch (IOException e) {
            throw new SignerException(e);
        }

    }
    public String sign(String keyId, SignerAlgorithm signerAlgorithm,String plainText) throws  SignerException
    {

        try {
        KeyPair keyPair=this.keyPairMap.computeIfAbsent(keyId, e->{

            if (signerAlgorithm.isEC()) {
                try {
                    return createECCKeyPair();
                } catch (SignerException ex) {
                    throw new RuntimeException(ex);
                }
            }
            return null;
        });
        Signature signature = Signature.getInstance(signerAlgorithm.getJvmName());
        signature.initSign(keyPair.getPrivate());
        signature.update(plainText.getBytes(StandardCharsets.UTF_8));
  return Base64.getEncoder().encodeToString(signature.sign());
    } catch (NoSuchAlgorithmException |
             SignatureException |InvalidKeyException e)
    {
        throw new SignerException(e);
    }
    }
}
