package fr.pilou.security.hash;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class TestPemWriter {

    public static KeyPair GenerateKeys() throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidAlgorithmParameterException {
        //  Other named curves can be found in http://www.bouncycastle.org/wiki/display/JA1/Supported+Curves+%28ECDSA+and+ECGOST%29

        KeyPairGenerator  kpGen = KeyPairGenerator.getInstance("EC", "BC");

        kpGen.initialize(new ECGenParameterSpec("P-256"));

        return kpGen.generateKeyPair();


    }
    @Test
    public void testPemWriter() throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyPair keyPair = GenerateKeys();
        StringWriter privateKey=new StringWriter();
        StringWriter publicKey=new StringWriter();
        JcaPEMWriter writer=new  JcaPEMWriter(privateKey);

        writer.writeObject(keyPair.getPrivate());
        writer.close();
        System.err.println(privateKey.toString());

    }
}
