package fr.pilou.security.httpsign.exception;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

public class SignerException extends Exception{
    public SignerException(GeneralSecurityException e) {
        super(e);
    }

    public SignerException(UnsupportedEncodingException e) {
        super(e);
    }

    public SignerException(String keyNotFound) {
        super(keyNotFound);
    }

    public SignerException(IOException e) {
        super(e);
    }

    public SignerException(Exception e) {

        super(e);
    }
}
