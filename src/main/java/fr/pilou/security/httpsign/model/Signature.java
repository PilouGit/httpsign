package fr.pilou.security.httpsign.model;


public class Signature {
     private  Long timeBeforeExpiration;
    private SignerAlgorithm algorithm;

    private boolean withNonce;

    private  String keyId;

    public Long getTimeBeforeExpiration() {
        return timeBeforeExpiration;
    }

    public void setTimeBeforeExpiration(Long timeBeforeExpiration) {
        this.timeBeforeExpiration = timeBeforeExpiration;
    }

    public boolean isWithNonce() {
        return withNonce;
    }

    public void setWithNonce(boolean withNonce) {
        this.withNonce = withNonce;
    }

    public SignerAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(SignerAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
