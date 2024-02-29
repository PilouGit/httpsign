package fr.pilou.security.httpsign.model;

import org.apache.commons.lang3.StringUtils;

public enum SignerAlgorithm {
    ECDSA_SHA1("SHA1withECDSA", "ecdsa-sha1"),
    ECDSA_SHA256("SHA256withECDSA", "ecdsa-sha256"),
    ECDSA_SHA384("SHA384withECDSA", "ecdsa-sha384"),
    ECDSA_SHA512("SHA512withECDSA", "ecdsa-sha512");


    private final String portableName;
    private final String jvmName;

    public boolean isEC()
    {
        return StringUtils.contains(portableName,"ecdsa");
    }
    SignerAlgorithm(final String jvmName, final String portableName)
    {
        this.jvmName=jvmName;
        this.portableName=portableName;
    }

    public String getPortableName() {
        return portableName;
    }

    public String getJvmName() {
        return jvmName;
    }
}
