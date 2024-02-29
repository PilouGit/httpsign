package fr.pilou.security.httpsign.model;

public enum DerivedComponent {
    METHOD("@method"),
    TARGET_URI( "@target-uri"),
    AUTHORITY("@authority"),
    SCHEME( "@scheme"),
    STATUS("@status");

    private final String derivedComponentString;

    DerivedComponent(String derivedComponentString) {
        this.derivedComponentString=derivedComponentString;
    }

    public String getDerivedComponentString() {
        return derivedComponentString;
    }
}
