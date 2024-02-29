package fr.pilou.security.httpsign.model;


import java.util.ArrayList;
import java.util.List;


public class SignConfiguration {
    protected List<DerivedComponent> derivedComponentList=new ArrayList<>();
    protected List<String> mandatoryHeader=new ArrayList<>();

    protected Signature signature;

    public List<DerivedComponent> getDerivedComponentList() {
        return derivedComponentList;
    }

    public void setDerivedComponentList(List<DerivedComponent> derivedComponentList) {
        this.derivedComponentList = derivedComponentList;
    }

    public List<String> getMandatoryHeader() {
        return mandatoryHeader;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    public void setMandatoryHeader(List<String> mandatoryHeader) {
        this.mandatoryHeader = mandatoryHeader;
    }


}
