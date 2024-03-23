package fr.pilou.security.httpsign.model;


import java.util.ArrayList;
import java.util.List;


public class SignConfiguration {
    protected List<DerivedComponent> derivedRequestComponentList=new ArrayList<>();
    protected List<DerivedComponent> derivedResponseComponentList=new ArrayList<>();
    protected List<String> mandatoryRequestHeader=new ArrayList<>();
    protected List<String> mandatoryResponseHeader=new ArrayList<>();

    protected Signature signature;

    public List<DerivedComponent> getDerivedRequestComponentList() {
        return derivedRequestComponentList;
    }

    public List<DerivedComponent> getDerivedResponseComponentList() {
        return derivedResponseComponentList;
    }

    public List<String> getMandatoryResponseHeader() {
        return mandatoryResponseHeader;
    }

    public void setMandatoryResponseHeader(List<String> mandatoryResponseHeader) {
        this.mandatoryResponseHeader = mandatoryResponseHeader;
    }



    public List<String> getMandatoryRequestHeader() {
        return mandatoryRequestHeader;
    }

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    public void setMandatoryRequestHeader(List<String> mandatoryHeader) {
        this.mandatoryRequestHeader = mandatoryHeader;
    }


}
