package fr.pilou.security;

import fr.pilou.security.httpsign.exception.SignerException;
import fr.pilou.security.httpsign.service.SignerKeyStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestSignController {

    @Autowired
    SignerKeyStore keyStore;
    @GetMapping(value = "/", produces ="application/json")
    public String greeting() {
        return "{\"hello\": \"world\"}\n";
    }
    @GetMapping(value="/publickey/{keyuid}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String publicKey(@PathVariable("keyuid") String keyuid) throws SignerException {
        return keyStore.publicKey(keyuid);
    }

}
