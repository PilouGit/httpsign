package fr.pilou.security.hash;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@SpringBootTest
class DemoApplicationTests {

	@Test
	void contextLoads() throws NoSuchAlgorithmException {
		String test="{\"hello\": \"world\"}";
		MessageDigest digester = MessageDigest.getInstance("SHA-256");
		digester.update(test.getBytes(StandardCharsets.UTF_8));
		System.err.println(Base64.getEncoder().encodeToString(digester.digest()));
		digester.reset();;
		digester.update("".getBytes(StandardCharsets.UTF_8));
		System.err.println(Base64.getEncoder().encodeToString(digester.digest()));
		digester.reset();;

	}

}
