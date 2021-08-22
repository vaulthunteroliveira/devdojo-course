package academy.devdojo.youtube.security.token.creator;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import academy.devdojo.youtube.core.model.ApplicationUser;
import academy.devdojo.youtube.core.propertie.JwtConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenCreator {
	
	private final JwtConfiguration jwtConfiguration;
	
	@SneakyThrows
	public SignedJWT createSignedJwt(Authentication authentication) {
		log.info("start to create signed JWT");

		ApplicationUser applicationUser = (ApplicationUser) authentication.getPrincipal();

		JWTClaimsSet jwtClaimsSet = createJwtClaimsSet(authentication, applicationUser);

		KeyPair rsaKeys = generateKeyPair();

		log.info("building JWK from the RSA Keys");

		JWK jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();

		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwk).type(JOSEObjectType.JWT).build(), jwtClaimsSet);

		log.info("Signing the token with the private RSA key");

		RSASSASigner signer = new RSASSASigner(rsaKeys.getPrivate());

		signedJWT.sign(signer);

		log.info("serialized token '{}'", signedJWT.serialize());
		
		return signedJWT;
	}
	
	private JWTClaimsSet createJwtClaimsSet(Authentication authentication, ApplicationUser applicationUser) {
		log.info("creating jwtclaims for {} object", applicationUser);

		return new JWTClaimsSet.Builder().subject(applicationUser.getUsername())
				.claim("authorities",
						authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
								.collect(Collectors.toList()))
				.issuer("irineu").issueTime(new Date())
				.expirationTime(new Date(System.currentTimeMillis() + (jwtConfiguration.getExpiration() * 1000)))
				.build();

	}

	@SneakyThrows
	private KeyPair generateKeyPair() {
		log.info("Generating RSA 2048 bits keys");

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

		generator.initialize(2048);

		return generator.genKeyPair();

	}
	
	@SneakyThrows
	public String encryptToken(SignedJWT signedJWT) {
		log.info("Starting the encryptToken method");

		DirectEncrypter directEncrypter = new DirectEncrypter(jwtConfiguration.getPrivtaeKey().getBytes());

		JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
				.contentType("JWT")
				.build(), new Payload(signedJWT));
		
		log.info("Encrypting token with sistem's private key");
		
		jweObject.encrypt(directEncrypter);
		
		log.info("token encrypted");

		return jweObject.serialize();
	}
	
	
}
