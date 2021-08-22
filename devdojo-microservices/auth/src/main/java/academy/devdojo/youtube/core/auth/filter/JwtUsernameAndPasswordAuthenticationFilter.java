package academy.devdojo.youtube.core.auth.filter;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.hibernate.transform.ToListResultTransformer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
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

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final JwtConfiguration jwtConfiguration;

	@Override
	@SneakyThrows
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

		log.info("Attempting authentication...");
		ApplicationUser applicationUser = new ObjectMapper().readValue(request.getInputStream(), ApplicationUser.class);

		if (applicationUser == null)
			throw new UsernameNotFoundException("User not found!");

		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				applicationUser.getUsername(), applicationUser.getPassword(), Collections.emptyList());

		usernamePasswordAuthenticationToken.setDetails(applicationUser);

		return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication auth) throws IOException, ServletException {

		log.info("authetication was successful for the user '{}', generating JWE token.", auth.getName());
		
		SignedJWT signedJWT = createSignedJwt(auth);
		
		String encryptedToken = encryptToken(signedJWT);
		
		log.info("token generated successfully, adding token to the response header");
		
		response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, "+jwtConfiguration.getHeader().getName());
		
		response.addHeader(jwtConfiguration.getHeader().getName(), jwtConfiguration.getHeader().getPrefix() + encryptedToken);
		
		
		
		

	}

	@SneakyThrows
	private SignedJWT createSignedJwt(Authentication authentication) {
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
	private String encryptToken(SignedJWT signedJWT) {
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
