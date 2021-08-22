package academy.devdojo.youtube.core.auth.security;

import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.cert.ocsp.Req;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;

import academy.devdojo.youtube.core.auth.filter.JwtUsernameAndPasswordAuthenticationFilter;
import academy.devdojo.youtube.core.propertie.JwtConfiguration;
import academy.devdojo.youtube.core.repository.CourseRepository;
import lombok.RequiredArgsConstructor;

@EnableWebSecurity
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class SecurityCredentialsConfig extends WebSecurityConfigurerAdapter{
	
	private final UserDetailsService userDetailsService;
	private final JwtConfiguration jwtConfiguration;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
		//desabilitando csrf
		.csrf().disable()
		//
		.cors().configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues())
		//sessão sem estado 
		.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		//
		.and().exceptionHandling().authenticationEntryPoint((req, res, ex) -> res.sendError(HttpServletResponse.SC_UNAUTHORIZED))
		///login/**
		//.and().addFilter(null).authorizeRequests().antMatchers(JwtConfiguration.getLoginUrl()).permitAll()
		.and().addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfiguration)).authorizeRequests().antMatchers("login/**").permitAll()
		//
		.antMatchers("/courses/admin/**").hasRole("ADMIN")
		//
		.anyRequest().authenticated();
		
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(); 
	}
	
}
