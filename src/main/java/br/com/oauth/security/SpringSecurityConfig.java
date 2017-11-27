package br.com.oauth.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.util.security.TokenAuthenticationService;
import br.com.util.security.UserService;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	private UserService userService;
	private final TokenAuthenticationService tokenAuthentication;

	public SpringSecurityConfig() {
		super(true);
		this.userService = new UserService();
		tokenAuthentication = new TokenAuthenticationService(userService);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.headers().cacheControl();

		http
				.cors()
				.and()
				.exceptionHandling().and()
				.anonymous().and()
				.servletApi().and()
				.headers().cacheControl().and().and()
				.authorizeRequests()
				.antMatchers("/").permitAll()
				.antMatchers("/auth/**").permitAll()
				.antMatchers("/user/esqueci-senha/**").permitAll()
				.antMatchers("/user/trocar-senha").permitAll()
				.antMatchers("/swagger*").permitAll()
				.antMatchers("/webjars/springfox-swagger-ui/**").permitAll()
				.antMatchers("/v2/**").permitAll()
				.antMatchers("/configuration/**").permitAll()
				.antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				.anyRequest().authenticated()
				.and()
				.addFilterBefore(new StatelessAuthenticationFilter(tokenAuthentication),
						UsernamePasswordAuthenticationFilter.class);
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers(HttpMethod.OPTIONS, "/**")
				.antMatchers(HttpMethod.POST, "/auth/**")
				.antMatchers(HttpMethod.POST, "/user/esqueci-senha")
				.antMatchers(HttpMethod.POST, "/user/trocar-senha")
				.antMatchers("/webjars/springfox-swagger-ui/**")
				.antMatchers("/swagger*")
				.antMatchers("/v2/**")
				.antMatchers("/configuration/**");
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService).passwordEncoder(new BCryptPasswordEncoder());
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	@Override
	public UserService userDetailsService() {
		return userService;
	}

	@Bean
	public TokenAuthenticationService tokenAuthentication() {
		return tokenAuthentication;
	}

}