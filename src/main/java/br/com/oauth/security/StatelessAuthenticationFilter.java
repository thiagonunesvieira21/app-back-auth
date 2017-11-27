package br.com.oauth.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import br.com.util.security.TokenAuthenticationService;

public class StatelessAuthenticationFilter extends GenericFilterBean {

	private final TokenAuthenticationService authenticationService;

	public StatelessAuthenticationFilter(TokenAuthenticationService authenticationService){
		this.authenticationService = authenticationService;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		if(httpRequest.getHeader(TokenAuthenticationService.AUTH_HEADER_NAME) == null ) {
			httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
			SecurityContextHolder.getContext().setAuthentication(null);
			return;
		} else{
			Authentication authentication = authenticationService.getAuthentication(httpRequest);
			if(authentication != null) {
				SecurityContextHolder.getContext().setAuthentication(authentication);
				filterChain.doFilter(request, response);
			} else {
				httpResponse.setStatus(HttpStatus.UNAUTHORIZED.value());
			}

		}

		SecurityContextHolder.getContext().setAuthentication(null);

	}
}