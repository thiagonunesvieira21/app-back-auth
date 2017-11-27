package br.com.oauth.controller;

import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.com.oauth.service.AcessoUsuarioService;
import br.com.util.entity.AcessoUsuario;
import br.com.util.json.bean.Login;
import br.com.util.security.Token;
import io.swagger.annotations.ApiOperation;

@RestController
@RequestMapping(value = "/auth")
public class LoginController {

	@Autowired
	private AcessoUsuarioService usuarioService;
	
	@RequestMapping(value = "/login", method=RequestMethod.POST, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ApiOperation(notes="Guarde o token gerado para futuras requisições", value = "Login do sistema", response=Token.class)
	public ResponseEntity<?> doLogin(HttpServletRequest request, HttpServletResponse response,
			@RequestBody Login login) throws UnknownHostException {
		
		AcessoUsuario usuario = usuarioService.doLogin(request, response, login.getLogin(), login.getSenha());
		HashMap<String, Object> map = new HashMap<>();
		
		
		if(usuario == null) {
			map.put("msg", "Usuário ou senha inválido");
			return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
		}
		
		if(usuario.getSenhaExpirada() !=null && usuario.getSenhaExpirada()) {
			map.put("senhaExpirada", true);
			return new ResponseEntity<>(map, HttpStatus.FORBIDDEN);
		}
		
		usuario.setDtHrUltimoAcesso(new Date());
		usuario = usuarioService.save(usuario);
		Token token = new Token(usuarioService.getUserToken());

		return new ResponseEntity<>(token, HttpStatus.OK);
	}
	
}
