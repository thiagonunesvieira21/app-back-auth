package br.com.oauth.service;

import static br.com.util.utilities.MyHibernateUtils.listAndCast;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.transaction.Transactional;

import org.hibernate.Criteria;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.oauth.criteria.UsuarioCriteria;
import br.com.util.entity.AcessoUsuario;
import br.com.util.enums.StatusUsuario;
import br.com.util.repository.AcessoUsuarioRepository;
import br.com.util.security.SecurityUser;
import br.com.util.security.TokenAuthenticationService;
import br.com.util.security.UserAuthentication;
import br.com.util.security.UserService;
import br.com.util.service.GenericService;

@Service
public class AcessoUsuarioService extends GenericService<AcessoUsuario, Integer>{
	
	private AcessoUsuarioRepository  usuarioRepo;
	
	@Autowired 
	private UsuarioCriteria usuarioCriteria;
	
	private String userToken;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private HttpSession session;

	@Autowired
	private EmailService email;
	
	@Autowired
	public AcessoUsuarioService(AcessoUsuarioRepository usuarioRepo) {
		super(usuarioRepo);
		this.usuarioRepo = usuarioRepo;
	}
	
	public AcessoUsuario findByLoginAndSenha(String login, String senha) {
		AcessoUsuario usuario = usuarioRepo.findByDeLogin(login.trim());
		if(usuario != null && isPassMatch(senha, usuario)) {
			return usuario;
		}
		return null;
	}
	
	public AcessoUsuario findByLogin(String login){
		return usuarioRepo.findByDeLogin(login.trim());
	}
	
	@Transactional
	public AcessoUsuario cadastrarUsuario(AcessoUsuario usuario) {
		String senhaRandom = generatePassword();
		usuario.setSenha(encodePassword(senhaRandom));
		usuario.setStatus(StatusUsuario.ATIVO.value());
		usuario.setSenhaExpirada(true);
		usuario = usuarioRepo.save(usuario);
		email.sendPasswordEmail(usuario, senhaRandom);
		return usuario;
	}
	
	public AcessoUsuario doLogin(HttpServletRequest request, HttpServletResponse response, String login, String senha) {
		AcessoUsuario usuario = this.findByLoginAndSenha(login, senha);
		if(usuario == null) {
			return null;
		}
		makeAuthenication(request, response, usuario);
		return usuario;
	}

	public String makeAuthenication(HttpServletRequest request, HttpServletResponse response, AcessoUsuario usuario) {
		SecurityUser securityUser = new SecurityUser(usuario);
		UserService userService = new UserService();
		userService.setSession(session);
		userService.addUser(securityUser);

		TokenAuthenticationService authenticationService = new TokenAuthenticationService(userService);
		UserAuthentication userAuthentication = new UserAuthentication(securityUser);
		userToken = authenticationService.addAuthentication(response, userAuthentication);
		Authentication authentication = authenticationService.getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		return userToken;
	}
	
	/**
	 * 
	 * @param senha
	 * 
    
    (?=.*[0-9]) a digit must occur at least once
    (?=.*[a-z]) a lower case letter must occur at least once
    (?=.*[A-Z]) an upper case letter must occur at least once
    (?=.*[@#$%^&+=]) a special character must occur at least once
    (?=\\S+$) no whitespace allowed in the entire string
    .{8,} at least 8 characters

	 * @return
	 */
	public Boolean isPasswordWeak(String senha) {
		String pattern = "(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{5,20}";
	    return !senha.matches(pattern);
	}

	
	public String generatePassword(){
		return Long.toHexString(Double.doubleToLongBits(Math.random())).substring(0, 8);
	}
	
	private String encodePassword(String senha){
		return passwordEncoder.encode(senha);
	}
	
	private boolean isPassMatch(String senha, AcessoUsuario usuario) {
		return BCrypt.checkpw(senha, usuario.getSenha());
	}

	public String getUserToken() {
		return userToken;
	}
	
	@Override
	public List<AcessoUsuario> findAll() {
		Criteria criteria = usuarioCriteria.getCriteria(AcessoUsuario.class);
		criteria.setResultTransformer(Criteria.DISTINCT_ROOT_ENTITY);
		List<AcessoUsuario> usuarios = listAndCast(criteria);
		return usuarios;
	}
}