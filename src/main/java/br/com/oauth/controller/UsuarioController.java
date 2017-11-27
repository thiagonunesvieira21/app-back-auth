package br.com.oauth.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import br.com.oauth.service.AcessoUsuarioService;
import br.com.oauth.service.EmailService;
import br.com.util.controller.UtilController;
import br.com.util.entity.AcessoHistoricoSenha;
import br.com.util.entity.AcessoUsuario;
import br.com.util.exceptions.GenericServiceException;
import br.com.util.exceptions.InvalidRequestException;
import br.com.util.json.bean.CadastrarUsuario;
import br.com.util.json.bean.TrocarSenha;
import br.com.util.json.bean.UpdateUsuario;
import br.com.util.security.SecurityUser;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;

@RestController
@RequestMapping(value = "/user")
public class UsuarioController extends UtilController{
	
	private static final Integer QUANTIDADE_HISTORICO_SENHA = 5;

	@Autowired
	private AcessoUsuarioService service;
	
	@Autowired
	private HttpSession session;
	
	@Autowired
	private EmailService mail;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@ApiOperation(value="Serviço responsável por Alterar os Dados do Usuário")
	@ApiImplicitParam(paramType="header", name=AUTH_HEADER_NAME, value="API Key")
	@RequestMapping(value="/{id}", method=RequestMethod.PUT, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@Secured({"ROLE_MANTER_USUARIO"})
	public ResponseEntity<?> update(@RequestBody UpdateUsuario model, @PathVariable Integer id, BindingResult result) {
		
		if(result.hasErrors()) {
			throw new InvalidRequestException("Erro na validação do formulário do usuário", result);
		}
		
		AcessoUsuario userUpdate =  service.findById(id);
		
		if(userUpdate == null){
			throw new AccessDeniedException("O Usuário solicitado não existe na base");
		}		
		//RN altera a dt_hr_status somente se o status mudar
		if(!model.getStatus().equals(userUpdate.getStatus())){
			userUpdate.setDtHrStatus(new Date());
		}
		BeanUtils.copyProperties(model, userUpdate, getNullPropertyNames(model));
		checksUsuario(userUpdate);
		service.save(userUpdate);
		
		HashMap<String, String> map = new HashMap<>();
		map.put("msg", "Dados do Usuário "+ userUpdate.getNome() + " Alterados com sucesso");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	
	@ApiOperation(value = "Serviço responsável por cadastrar o usuário")
	@ApiResponses(value = { @ApiResponse(code = 400, message = "JSON inválido")})
	@RequestMapping(method = RequestMethod.POST, consumes=MediaType.APPLICATION_JSON_UTF8_VALUE, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@Secured({"ROLE_MANTER_USUARIO"})
	public ResponseEntity<?> create(@RequestBody @Valid CadastrarUsuario model, BindingResult result){

		if (result.hasErrors()) {
			throw new InvalidRequestException("Validação do cadastro de usuários", result);
		}
		if(service.findByLogin(model.getDeLogin()) != null){
			throw new InvalidRequestException("Já existe o Login cadastrado", result);
		}		
		
		AcessoUsuario newUser = new AcessoUsuario();
		BeanUtils.copyProperties(model, newUser, getNullPropertyNames(model));		
		checksUsuario(newUser);
		try {
			service.cadastrarUsuario(newUser);
		} catch (Exception e) {
			throw new GenericServiceException("Não foi possível Cadastrar Usuário",e);
		}
		
		HashMap<String, Object> map = new HashMap<>();
		map.put("msg", "Usuario " + newUser.getNome() + " cadastrado com sucesso");
		map.put("id", newUser.getIdUsuario());
		return new ResponseEntity<>(map, HttpStatus.CREATED);
	}

	@RequestMapping(value = "/trocar-senha", method = RequestMethod.POST, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ApiOperation(value = "Serviço responsável por trocar a senha do usuário")
	public ResponseEntity<?> trocarSenha(@RequestBody TrocarSenha trocarSenha, HttpServletRequest request,
			HttpServletResponse response) {

		AcessoUsuario usuario = service.findByLoginAndSenha(trocarSenha.getLogin(), trocarSenha.getSenha());

		HashMap<String, String> map = new HashMap<>();
		if (usuario == null) {
			throw new AccessDeniedException("Login ou senha incorretos");
		}

		if (service.isPasswordWeak(trocarSenha.getNovaSenha())) {
			throw new AccessDeniedException("Senha fraca");
		}

		List<AcessoHistoricoSenha> senhas = new ArrayList<AcessoHistoricoSenha>();
		senhas.addAll(usuario.getAcessoHistoricoSenhas());
		
		AcessoHistoricoSenha senha = new AcessoHistoricoSenha();
		senha.setDataHoraTroca(LocalDateTime.now());
		for(AcessoHistoricoSenha a : senhas){
			if(isPassMatch(trocarSenha.getNovaSenha(), a.getSenhaAnterior())){
				throw new AccessDeniedException("Você não pode usar uma senha que já utilizou recentemente.");
			}
			if(senhas.size() == QUANTIDADE_HISTORICO_SENHA && a.getDataHoraTroca().isBefore(senha.getDataHoraTroca())){
					senha = a;
			}
		}
		senha.setAcessoUsuario(usuario);
		senhas.remove(senha);
		senha.setDataHoraTroca(LocalDateTime.now());
		senha.setSenhaAnterior(passwordEncoder.encode(trocarSenha.getSenha()));
		senhas.add(senha);
		
		usuario.setSenhaExpirada(false);
		usuario.setSenha(passwordEncoder.encode(trocarSenha.getNovaSenha()));
		usuario.setDtHrUltimaTrocaSenha(new Date());
		usuario.getAcessoHistoricoSenhas().addAll(senhas);
		
		usuario = service.save(usuario);
		
		service.makeAuthenication(request, response, usuario);
		map.put("msg", "Senha alterada com sucesso");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	
	@ApiOperation(value="Serviço responsável pela solicitação realizada pelo Usuário de uma nova senha provisória para a posterior alteração por motivo de esquecimento")
	@RequestMapping(value="/esqueci-senha/{login}/{cpf}", method=RequestMethod.GET)
//	@Secured({"ROLE_MANTER_USUARIO"})
	public ResponseEntity<?> esqueciSenha(@PathVariable String login,@PathVariable  String cpf){
		
		AcessoUsuario userChangePw =  service.findByLogin(login); 
		
		if(userChangePw == null || !userChangePw.getCpf().equals(cpf)){
			throw new AccessDeniedException("O Usuário solicitado não existe na base");
		}
		
		userChangePw.setSenhaExpirada(true);
		service.save(userChangePw);
		
		try {
			
			mail.sendPasswordEmail(userChangePw,service.generatePassword());
		} catch (Exception e) {
			throw new GenericServiceException("Não foi possível enviar Senha por E-mail para o Usuário",e);
		}
		
		
		HashMap<String, String> map = new HashMap<>();
		map.put("msg", "Solicitação de Alteração de Senha do Usuário "+ userChangePw.getNome() + " realizada com sucesso");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	
	@ApiOperation(value="Serviço responsável pela solicitação de Alteração de Senha solicitada pelos Gestores")
	@ApiImplicitParam(paramType="header", name=AUTH_HEADER_NAME, value="API Key")
	@RequestMapping(value="/troca-senha-gestor/{id}", method=RequestMethod.GET)
	public ResponseEntity<?> update(@PathVariable Integer id) {
		
		AcessoUsuario userChangePw =  service.findById(id);
		SecurityUser user = getAthenticatedUser(session);
		
		if(userChangePw == null){
			throw new AccessDeniedException("O Usuário solicitado não existe na base");
		}
		
		userChangePw.setSenhaExpirada(true);
		service.save(userChangePw);
		
		try {
			
			mail.sendPasswordEmail(userChangePw,service.generatePassword());
		} catch (Exception e) {
			throw new GenericServiceException("Não foi possível enviar Senha por E-mail para o Usuário",e);
		}		
		
		HashMap<String, String> map = new HashMap<>();
		map.put("msg", "Solicitação de Alteração de Senha do Usuário "+ userChangePw.getNome() + " realizada com sucesso");
		return new ResponseEntity<>(map, HttpStatus.OK);
	}
	
	@ApiOperation(value = "Serviço responsável por buscar os usuários")
	@RequestMapping(method = RequestMethod.GET, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ApiImplicitParam(paramType="header", name=AUTH_HEADER_NAME, value="API Key")
//	@Secured({"ROLE_MANTER_USUARIO"})
	/*TODO CORRIGIR A DUPLICAÇÃO DO ACESSOGRUPOS NESTE SERVIÇO*/
	public List<AcessoUsuario> get() {
		return this.service.findAll();
	}
	
	@ApiOperation(value = "Serviço responsável por buscar as permissões do usuário logado", response=GrantedAuthority.class, responseContainer="List")
	@RequestMapping(value="/permissions", method = RequestMethod.GET, produces=MediaType.APPLICATION_JSON_UTF8_VALUE)
	@ApiImplicitParam(paramType="header", name=AUTH_HEADER_NAME, value="API Key")
	public Collection<? extends GrantedAuthority> getPermission() {
		SecurityUser user = getAthenticatedUser(session);
		Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
		return authorities;
	}
	
	private void checksUsuario(AcessoUsuario userNewOrUpdate){
		SecurityUser user = getAthenticatedUser(session);
	}
	
	private boolean isPassMatch(String s1, String s2) {
		return BCrypt.checkpw(s1,s2);
	}
	
}
