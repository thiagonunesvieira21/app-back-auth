package br.com.oauth.service;

import java.io.File;

import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.mail.javamail.MimeMessagePreparator;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import br.com.util.entity.AcessoUsuario;
import br.com.util.exceptions.GenericServiceException;

@Service
public class EmailService {
	
	@Autowired
	private JavaMailSender sender;
	
	@Autowired
	private HttpServletRequest request;
	
	@Async
	public void sendPasswordEmail(AcessoUsuario usuario, String senha) {
		
		StringBuilder url = new StringBuilder();
//		url.append(request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath());
		url.append("/api/usuario/trocar-senha");
				
		
		String corpoEmail = "Olá " + usuario.getNome() + "! Bem vindo ao sistema PPP. \n" +
				 	"Logue com o seu nome de usuário "+ usuario.getDeLogin() +
					"\n Sua senha provisória é "+ senha + 
					"\n Acesse "+ url.toString() +" e troque pela senha desejada!";

		System.out.println(corpoEmail);

//		MimeMessage message = sender.createMimeMessage();
//		MimeMessageHelper helper = new MimeMessageHelper(message);
//		try {
//			helper.setTo(usuario.getEmail());
//			helper.setText(corpoEmail);
//			helper.setSubject("Acesso ao sistema PPP");
//		} catch (MessagingException e) {
//			throw new GenericServiceException("Não foi possível enviar senha por e-mail", e);
//		}
//
//		sender.send(message);

	}
	
	@Async
	public void sendBoletoEmail(String emailDestino, String nomeArquivo,String diretorioTemp,String nomeDestinatario){
		
		String corpoEmail = "Olá " + nomeDestinatario + "! Segue anexo o boleto solicitado. \n";

		try {                         
			String nomeArqCompleto = diretorioTemp+nomeArquivo;
				sender.send(new MimeMessagePreparator() {
					 
		            @Override
		            public void prepare(MimeMessage mimeMessage) throws Exception {
		                MimeMessageHelper messageHelper = new MimeMessageHelper(
		                        mimeMessage, true, "UTF-8");
		                messageHelper.setTo(emailDestino);
		                messageHelper.setSubject("Boleto "+nomeArquivo);
		                messageHelper.setText(corpoEmail);
						messageHelper.addAttachment(nomeArquivo,new File(nomeArqCompleto));
		                }
		                 
		            });
					
			} catch (Exception e) {                                                                             
				throw new GenericServiceException("Não foi possível enviar o boleto por email", e);             
			}                                                                                                   
		
	}

}