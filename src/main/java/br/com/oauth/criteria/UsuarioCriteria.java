package br.com.oauth.criteria;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpSession;

import org.hibernate.Criteria;
import org.hibernate.Session;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class UsuarioCriteria {
	
	@PersistenceContext
	EntityManager em;
	
	@Autowired HttpSession session;
	
	public Criteria getCriteria(Class<? extends Object> clazz){
		return getSession().createCriteria(clazz);
	}

	public Session getSession(){
		return em.unwrap(Session.class);
	}

}
