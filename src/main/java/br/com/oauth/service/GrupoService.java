package br.com.oauth.service;

import static br.com.util.utilities.MyHibernateUtils.listAndCast;

import java.util.List;

import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.hibernate.Criteria;
import org.hibernate.criterion.Restrictions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.oauth.criteria.UsuarioCriteria;
import br.com.util.entity.AcessoGrupo;
import br.com.util.repository.AcessoGrupoRepository;
import br.com.util.service.GenericService;

@Service
public class GrupoService extends GenericService<AcessoGrupo, Integer>{
	
	@Autowired 
	private UsuarioCriteria usuarioCriteria;
	
	@Autowired
	private EntityManager em;
	
	@Autowired
	public GrupoService(AcessoGrupoRepository repo) {
		super(repo);
	}
	
	public List<AcessoGrupo> findAll() {
		Criteria criteria = grupoCriteria();
		List<AcessoGrupo> grupos = listAndCast(criteria);
		return grupos;
	}
	
	public AcessoGrupo findByNuGrupoPai(Integer idGrupoPai, Integer idGrupo) {
		Query query = em.createQuery("select g from AcessoGrupo g where g.idGrupoPai = :idGrupoPai and g.id = :id");
		query.setParameter("idGrupoPai", idGrupoPai);
		query.setParameter("id", idGrupo);
		return (AcessoGrupo) query.getSingleResult();
	}
	
	public AcessoGrupo findById(Integer id) {
		Criteria criteria = grupoCriteria();
		criteria.add(Restrictions.eq("id", id));
		return (AcessoGrupo) criteria.uniqueResult();
	}
	
	@SuppressWarnings("unchecked")
	public List<AcessoGrupo> findByUsuarioId(Integer id) {
		Query q = em.createNativeQuery("WITH RECURSIVE q AS ( "
				+ "select distinct grupo.nu_grupo, grupo.* from suporte.acesso_grupo grupo where grupo.nu_grupo=grupo.nu_grupo_pai"
				+ "    UNION"
				+ "    select distinct grupo.nu_grupo, grupo.* from suporte.acesso_grupo grupo inner join "
				+ "suporte.acesso_grupo_usuario gusu on gusu.nu_usuario = ? and gusu.nu_grupo = grupo.nu_grupo) "
				+ "SELECT * FROM q;", AcessoGrupo.class);
		q.setParameter(1, id);
		List<AcessoGrupo> result = q.getResultList();
		return result;
	}
	
	private Criteria grupoCriteria() {
		return usuarioCriteria.getCriteria(AcessoGrupo.class);
	}
	
}