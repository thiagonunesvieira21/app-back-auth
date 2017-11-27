package br.com.oauth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import br.com.util.entity.AcessoFuncionalidade;
import br.com.util.repository.AcessoFuncionalidadeRepository;

@Service
public class AcessoFuncionalidadeService extends GenericService<AcessoFuncionalidade, Integer>{

	@Autowired
	public AcessoFuncionalidadeService(AcessoFuncionalidadeRepository repo) {
		super(repo);
	}
}
