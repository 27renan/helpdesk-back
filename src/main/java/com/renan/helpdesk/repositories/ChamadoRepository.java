package com.renan.helpdesk.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.renan.helpdesk.domain.Chamado;

public interface ChamadoRepository extends JpaRepository<Chamado, Integer> {

}
