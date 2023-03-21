package com.renan.helpdesk.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.renan.helpdesk.domain.Tecnico;

public interface TecnicoRepository extends JpaRepository<Tecnico, Integer> {

}
