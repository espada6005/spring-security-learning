package com.secure.notes.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.secure.notes.model.AuditLog;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByNoteId(Long noteId);

}
