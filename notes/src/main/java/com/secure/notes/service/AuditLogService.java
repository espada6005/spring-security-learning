package com.secure.notes.service;

import java.util.List;

import com.secure.notes.model.AuditLog;
import com.secure.notes.model.Note;

public interface AuditLogService {

    void logNoteCreation(String username, Note note);

    void logNoteUpdate(String username, Note note);

    void logNoteDeletion(String username, Long noteId);

    List<AuditLog> getAllAuditLogs();

    List<AuditLog> getAuditLogsByNoteId(Long noteId);

}
