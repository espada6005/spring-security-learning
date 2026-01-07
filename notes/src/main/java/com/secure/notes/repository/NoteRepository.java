package com.secure.notes.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.secure.notes.model.Note;

public interface NoteRepository extends JpaRepository<Note, Long> {

    List<Note> findByOwnerUsername(String ownerUsername);

}