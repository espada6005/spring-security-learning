package com.secure.notes.controller;

import java.util.List;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.secure.notes.model.Note;
import com.secure.notes.service.NoteService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/notes")
public class NoteController {

    private final NoteService noteService;

    @PostMapping
    public Note createNote(@RequestBody String content, @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        System.out.println("User DETAILS: " + username);
        return noteService.createNoteForUser(username, content);
    }
    
    @GetMapping
    public List<Note> getUserNotes(@AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return noteService.getNotesForUser(username);
    }
    
    @PutMapping("/{noteId}")
    public Note updateNote(@PathVariable Long noteId, @RequestBody String content,
            @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        return noteService.updateNoteForUser(noteId, content, username);
    }

    @DeleteMapping("/{noteId}")
    public void deleteNote(@PathVariable Long noteId, @AuthenticationPrincipal UserDetails userDetails) {
        String username = userDetails.getUsername();
        noteService.deleteNoteForUser(noteId, username);
    }

}
