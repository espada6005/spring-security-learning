package com.secure.notes.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.secure.notes.model.PasswordResetToken;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    Optional<PasswordResetToken> findByToken(String token);
}
