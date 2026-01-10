package com.secure.notes.dto;

import java.time.LocalDate;
import java.time.LocalDateTime;

import com.secure.notes.model.Role;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDTO {

    private Long userId;

    private String username;

    private String email;

    private boolean accountNonLocked;

    private boolean accountNonExpired;
    
    private boolean credentialsNonExpired;
    
    private boolean enabled;
    
    private LocalDate credentialsExpiryDate;
    
    private LocalDate accountExpiryDate;
    
    private String twoFactorSecret;
    
    private boolean isTwoFactorEnabled;
    
    private String signUpMethod;
    
    private Role role;
    
    private LocalDateTime createdDate;
    
    private LocalDateTime updatedDate;

}
