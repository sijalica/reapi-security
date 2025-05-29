package com.reapi.securityAPI.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class UserDTO {
    private String username;
    private String password;
    private Set<String> roles;
}
