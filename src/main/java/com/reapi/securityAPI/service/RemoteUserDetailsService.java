package com.reapi.securityAPI.service;

import com.reapi.securityAPI.model.UserDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class RemoteUserDetailsService implements UserDetailsService {

    private final RestTemplate restTemplate;

    @Value("${registration.service.url}")
    private String registrationServiceUrl;

    public RemoteUserDetailsService(RestTemplateBuilder builder) {
        this.restTemplate = builder.build();
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            ResponseEntity<UserDTO> response = restTemplate.getForEntity(
                    registrationServiceUrl + "/v1/load/" + username,
                    UserDTO.class
            );

            UserDTO user = response.getBody();
            if (user == null) throw new UsernameNotFoundException("User not found");

            List<GrantedAuthority> authorities = user.getRoles().stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            return new org.springframework.security.core.userdetails.User(
                    user.getUsername(),
                    user.getPassword(),
                    authorities
            );
        } catch (HttpClientErrorException e) {
            throw new UsernameNotFoundException("User not found", e);
        }
    }
}