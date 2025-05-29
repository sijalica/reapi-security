package com.reapi.securityAPI.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.reapi.securityAPI.request.LoginRequest;
import com.reapi.securityAPI.response.LoginResponse;
import com.reapi.securityAPI.service.AuthService;
import com.reapi.securityAPI.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.BDDMockito.given;
import static org.mockito.ArgumentMatchers.any;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = { AuthController.class })
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {
    @Autowired
    MockMvc mvc;

    @MockitoBean
    AuthService authService;

    @MockitoBean
    JwtUtil jwtUtil;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @Autowired
    ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
    }

    @Test
    void login() throws Exception {
        LoginRequest loginRequest = getLoginRequest();

        LoginResponse loginResponse = getLoginResponse();

        given(authenticationManager.authenticate(any()))
                .willReturn(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword(), List.of(new SimpleGrantedAuthority("ROLE_USER"))));

        given(authService.generateToken(any(LoginRequest.class))).willReturn(loginResponse);

        mvc.perform(post("/auth/login")
                        .with(csrf())
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk());
    }

    private static LoginResponse getLoginResponse() {
        return LoginResponse.builder()
                .token("token")
                .refreshToken("refreshToken")
                .build();
    }

    private static LoginRequest getLoginRequest() {
        return LoginRequest.builder()
                .username("test")
                .password("test")
                .build();
    }
}