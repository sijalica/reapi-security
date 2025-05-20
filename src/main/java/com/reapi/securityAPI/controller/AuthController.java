package com.reapi.securityAPI.controller;

import com.reapi.securityAPI.request.LoginRequest;
import com.reapi.securityAPI.response.LoginResponse;
import com.reapi.securityAPI.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;


@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            String token = jwtUtil.generateToken(authentication);
            String refreshToken = jwtUtil.generateRefreshToken(request.getUsername());

            return new LoginResponse(token, refreshToken);

        } catch (AuthenticationException e) {
            throw new RuntimeException("Invalid username or password");
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !jwtUtil.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }

        String username = jwtUtil.getUsername(refreshToken);

        // optionally, fetch roles from DB or use a cache
        List<String> roles = List.of("ROLE_USER"); // or query based on username

        String newAccessToken = jwtUtil.generateToken(username, roles);

        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }
}
