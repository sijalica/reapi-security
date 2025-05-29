package com.reapi.securityAPI.service;

import com.reapi.securityAPI.request.LoginRequest;
import com.reapi.securityAPI.response.LoginResponse;

public interface AuthService {
    LoginResponse generateToken(LoginRequest request);
}
