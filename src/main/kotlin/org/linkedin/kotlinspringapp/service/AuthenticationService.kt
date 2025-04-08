package org.linkedin.kotlinspringapp.service

import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.models.dto.AuthResponseDto
import org.linkedin.kotlinspringapp.models.dto.RegisterDto
import org.springframework.security.core.Authentication

interface AuthenticationService {
    fun register(registerDto: RegisterDto): AuthResponseDto
    fun authenticate(authentication: Authentication, response: HttpServletResponse): AuthResponseDto
    fun  getAccessTokenUsingRefreshToken(refreshToken: String?): AuthResponseDto
}