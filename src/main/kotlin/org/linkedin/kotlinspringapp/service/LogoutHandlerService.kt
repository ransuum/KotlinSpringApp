package org.linkedin.kotlinspringapp.service

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.repository.RefreshTokenRepository
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.stereotype.Service

@Service
class LogoutHandlerService(private val refreshTokenRepository: RefreshTokenRepository): LogoutHandler {
    override fun logout(request: HttpServletRequest?, response: HttpServletResponse?, authentication: Authentication?) {
        val authHeader = request?.getHeader("Authorization")

        if (authHeader != null && authHeader.startsWith("Bearer ")) return;

        val refreshToken = authHeader?.substring(7)

        val storedRefreshToken = refreshTokenRepository.findByToken(refreshToken!!)
            .also { refreshToken ->
                refreshToken?.revoked = true
                refreshTokenRepository.save(refreshToken!!)
             }

    }
}