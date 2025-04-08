package org.linkedin.kotlinspringapp.service.impl

import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.models.dto.AuthResponseDto
import org.linkedin.kotlinspringapp.models.dto.RegisterDto
import org.linkedin.kotlinspringapp.models.entity.RefreshToken
import org.linkedin.kotlinspringapp.repository.RefreshTokenRepository
import org.linkedin.kotlinspringapp.repository.UsersRepository
import org.linkedin.kotlinspringapp.security.jwt.JwtTokenGenerator
import org.linkedin.kotlinspringapp.service.AuthenticationService
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import java.time.Instant
import java.time.temporal.ChronoUnit

@Service
class AuthenticationServiceImpl(
    private val refreshTokenRepository: RefreshTokenRepository,
    private val jwtTokenGenerator: JwtTokenGenerator,
    private val usersRepository: UsersRepository,
) : AuthenticationService {
    override fun register(registerDto: RegisterDto): AuthResponseDto {
        val user = usersRepository.findByEmail(registerDto.email)
            ?: throw UsernameNotFoundException("User ${registerDto.email} not found")
        val authentication = jwtTokenGenerator.createAuthenticationObject(user)

        val accessToken = jwtTokenGenerator.generateAccessToken(authentication)
        val refreshToken = jwtTokenGenerator.generateRefreshToken(authentication)
        refreshTokenRepository.save(
            RefreshToken(
                token = refreshToken,
                users = user,
                expiresIn = Instant.now().plus(25, ChronoUnit.DAYS),
                revoked = false
            )
        )
        return AuthResponseDto(
            accessToken = accessToken,
            accessTokenExpiresIn = 5 * 60,
            refreshToken = refreshToken,
            tokenType = "Bearer",
            email = registerDto.email,
        )
    }

    override fun authenticate(authentication: Authentication, response: HttpServletResponse): AuthResponseDto {
        val user = usersRepository.findByEmail(authentication.name)
            ?: throw UsernameNotFoundException("User ${authentication.name} not found")
        val accessToken = jwtTokenGenerator.generateAccessToken(authentication)
        val refreshToken = jwtTokenGenerator.generateRefreshToken(authentication)

        refreshTokenRepository.save(
            RefreshToken(
                token = refreshToken,
                users = user,
                expiresIn = Instant.now().plus(25, ChronoUnit.DAYS),
                revoked = false
            )
        )
        return AuthResponseDto(
            accessToken = accessToken,
            accessTokenExpiresIn = 5 * 60,
            refreshToken = refreshToken,
            tokenType = "Bearer",
            email = authentication.name,
        )
    }

    override fun getAccessTokenUsingRefreshToken(refreshToken: String?): AuthResponseDto {
        if (refreshToken == null || !refreshToken.startsWith("Bearer"))
            throw UsernameNotFoundException("Header is null")
        val refreshToken = refreshToken!!.substring(7)

        val refreshTokenEntity = refreshTokenRepository.findByToken(refreshToken)
            ?.also { it.revoked.not() }
            ?: throw UsernameNotFoundException("Refresh token not found")

        val user = refreshTokenEntity.users
        refreshTokenEntity.revoked = true
        refreshTokenRepository.save(refreshTokenEntity)

        val auth = jwtTokenGenerator.createAuthenticationObject(user)
        val accessToken = jwtTokenGenerator.generateAccessToken(auth)
        return AuthResponseDto(
            accessToken = accessToken,
            accessTokenExpiresIn = 5 * 60,
            refreshToken = refreshToken,
            tokenType = "Bearer",
            email = auth.name,
        )
    }
}