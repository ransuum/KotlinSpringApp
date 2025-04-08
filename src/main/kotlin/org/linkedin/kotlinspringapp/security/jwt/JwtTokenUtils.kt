package org.linkedin.kotlinspringapp.security.jwt

import org.linkedin.kotlinspringapp.repository.UsersRepository
import org.linkedin.kotlinspringapp.security.userconfiguration.UserConfig
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.stereotype.Component
import java.time.Instant

@Component
class JwtTokenUtils(private val usersRepository: UsersRepository) {

    fun getUsername(jwtToken: Jwt): String? = jwtToken.subject

    fun isTokenValid(jwtToken: Jwt, userDetails: UserDetails): Boolean {
        val username = getUsername(jwtToken)
        val isTokenExpired = getIfTokenIsExpired(jwtToken)
        val isTokenUserSameAsDatabase = username == userDetails.username
        return username != null && isTokenExpired != null && isTokenUserSameAsDatabase
    }

    private fun getIfTokenIsExpired(jwtToken: Jwt): Boolean? = jwtToken.expiresAt?.isBefore(Instant.now())

    fun userDetails(username: String): UserDetails = usersRepository.findByEmail(username)
        ?.let { UserConfig(it) }
        ?: throw UsernameNotFoundException("User $username not found")
}