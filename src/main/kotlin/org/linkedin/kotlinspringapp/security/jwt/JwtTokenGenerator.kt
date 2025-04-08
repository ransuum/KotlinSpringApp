package org.linkedin.kotlinspringapp.security.jwt

import org.linkedin.kotlinspringapp.models.entity.RefreshToken
import org.linkedin.kotlinspringapp.models.entity.User
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.stereotype.Service
import java.time.Instant
import java.time.temporal.ChronoUnit

@Service
class JwtTokenGenerator(private val jwtEncoder: JwtEncoder) {
    val createRefreshToken: (User, Authentication) -> RefreshToken = { user, authentication ->
        RefreshToken(
            token = generateRefreshToken(authentication),
            expiresIn = Instant.now().plus(25, ChronoUnit.DAYS),
            users = user,
            revoked = false
        )
    }

    private val getRoleOfUser: (Authentication) -> String = { authentication ->
        authentication.authorities
            .map { it.authority }
            .toList()
            .joinToString(separator = " ")
    }

    private val getPermissionsFromRoles: (String) -> String = { roles ->
        roles.split(",")
            .map { it.trim() }
            .toList()
            .joinToString(separator = " ")
    }

    fun createAuthenticationObject(user: User): Authentication {
        val authorities: List<GrantedAuthority> = user.roles
            .split(",")
            .map { role -> SimpleGrantedAuthority(role) }
            .toList()

        return UsernamePasswordAuthenticationToken(user.email, user.password, authorities)
    }

    fun generateRefreshToken(authentication: Authentication): String {
        val claims = JwtClaimsSet.builder()
            .issuer("kotlin-project")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plus(25, ChronoUnit.DAYS))
            .subject(authentication.getName())
            .claim("scope", "REFRESH_TOKEN")
            .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).tokenValue
    }

    fun generateAccessToken(authentication: Authentication): String {
        val roles = getRoleOfUser(authentication)

        val permissions = getPermissionsFromRoles(roles)

        val claims = JwtClaimsSet.builder()
            .issuer("kotlin-project")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plus(30, ChronoUnit.MINUTES))
            .subject(authentication.name)
            .claim("scope", permissions)
            .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).tokenValue
    }


}