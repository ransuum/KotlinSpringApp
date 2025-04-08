package org.linkedin.kotlinspringapp.security.jwt

import org.linkedin.kotlinspringapp.models.Roles
import org.linkedin.kotlinspringapp.models.entity.RefreshToken
import org.linkedin.kotlinspringapp.models.entity.Users
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
    val createRefreshToken: (Users, Authentication) -> RefreshToken = { user, authentication ->
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
        val rolesList = roles.split(",").map { it.trim() }
        Roles.getPermissionsForRoles(rolesList).joinToString(" ")
    }

    fun createAuthenticationObject(users: Users): Authentication {
        val authorities: List<GrantedAuthority> = users.roles
            .split(",")
            .map { role -> SimpleGrantedAuthority(role) }
            .toList()

        return UsernamePasswordAuthenticationToken(users.email, users.password, authorities)
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