package org.linkedin.kotlinspringapp.security.jwt

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.security.rsa.RSAKeyRecord
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidationException
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.web.filter.OncePerRequestFilter

class JwtAccessTokenFilter(private val rsaKeyRecord: RSAKeyRecord,
                           private val jwtTokenUtils: JwtTokenUtils
) : OncePerRequestFilter() {
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        try {
            val authHeader: String? = request.getHeader(HttpHeaders.AUTHORIZATION)

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response)
                return
            }

            val jwtDecoder: JwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey).build()
            val token = authHeader.substring(7)
            val jwt = jwtDecoder.decode(token)!!
            val username = jwtTokenUtils.getUsername(jwt)

            if (!username.isNullOrEmpty() && SecurityContextHolder.getContext().authentication == null) {
                val userDetails = jwtTokenUtils.userDetails(username)
                if (jwtTokenUtils.isTokenValid(jwt, userDetails)) {
                    val securityContext = SecurityContextHolder.createEmptyContext()

                    val createdToken = UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.authorities
                    )

                    createdToken.details = WebAuthenticationDetailsSource().buildDetails(request)
                    securityContext.authentication = createdToken
                    SecurityContextHolder.setContext(securityContext)
                }
            }

            filterChain.doFilter(request, response)
        } catch (jwtValidationException: JwtValidationException) {
            response.sendError(HttpStatus.UNAUTHORIZED.value(), "Invalid refresh token")
            return
        }

        filterChain.doFilter(request, response);
    }
}