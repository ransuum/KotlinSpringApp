package org.linkedin.kotlinspringapp.security

import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.repository.RefreshTokenRepository
import org.linkedin.kotlinspringapp.security.jwt.JwtAccessTokenFilter
import org.linkedin.kotlinspringapp.security.jwt.JwtRefreshTokenFilter
import org.linkedin.kotlinspringapp.security.jwt.JwtTokenUtils
import org.linkedin.kotlinspringapp.security.rsa.RSAKeyRecord
import org.linkedin.kotlinspringapp.security.userconfiguration.UserManagerConfig
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.OrRequestMatcher
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class Config(
    private val userManagerConfig: UserManagerConfig,
    private val rsaKeyRecord: RSAKeyRecord,
    private val jwtTokenUtils: JwtTokenUtils,
    private val refreshTokenRepository: RefreshTokenRepository
) {

    @Order(1)
    @Bean
    fun signInSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(AntPathRequestMatcher("/sign-in/**"))
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .userDetailsService(userManagerConfig)
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .exceptionHandling { ex ->
                ex.authenticationEntryPoint { _, response, authException ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.message)
                }
            }
            .httpBasic(withDefaults())
            .build()

    @Order(2)
    @Bean
    fun apiSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(AntPathRequestMatcher("/api/**"))
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .oauth2ResourceServer { it.jwt(withDefaults()) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { ex ->
                ex.authenticationEntryPoint(BearerTokenAuthenticationEntryPoint())
                ex.accessDeniedHandler(BearerTokenAccessDeniedHandler())
            }
            .httpBasic(withDefaults())
            .build()

    @Order(3)
    @Bean
    fun refreshTokenSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(AntPathRequestMatcher("/refresh-token/**"))
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .oauth2ResourceServer { it.jwt(withDefaults()) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(JwtRefreshTokenFilter(rsaKeyRecord, jwtTokenUtils, refreshTokenRepository), UsernamePasswordAuthenticationFilter::class.java)
            .exceptionHandling { ex ->
                ex.authenticationEntryPoint(BearerTokenAuthenticationEntryPoint())
                ex.accessDeniedHandler(BearerTokenAccessDeniedHandler())
            }
            .httpBasic(withDefaults())
            .build()

    @Order(4)
    @Bean
    fun logoutSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(AntPathRequestMatcher("/logout/**"))
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .oauth2ResourceServer { it.jwt(withDefaults()) }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .addFilterBefore(JwtAccessTokenFilter(rsaKeyRecord, jwtTokenUtils), UsernamePasswordAuthenticationFilter::class.java)
            .logout { logout ->
                logout
                    .logoutUrl("/logout")
                    .addLogoutHandler(logoutHandlerService)
                    .logoutSuccessHandler { _, _, _ -> SecurityContextHolder.clearContext() }
            }
            .exceptionHandling { ex ->
                ex.authenticationEntryPoint(BearerTokenAuthenticationEntryPoint())
                ex.accessDeniedHandler(BearerTokenAccessDeniedHandler())
            }
            .build()

    @Order(5)
    @Bean
    fun registerSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(OrRequestMatcher(
                AntPathRequestMatcher("/sign-up/**"),
                AntPathRequestMatcher("/check-username"),
                AntPathRequestMatcher("/check-email"),
                AntPathRequestMatcher("/public/**")
            ))
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().permitAll() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .build()

    @Order(6)
    @Bean
    fun swaggerSecurityFilterChain(httpSecurity: HttpSecurity): SecurityFilterChain =
        httpSecurity
            .securityMatcher(
                OrRequestMatcher(
                    AntPathRequestMatcher("/swagger-ui/**"),
                    AntPathRequestMatcher("/v3/api-docs"),
                    AntPathRequestMatcher("/v3/api-docs/**"),
                    AntPathRequestMatcher("/swagger-ui.html")
                )
            )
            .csrf { it.disable() }
            .cors { it.configurationSource(corsConfigurationSource()) }
            .authorizeHttpRequests { it.anyRequest().permitAll() }
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .build()


    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun jwtDecoder() = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey).build()!!

    @Bean
    fun corsConfigurationSource(): CorsConfigurationSource {
        val configuration = CorsConfiguration().apply {
            addAllowedOrigin("http://localhost:8000")
            allowedMethods = listOf(
                "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
            )
            allowedHeaders = listOf(
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
            )
            exposedHeaders = listOf(
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials",
                "Authorization"
            )
            allowCredentials = true
            maxAge = 3600L
        }

        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/**", configuration)
        }
    }
}