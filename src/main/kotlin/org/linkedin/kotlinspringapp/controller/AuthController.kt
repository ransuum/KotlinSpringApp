package org.linkedin.kotlinspringapp.controller

import jakarta.servlet.http.HttpServletResponse
import org.linkedin.kotlinspringapp.models.dto.AuthResponseDto
import org.linkedin.kotlinspringapp.models.dto.RegisterDto
import org.linkedin.kotlinspringapp.service.AuthenticationService
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.security.core.Authentication
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@RestController
class AuthController(
    private val authenticationService: AuthenticationService
) {
    @PostMapping("/sign-in")
    fun signIn(authentication: Authentication, response: HttpServletResponse): ResponseEntity<AuthResponseDto> =
        ResponseEntity(authenticationService.authenticate(authentication, response), HttpStatus.OK)

    @PostMapping("/sign-up")
    fun signup(@RequestBody registerDto: RegisterDto): ResponseEntity<AuthResponseDto> =
        ResponseEntity(authenticationService.register(registerDto), HttpStatus.CREATED)

}