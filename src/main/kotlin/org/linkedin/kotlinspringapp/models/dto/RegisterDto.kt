package org.linkedin.kotlinspringapp.models.dto

data class RegisterDto(
    val username: String,
    val email: String,
    val password: String,
    val name: String
)