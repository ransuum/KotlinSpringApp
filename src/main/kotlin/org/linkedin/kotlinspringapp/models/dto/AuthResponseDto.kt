package org.linkedin.kotlinspringapp.models.dto

data class AuthResponseDto(
    val accessToken: String,
    val tokenType: String,
    val accessTokenExpiresIn: Int,
    val refreshToken: String,
    val email: String
)
