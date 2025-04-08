package org.linkedin.kotlinspringapp.repository

import org.linkedin.kotlinspringapp.models.entity.RefreshToken
import org.linkedin.kotlinspringapp.models.entity.Users
import org.springframework.data.jpa.repository.JpaRepository

interface RefreshTokenRepository: JpaRepository<RefreshToken, Long> {
    fun findByToken(token: String): RefreshToken?
    fun findByUsers(users: Users): RefreshToken?
}