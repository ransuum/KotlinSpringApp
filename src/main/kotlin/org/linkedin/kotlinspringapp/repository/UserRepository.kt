package org.linkedin.kotlinspringapp.repository

import org.linkedin.kotlinspringapp.models.entity.User
import org.springframework.data.jpa.repository.JpaRepository

interface UserRepository : JpaRepository<User, String>{
    fun findByEmail(email: String): User?
}