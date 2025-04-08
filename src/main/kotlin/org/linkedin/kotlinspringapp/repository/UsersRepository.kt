package org.linkedin.kotlinspringapp.repository

import org.linkedin.kotlinspringapp.models.entity.Users
import org.springframework.data.jpa.repository.JpaRepository

interface UsersRepository : JpaRepository<Users, String>{
    fun findByEmail(email: String): Users?
}