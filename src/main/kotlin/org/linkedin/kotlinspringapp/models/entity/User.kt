package org.linkedin.kotlinspringapp.models.entity

import jakarta.persistence.*
import org.springframework.data.relational.core.mapping.Table

@Table(name = "users")
@Entity
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    val id: String,

    val name: String,

    @Column(name = "email", nullable = false, unique = true)
    val email: String,

    @Column(name = "username", nullable = false, unique = true)
    val username: String,

    val password: String,
    val roles: String,

    @OneToMany(cascade = [CascadeType.ALL], fetch = FetchType.LAZY, mappedBy = "users")
    val refreshTokens: List<RefreshToken>
)
