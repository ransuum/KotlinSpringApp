package org.linkedin.kotlinspringapp.models.entity

import jakarta.persistence.*

@Entity
@Table(name = "users")
data class Users(
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(nullable = false, updatable = false)
    var id: String? = null,

    var name: String?,

    @Column(name = "email", nullable = false, unique = true)
    var email: String?,

    @Column(name = "username", nullable = false, unique = true)
    var username: String?,

    @Column(name = "password", nullable = false)
    var password: String?,
    var roles: String,

    @OneToMany(cascade = [CascadeType.ALL], fetch = FetchType.LAZY, mappedBy = "users")
    val refreshTokens: MutableList<RefreshToken> = mutableListOf()
)
