package org.linkedin.kotlinspringapp.models.entity

import jakarta.persistence.*
import java.time.Instant

@Entity
@Table(name = "refresh_token")
data class RefreshToken(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    var id: Long? = null,

    @Column(nullable = false, updatable = false, length = 1000)
    var token: String,
    var expiresIn: Instant,
    var createdAt: Instant = Instant.now(),
    var revoked: Boolean,

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    var users: Users
)
