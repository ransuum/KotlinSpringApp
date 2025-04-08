package org.linkedin.kotlinspringapp.models.entity

import jakarta.persistence.*
import org.springframework.data.relational.core.mapping.Table
import java.time.Instant

@Table(name = "users")
@Entity
data class RefreshToken(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    val token: String,
    val expiresIn: Instant,
    val createdAt: Instant = Instant.now(),
    var revoked: Boolean,

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    val users: User
)
