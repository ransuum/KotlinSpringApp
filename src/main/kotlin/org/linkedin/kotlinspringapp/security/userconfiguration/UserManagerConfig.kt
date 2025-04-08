package org.linkedin.kotlinspringapp.security.userconfiguration

import org.linkedin.kotlinspringapp.repository.UserRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserManagerConfig(private val userRepository: UserRepository) : UserDetailsService {
    override fun loadUserByUsername(email: String): UserDetails {
        return userRepository.findByEmail(email)
            ?.let { UserConfig(it) }
            ?: throw UsernameNotFoundException("User $email not found")
    }
}