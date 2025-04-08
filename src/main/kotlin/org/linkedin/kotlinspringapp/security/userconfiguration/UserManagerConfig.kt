package org.linkedin.kotlinspringapp.security.userconfiguration

import org.linkedin.kotlinspringapp.repository.UsersRepository
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service

@Service
class UserManagerConfig(private val usersRepository: UsersRepository) : UserDetailsService {
    override fun loadUserByUsername(email: String): UserDetails {
        return usersRepository.findByEmail(email)
            ?.let { UserConfig(it) }
            ?: throw UsernameNotFoundException("User $email not found")
    }
}