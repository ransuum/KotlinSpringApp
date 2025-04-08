package org.linkedin.kotlinspringapp.security.userconfiguration

import org.linkedin.kotlinspringapp.models.entity.User
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class UserConfig(private val user: User) : UserDetails {
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = user.roles.split(",")
        .toMutableList()
        .map { SimpleGrantedAuthority(it) }
        .toMutableList()

    override fun getPassword() = user.password
    override fun getUsername() = user.email
    override fun isAccountNonExpired() = true
    override fun isAccountNonLocked() = true
    override fun isCredentialsNonExpired() = true
    override fun isEnabled() = true
}