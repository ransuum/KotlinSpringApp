package org.linkedin.kotlinspringapp.security.userconfiguration

import org.linkedin.kotlinspringapp.models.entity.Users
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails

class UserConfig(private val users: Users) : UserDetails {
    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = users.roles.split(",")
        .toMutableList()
        .map { SimpleGrantedAuthority(it) }
        .toMutableList()

    override fun getPassword() = users.password
    override fun getUsername() = users.email
    override fun isAccountNonExpired() = true
    override fun isAccountNonLocked() = true
    override fun isCredentialsNonExpired() = true
    override fun isEnabled() = true
}