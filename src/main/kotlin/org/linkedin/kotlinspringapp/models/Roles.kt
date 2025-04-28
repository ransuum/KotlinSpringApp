package org.linkedin.kotlinspringapp.models

enum class Roles(private val permissions: Set<String>) {
    ROLE_USER(setOf("ALL")),
    ADMIN(setOf("DELETE", "FULL_ACCESS"));

    companion object {
        fun getPermissionsForRoles(roles: Collection<String>) = roles
            .map { Roles.valueOf(it) }
            .flatMap { it.permissions }
            .toSet()
    }

    fun getPermissions() = permissions
}