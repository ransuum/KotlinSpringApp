package org.linkedin.kotlinspringapp.models

enum class Roles(private val permissions: Set<String>) {
    ROLE_TRAINEE(setOf("VIEW_TRAINEE_PROFILE", "SEARCH_TRAINEES", "AUTHORIZED")),
    ROLE_TRAINER(setOf("VIEW_TRAINER_PROFILE", "SEARCH_TRAINERS", "CHANGE_STATUS", "AUTHORIZED")),
    ADMIN(setOf("TRAINEE_DELETE", "TRAINER_DELETE", "FULL_ACCESS"));

    fun getPermissionsForRoles(roles: Collection<String>) = roles
        .map { Roles.valueOf(it) }
        .flatMap { it.permissions }
        .toSet()

    fun getPermissions() = permissions
}