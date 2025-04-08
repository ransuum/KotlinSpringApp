package org.linkedin.kotlinspringapp

import org.linkedin.kotlinspringapp.security.rsa.RSAKeyRecord
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.runApplication

@SpringBootApplication
@EnableConfigurationProperties(RSAKeyRecord::class)
class KotlinSpringAppApplication

fun main(args: Array<String>) {
    runApplication<KotlinSpringAppApplication>(*args)
}
