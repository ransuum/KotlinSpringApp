package org.linkedin.kotlinspringapp.security.rsa

import org.springframework.boot.context.properties.ConfigurationProperties
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

@ConfigurationProperties(prefix = "jwt")
data class RSAKeyRecord(
    val rsaPublicKey: RSAPublicKey,
    val rsaPrivateKey: RSAPrivateKey
)
