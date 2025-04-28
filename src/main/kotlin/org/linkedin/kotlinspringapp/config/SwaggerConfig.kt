package org.linkedin.kotlinspringapp.config

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.Info
import io.swagger.v3.oas.models.security.SecurityRequirement
import io.swagger.v3.oas.models.security.SecurityScheme
import io.swagger.v3.oas.models.servers.Server
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
@OpenAPIDefinition
class SwaggerConfig: WebMvcConfigurer {
    @Bean
    fun openAPI(): OpenAPI =
        OpenAPI().servers(listOf(Server().url("http://localhost:8000")))
            .info(Info().title("Swagger API").version("v1.0.0"))
            .components(Components()
                .addSecuritySchemes("basicAuth", SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("basic"))
                .addSecuritySchemes("bearerAuth", SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")))
            .addSecurityItem(SecurityRequirement().addList("basicAuth"))
            .addSecurityItem(SecurityRequirement().addList("bearerAuth"))

    override fun addViewControllers(registry: ViewControllerRegistry) {
        registry.addRedirectViewController("/", "/swagger-ui.html");
    }


}