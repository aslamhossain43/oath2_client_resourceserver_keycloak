package com.clientserver.oath2_client_resourceserver_keycloak.config.resourceserver;

import com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak.KeycloakClientFilter;
import com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak.KeycloakClientRoleConverter;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Configuration
public abstract class ResouceServerConfig {
    private final KeycloakClientFilter keycloakClientFilter;
    private final ResourceServerCorsConfig resourceServerCorsConfig;
    private final KeycloakClientRoleConverter keycloakClientRoleConverter;


    public ResouceServerConfig(KeycloakClientFilter keycloakClientFilter, ResourceServerCorsConfig resourceServerCorsConfig
            , KeycloakClientRoleConverter keycloakClientRoleConverter) {
        this.keycloakClientFilter = keycloakClientFilter;
        this.resourceServerCorsConfig = resourceServerCorsConfig;
        this.keycloakClientRoleConverter = keycloakClientRoleConverter;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ServerProperties serverProperties) throws Exception {
        // If access token exists then verify with keycloak
        http.addFilterBefore(keycloakClientFilter, BasicAuthenticationFilter.class);
        // Enable OAuth2 with custom authorities mapping
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(authenticationConverter());
        // Enable and configure CORS for /greet/**, you can customize more
        http.cors().configurationSource(resourceServerCorsConfig.corsConfigurationSource("/greet/**"));
        // State-less session (state in access-token only)
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        // Enable CSRF with cookie repo because of state-less session-management
        http.csrf().disable();
        // If SSL enabled, disable http (https only)
        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        } else {
            http.requiresChannel().anyRequest().requiresInsecure();
        }
//        Path mapping and other some configuration is in keycloak client side because that is the entry point of server
        return http.build();
    }

    Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(keycloakClientRoleConverter);
        return jwtAuthenticationConverter;
    }

}
