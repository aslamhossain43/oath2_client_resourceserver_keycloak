package com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 08, 2022
 */
@Component
public class KeycloakClientRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @SuppressWarnings("unchecked")
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        final var realmAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("realm_access", Map.of());
        final var realmRoles = (Collection<String>) realmAccess.getOrDefault("roles", List.of().stream().map(roleName -> roleName.toString().toUpperCase()));
        final var resourceAccess = (Map<String, Object>) jwt.getClaims().getOrDefault("resource_access", Map.of());
        // We assume here you have "spring-addons-confidential" and "spring-addons-public" clients configured with "client roles" mapper in Keycloak
        final var confidentialClientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons-confidential", Map.of());
        final var confidentialClientRoles = (Collection<String>) confidentialClientAccess.getOrDefault("roles", List.of().stream().map(roleName -> roleName.toString().toUpperCase()));
        final var publicClientAccess = (Map<String, Object>) resourceAccess.getOrDefault("spring-addons-public", Map.of());
        final var publicClientRoles = (Collection<String>) publicClientAccess.getOrDefault("roles", List.of().stream().map(roleName -> roleName.toString().toUpperCase()));
        return Stream.concat(realmRoles.stream(), Stream.concat(confidentialClientRoles.stream(), publicClientRoles.stream()))
                .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}