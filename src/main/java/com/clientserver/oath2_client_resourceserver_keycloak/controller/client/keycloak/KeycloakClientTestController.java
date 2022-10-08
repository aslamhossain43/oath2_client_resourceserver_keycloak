package com.clientserver.oath2_client_resourceserver_keycloak.controller.client.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 08, 2022
 */
@RestController
@RequestMapping("/keycloak-client-test")
@PreAuthorize("isAuthenticated()")
public class KeycloakClientTestController {
    @GetMapping("/greet")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> getGreeting() throws JsonProcessingException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String authenticationName = authentication.getName();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        ObjectMapper objectMapper = new ObjectMapper();
        String roles = objectMapper.writeValueAsString(authorities);
        return ResponseEntity.ok("User id: " + authenticationName + ", Roles: " + roles);

    }

}
