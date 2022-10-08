package com.clientserver.oath2_client_resourceserver_keycloak.controller.client.keycloak;

import com.clientserver.oath2_client_resourceserver_keycloak.model.client.LogoutResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakIntrospectResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakTokenRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.service.client.keycloak.KeycloakClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@RestController
@RequestMapping("/keycloak-client")
public class KeycloakClientController {
    private final KeycloakClientService keycloakClientService;

    public KeycloakClientController(KeycloakClientService keycloakClientService) {
        this.keycloakClientService = keycloakClientService;
    }

    @PostMapping("/login")
    public ResponseEntity<KeycloakLoginResponse> login(@RequestBody KeycloakLoginRequest keycloakLoginRequest) {
        return keycloakClientService.login(keycloakLoginRequest);
    }

    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(@RequestBody KeycloakTokenRequest keycloakTokenRequest) {
        return keycloakClientService.logout(keycloakTokenRequest);
    }

    @PostMapping("/introspect")
    public ResponseEntity<KeycloakIntrospectResponse> introspect(@RequestBody KeycloakTokenRequest keycloakTokenRequest) {
        return keycloakClientService.introspect(keycloakTokenRequest);
    }
}
