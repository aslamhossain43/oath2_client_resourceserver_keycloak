package com.clientserver.oath2_client_resourceserver_keycloak.service.client.keycloak;

import com.clientserver.oath2_client_resourceserver_keycloak.model.client.LogoutResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakIntrospectResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakTokenRequest;
import org.springframework.http.ResponseEntity;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
public interface KeycloakClientService {
    ResponseEntity<KeycloakLoginResponse> login(KeycloakLoginRequest keycloakLoginRequest);

    ResponseEntity<LogoutResponse> logout(KeycloakTokenRequest keycloakTokenRequest);

    ResponseEntity<KeycloakIntrospectResponse> introspect(KeycloakTokenRequest keycloakTokenRequest);
}
