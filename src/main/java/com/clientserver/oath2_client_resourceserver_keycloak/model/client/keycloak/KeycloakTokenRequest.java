package com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak;

import lombok.Data;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Data
public class KeycloakTokenRequest {
    private String access_token;
    private String refresh_token;
}
