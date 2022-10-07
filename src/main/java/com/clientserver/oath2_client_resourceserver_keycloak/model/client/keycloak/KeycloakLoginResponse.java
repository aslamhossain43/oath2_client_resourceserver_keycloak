package com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak;

import lombok.Data;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Data
public class KeycloakLoginResponse {

    private String access_token;
    private String refresh_token;
    private String expires_in;
    private String refresh_expires_in;
    private String token_type;


}