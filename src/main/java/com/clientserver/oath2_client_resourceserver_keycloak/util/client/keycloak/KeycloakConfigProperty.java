package com.clientserver.oath2_client_resourceserver_keycloak.util.client.keycloak;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Component
@Data
public class KeycloakConfigProperty {
    @Value("${spring.security.oauth2.client.provider.keycloak.issuer-uri}")
    private String issueUrl;
    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String tokenUrl;
    @Value("${keycloakclient.logout-url}")
    private String logoutUrl;
    @Value("${keycloakclient.introspect-url}")
    private String introspectUrl;
    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-secret}")
    private String clientSecret;
    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.authorization-grant-type}")
    private String grantType;
}
