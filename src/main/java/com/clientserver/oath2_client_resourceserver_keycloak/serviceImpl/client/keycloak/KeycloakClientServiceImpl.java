package com.clientserver.oath2_client_resourceserver_keycloak.serviceImpl.client.keycloak;

import com.clientserver.oath2_client_resourceserver_keycloak.model.client.LogoutResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakIntrospectResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakLoginResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakTokenRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.service.client.keycloak.KeycloakClientService;
import com.clientserver.oath2_client_resourceserver_keycloak.util.client.keycloak.KeycloakConfigProperty;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Service
public class KeycloakClientServiceImpl implements KeycloakClientService {
    private final RestTemplate restTemplate;
    private final KeycloakConfigProperty keycloakConfigProperty;


    public KeycloakClientServiceImpl(RestTemplate restTemplate, KeycloakConfigProperty keycloakConfigProperty) {
        this.restTemplate = restTemplate;
        this.keycloakConfigProperty = keycloakConfigProperty;
    }

    @Override
    public ResponseEntity<KeycloakLoginResponse> login(KeycloakLoginRequest keycloakLoginRequest) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", keycloakConfigProperty.getClientId());
        map.add("client_secret", keycloakConfigProperty.getClientSecret());
        map.add("grant_type", keycloakConfigProperty.getGrantType());
        map.add("username", keycloakLoginRequest.getUsername());
        map.add("password", keycloakLoginRequest.getPassword());
        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);
        ResponseEntity<KeycloakLoginResponse> responseEntity = restTemplate.postForEntity(keycloakConfigProperty.getTokenUrl(), httpEntity, KeycloakLoginResponse.class);
        return new ResponseEntity<>(responseEntity.getBody(), HttpStatus.OK);
    }

    @Override
    public ResponseEntity<LogoutResponse> logout(KeycloakTokenRequest keycloakTokenRequest) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", keycloakConfigProperty.getClientId());
        map.add("client_secret", keycloakConfigProperty.getClientSecret());
        map.add("refresh_token", keycloakTokenRequest.getRefresh_token());
        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);
        ResponseEntity<LogoutResponse> response = restTemplate.postForEntity(keycloakConfigProperty.getLogoutUrl(), httpEntity, LogoutResponse.class);
        LogoutResponse logoutResponse = new LogoutResponse();
        if (response.getStatusCode().is2xxSuccessful()) {
            logoutResponse.setMessage("Logged out successfully");
        }
        return new ResponseEntity<>(logoutResponse, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<KeycloakIntrospectResponse> introspect(KeycloakTokenRequest keycloakTokenRequest) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", keycloakConfigProperty.getClientId());
        map.add("client_secret", keycloakConfigProperty.getClientSecret());
        map.add("token", keycloakTokenRequest.getAccess_token());
        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);
        ResponseEntity<KeycloakIntrospectResponse> response = restTemplate.postForEntity(keycloakConfigProperty.getIntrospectUrl(), httpEntity, KeycloakIntrospectResponse.class);
        return new ResponseEntity<>(response.getBody(), HttpStatus.OK);
    }
}
