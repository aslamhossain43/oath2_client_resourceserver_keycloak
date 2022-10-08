package com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak;

import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakIntrospectResponse;
import com.clientserver.oath2_client_resourceserver_keycloak.model.client.keycloak.KeycloakTokenRequest;
import com.clientserver.oath2_client_resourceserver_keycloak.service.client.keycloak.KeycloakClientService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 08, 2022
 */
@Component
public class KeycloakClientFilter extends GenericFilterBean {
    private final KeycloakClientService keycloakClientService;

    public KeycloakClientFilter(KeycloakClientService keycloakClientService) {
        this.keycloakClientService = keycloakClientService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String accessToken = null;
        ResponseEntity<KeycloakIntrospectResponse> isKeycloakTokenValid = null;
        if (httpServletRequest.getHeader("Authorization") != null) {
            accessToken = httpServletRequest.getHeader("Authorization").substring(7).trim();
            KeycloakTokenRequest keycloakTokenRequest = new KeycloakTokenRequest();
            keycloakTokenRequest.setAccess_token(accessToken);
            isKeycloakTokenValid = keycloakClientService.introspect(keycloakTokenRequest);
            if (!StringUtils.isEmpty(accessToken) && isKeycloakTokenValid != null && !isKeycloakTokenValid.getBody().getActive()) {
                HttpServletResponse httpServletResponse = (HttpServletResponse) response;
                httpServletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            } else {
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }
}
