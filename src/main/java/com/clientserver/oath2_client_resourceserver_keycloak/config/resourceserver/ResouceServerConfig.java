package com.clientserver.oath2_client_resourceserver_keycloak.config.resourceserver;

import com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak.KeycloakClientFilter;
import com.clientserver.oath2_client_resourceserver_keycloak.config.client.keycloak.KeycloakClientRoleConverter;
import com.clientserver.oath2_client_resourceserver_keycloak.util.client.keycloak.KeycloakConfigProperty;
import org.keycloak.adapters.AdapterDeploymentContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springsecurity.AdapterDeploymentContextFactoryBean;
import org.keycloak.adapters.springsecurity.authentication.KeycloakLogoutHandler;
import org.keycloak.adapters.springsecurity.config.KeycloakSpringConfigResolverWrapper;
import org.keycloak.adapters.springsecurity.filter.*;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Configuration
public abstract class ResouceServerConfig {
    private final KeycloakClientFilter keycloakClientFilter;
    private final KeycloakConfigProperty keycloakConfigProperty;
    private final KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter;
    private final KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter;
    private final KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter;
    private final KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsFilter;
    private final AuthenticationManager authenticationManager;
    private final KeycloakLogoutHandler keycloakLogoutHandler;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final HttpSessionManager httpSessionManager;
    private final KeycloakConfigResolver keycloakConfigResolver;
    private final ResourceServerCorsConfig resourceServerCorsConfig;
    private final KeycloakClientRoleConverter keycloakClientRoleConverter;


    public ResouceServerConfig(KeycloakClientFilter keycloakClientFilter, KeycloakConfigProperty keycloakConfigProperty, KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter
            , KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter, KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter
            , KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsFilter, AuthenticationManager authenticationManager, KeycloakLogoutHandler keycloakLogoutHandler
            , AuthenticationEntryPoint authenticationEntryPoint, HttpSessionManager httpSessionManager, KeycloakConfigResolver keycloakConfigResolver, ResourceServerCorsConfig resourceServerCorsConfig, KeycloakClientRoleConverter keycloakClientRoleConverter) {
        this.keycloakClientFilter = keycloakClientFilter;
        this.keycloakConfigProperty = keycloakConfigProperty;
        this.keycloakPreAuthActionsFilter = keycloakPreAuthActionsFilter;
        this.keycloakAuthenticationProcessingFilter = keycloakAuthenticationProcessingFilter;
        this.keycloakSecurityContextRequestFilter = keycloakSecurityContextRequestFilter;
        this.keycloakAuthenticatedActionsFilter = keycloakAuthenticatedActionsFilter;
        this.authenticationManager = authenticationManager;
        this.keycloakLogoutHandler = keycloakLogoutHandler;
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.httpSessionManager = httpSessionManager;
        this.keycloakConfigResolver = keycloakConfigResolver;
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
        // Return 401 (unauthorized) instead of 403 (redirect to login) when authorization is missing or invalid
        http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
            response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
        });
        // If SSL enabled, disable http (https only)
        if (serverProperties.getSsl() != null && serverProperties.getSsl().isEnabled()) {
            http.requiresChannel().anyRequest().requiresSecure();
        } else {
            http.requiresChannel().anyRequest().requiresInsecure();
        }
        http.csrf().requireCsrfProtectionMatcher(keycloakCsrfRequestMatcher())
                .and()
                .sessionManagement()
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
                .addFilterBefore(keycloakPreAuthActionsFilter, LogoutFilter.class)
                .addFilterBefore(keycloakAuthenticationProcessingFilter, LogoutFilter.class)
                .addFilterAfter(keycloakSecurityContextRequestFilter, SecurityContextHolderAwareRequestFilter.class)
                .addFilterAfter(keycloakAuthenticatedActionsFilter, KeycloakSecurityContextRequestFilter.class)
                .exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
                .and()
                .logout()
                .addLogoutHandler(keycloakLogoutHandler)
                .logoutUrl("/sso/logout").permitAll()
                .logoutSuccessUrl("/");

        // Route security: authenticated to all routes but actuator and Swagger-UI
        http.authorizeRequests()
                .antMatchers("/actuator/health/readiness", "/actuator/health/liveness", "/v3/api-docs/**").permitAll()
                .anyRequest().authenticated();

        return http.build();
    }

    @Bean
    protected KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter() {
        return new KeycloakSecurityContextRequestFilter();
    }

    @Bean
    protected KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsRequestFilter() {
        return new KeycloakAuthenticatedActionsFilter();
    }

    @Bean
    protected AdapterDeploymentContext adapterDeploymentContext() throws Exception {
        AdapterDeploymentContextFactoryBean factoryBean;
        if (keycloakConfigResolver != null) {
            factoryBean = new AdapterDeploymentContextFactoryBean(new KeycloakSpringConfigResolverWrapper(keycloakConfigResolver));
        } else {
            factoryBean = new AdapterDeploymentContextFactoryBean(keycloakConfigProperty.getKeycloakConfigFileResource());
        }
        factoryBean.afterPropertiesSet();
        return factoryBean.getObject();
    }

    @Bean
    protected KeycloakAuthenticationProcessingFilter keycloakAuthenticationProcessingFilter() {
        KeycloakAuthenticationProcessingFilter filter = new KeycloakAuthenticationProcessingFilter(authenticationManager);
        filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy());
        return filter;
    }

    @Bean
    protected KeycloakPreAuthActionsFilter keycloakPreAuthActionsFilter() {
        return new KeycloakPreAuthActionsFilter(httpSessionManager);
    }

    protected KeycloakCsrfRequestMatcher keycloakCsrfRequestMatcher() {
        return new KeycloakCsrfRequestMatcher();
    }

    @Bean
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }

    protected abstract SessionAuthenticationStrategy sessionAuthenticationStrategy();

    Converter<Jwt, AbstractAuthenticationToken> authenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(keycloakClientRoleConverter);
        return jwtAuthenticationConverter;
    }

}
