package com.clientserver.oath2_client_resourceserver_keycloak.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

/**
 * @Author Md. Aslam Hossain
 * @Date Oct 07, 2022
 */
@Configuration
public class GeneralConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
