package com.example.demo.jwt;

import com.google.common.net.HttpHeaders;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


// error not regestred via @EnableConfigurationProperties or masked as spring component
// error spring boot configuration annotation processor not found in classpath see in google

@Component
@ConfigurationProperties(prefix = "application.jwt")
public class JwtConfig {

    private String secretkey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;


    public JwtConfig() {
    }


    public String getSecretkey() {
        return secretkey;
    }

    public void setSecretkey(String secretkey) {
        this.secretkey = secretkey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationAfterDays() {
        return tokenExpirationAfterDays;
    }

    public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
        this.tokenExpirationAfterDays = tokenExpirationAfterDays;
    }


    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }

}
