package com.javatechie.spring.cloud.security.api;

import lombok.RequiredArgsConstructor;
import lombok.var;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;

import java.util.function.Consumer;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    @Autowired
    OAuth2AuthorizedClientService defaultAuthorizedClientService;
    
    @Autowired
    OAuth2AuthorizedClientRepository defaultAuthorizedClientRepository;


    @Autowired
    OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    @Autowired
    OAuth2AccessTokenResponseClient tokenResponseCertificateClient;


//    private AuthorizationRequestRepository<OAuth2AuthorizationRequest> defaultOAuth2AuthzRequestRepository;

    @Bean
    public HttpSessionOAuth2AuthorizationRequestRepository defaultOAuth2AuthzRequestRepository(){
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }


    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {


        http
                .authorizeRequests()
                .antMatchers("/").authenticated()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .and()
                .oauth2Client(auth -> auth
                        .authorizedClientService(defaultAuthorizedClientService)
                        .authorizedClientRepository(defaultAuthorizedClientRepository)
                        .authorizationCodeGrant(codeGrant ->
                                codeGrant.authorizationRequestRepository(defaultOAuth2AuthzRequestRepository())
                                .authorizationRequestResolver(authorizationRequestResolver)
                                .accessTokenResponseClient(tokenResponseCertificateClient)));
        return http.build();
    }



    @Bean
    OAuth2AuthorizationRequestResolver authorizationRequestResolver() {
        var defaultRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
        defaultRequestResolver.setAuthorizationRequestCustomizer(pkceCustomizer());
        return defaultRequestResolver;
    }
    private Consumer<OAuth2AuthorizationRequest.Builder> pkceCustomizer() {

        return OAuth2AuthorizationRequestCustomizers.withPkce();
//        return null;

    }
}


