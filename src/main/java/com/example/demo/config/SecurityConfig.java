package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.CookieRequestCache;

import com.example.demo.security.CustomAuthenticationProvider;

@Configuration
@EnableWebSecurity
@ComponentScan("com.example.demo.security")
public class SecurityConfig {
    private static final String LOGIN_PAGE = "/login";

    @Bean
    public AuthenticationManager authManager(
            HttpSecurity http,
            CustomAuthenticationProvider authProvider) throws Exception {

        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(authProvider);
        return authenticationManagerBuilder.build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/home/**").hasAnyRole("ADMIN")
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
                        .sessionFixation()
                        .migrateSession()
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .invalidSessionUrl(LOGIN_PAGE)
                        .maximumSessions(1)
                        .expiredUrl(LOGIN_PAGE))
                .requestCache(cache -> cache.requestCache(new CookieRequestCache()))
                .formLogin(form -> form
                        .loginPage(LOGIN_PAGE)
                        .loginProcessingUrl(LOGIN_PAGE)
                        .defaultSuccessUrl("/home")
                        .permitAll())
                .build();
    }

}
