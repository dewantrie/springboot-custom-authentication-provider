package com.example.demo.security;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.example.demo.domain.model.TokenModel;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {
    @Value("${auth.baseurl}")
    private String authBaseurl;

    @Value("${auth.login.endpoint}")
    private String authLoginEndpoint;

    public CustomAuthenticationProvider() {
        super();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final var username = authentication.getName();
        final var password = authentication.getCredentials().toString();

        // Make a request to the API to authenticate the user and obtain the JWT token
        final var apiUrl = authBaseurl + authLoginEndpoint;

        // Prepare the request body
        final MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("username", username);
        requestBody.add("password", password);

        // Send the request to the API
        final var restTemplate = new RestTemplate();
        final var responseEntity = restTemplate.postForEntity(apiUrl, requestBody, TokenModel.class);

        if (responseEntity.getStatusCode() != HttpStatus.CREATED) {
            throw new BadCredentialsException("Invalid username or password");
        }

        log.info("Login Success");

        // Extract the JWT token from the response body and extract the role from the
        // JWT token
        final var responseBody = responseEntity.getBody();
        if (responseBody == null) {
            throw new BadCredentialsException("Access token not valid");
        }

        final var claims = parseClaims(responseBody.getAccessToken());
        final var role = extractRoleFromJwtToken(claims);

        // Create an authenticated token with the username, password, and authorities
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));
        Authentication authenticatedToken = new UsernamePasswordAuthenticationToken(username, password,
                authorities);

        // Store the access and refresh token in the session
        SecurityContextHolder.getContext().setAuthentication(authenticatedToken);
        ServletRequestAttributes request = (ServletRequestAttributes) RequestContextHolder
                .currentRequestAttributes();
        HttpSession session = request.getRequest().getSession(false);
        session.setAttribute("accessToken", responseBody.getAccessToken());
        session.setAttribute("refreshToken", responseBody.getRefreshToken());

        // Set session expiration based on JWT expiration time
        final var jwtExpiration = claims.getExpiration();
        final var sessionTimeoutInMillis = jwtExpiration.getTime() - System.currentTimeMillis();
        final var sessionExpiration = sessionTimeoutInMillis / 1000;
        session.setMaxInactiveInterval((int) sessionExpiration);

        return authenticatedToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    private PublicKey signingKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final byte[] signingKey = this.getClass().getClassLoader().getResourceAsStream("jwt.pub")
                .readAllBytes();
        String publicKeyPem = new String(signingKey)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("\\n", "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] keyContentAsBytes = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyContentAsBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    private Claims parseClaims(String jwtToken) {
        try {
            return Jwts.parserBuilder().setSigningKey(signingKey()).build().parseClaimsJws(jwtToken).getBody();
        } catch (SignatureException | ExpiredJwtException | UnsupportedJwtException | MalformedJwtException
                | IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            log.error("Parse Claims Error", e);
            throw new BadCredentialsException("Access token not valid");
        }
    }

    private String extractRoleFromJwtToken(Claims claims) {
        String role = claims.get("role", String.class);
        return "ROLE_" + role;
    }

}
