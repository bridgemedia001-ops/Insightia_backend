package com.mxr.integration.service;

import java.time.Instant;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.mxr.integration.dto.GitHubUserResponse;
import com.mxr.integration.dto.TokenResponse;
import com.mxr.integration.model.RefreshToken;
import com.mxr.integration.model.User;
import com.mxr.integration.repo.RefreshTokenRepository;
import com.mxr.integration.repo.UserRepository;
import com.mxr.integration.security.JwtUtil;
import com.mxr.integration.security.Role;

import lombok.Data;

@Service
public class GitHubOAuthService {

    @Value("${github.client-id}")
    private String clientId;

    @Value("${github.client-secret}")
    private String clientSecret;

    @Value("${github.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    public GitHubOAuthService(RestTemplate restTemplate, UserRepository userRepository,
            RefreshTokenRepository refreshTokenRepository, JwtUtil jwtUtil) {
        this.restTemplate = restTemplate;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtUtil = jwtUtil;
    }

    public String getGitHubAuthorizationUrl(String state, String codeChallenge) {
        return "https://github.com/login/oauth/authorize" +
                "?client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&state=" + state +
                "&code_challenge=" + codeChallenge +
                "&code_challenge_method=S256";
    }

    public TokenResponse exchangeCodeForTokens(String codeVerifier) {
        String tokenUrl = "https://github.com/login/oauth/access_token" +
                "?client_id=" + clientId +
                "&client_secret=" + clientSecret +
                // "&code=" + code +
                "&code_verifier=" + codeVerifier;

        GitHubTokenResponse tokenResponse = restTemplate.postForObject(tokenUrl, null, GitHubTokenResponse.class);

        if (tokenResponse == null || tokenResponse.getAccess_token() == null) {
            throw new RuntimeException("Failed to exchange code for token");
        }

        GitHubUserResponse githubUser = fetchGitHubUser(tokenResponse.getAccess_token());

        User user = createOrUpdateUser(githubUser);

        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), user.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        saveRefreshToken(refreshToken, user.getUsername());

        return TokenResponse.builder()
                .status("success")
                .access_token(accessToken)
                .refresh_token(refreshToken)
                .build();
    }

    private GitHubUserResponse fetchGitHubUser(String accessToken) {
        String userUrl = "https://api.github.com/user";
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setBearerAuth(accessToken);
        org.springframework.http.HttpEntity<String> entity = new org.springframework.http.HttpEntity<>(headers);

        return restTemplate.exchange(userUrl, org.springframework.http.HttpMethod.GET, entity,
                GitHubUserResponse.class).getBody();
    }

    private User createOrUpdateUser(GitHubUserResponse githubUser) {
        Optional<User> existingUser = userRepository.findByGithubId(githubUser.getId().toString());

        if (existingUser.isPresent()) {
            User user = existingUser.get();
            user.setLastLoginAt(Instant.now());
            user.setActive(true);
            return userRepository.save(user);
        }

        User newUser = User.builder()
                .githubId(githubUser.getId().toString())
                .username(githubUser.getLogin())
                .email(githubUser.getEmail())
                .avatarUrl(githubUser.getAvatar_url())
                .role(Role.ANALYST)
                .isActive(true)
                .lastLoginAt(Instant.now())
                .build();

        return userRepository.save(newUser);
    }

    private void saveRefreshToken(String token, String username) {
        refreshTokenRepository.deleteByUsername(username);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .username(username)
                .isRevoked(false)
                .expiresAt(Instant.now().plusSeconds(300))
                .createdAt(Instant.now())
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    public TokenResponse refreshAccessToken(String refreshToken) {
        Optional<RefreshToken> tokenOptional = refreshTokenRepository.findByToken(refreshToken);

        if (tokenOptional.isEmpty() || tokenOptional.get().isRevoked()) {
            throw new RuntimeException("Invalid refresh token");
        }

        RefreshToken tokenEntity = tokenOptional.get();

        if (tokenEntity.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        String username = tokenEntity.getUsername();
        Optional<User> userOptional = userRepository.findByUsername(username);

        if (userOptional.isEmpty() || !userOptional.get().isActive()) {
            throw new RuntimeException("User not found or inactive");
        }

        User user = userOptional.get();

        tokenEntity.setRevoked(true);
        refreshTokenRepository.save(tokenEntity);

        String newAccessToken = jwtUtil.generateAccessToken(user.getUsername(), user.getRole().name());
        String newRefreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        saveRefreshToken(newRefreshToken, user.getUsername());

        return TokenResponse.builder()
                .status("success")
                .access_token(newAccessToken)
                .refresh_token(newRefreshToken)
                .build();
    }

    public void logout(String refreshToken) {
        Optional<RefreshToken> tokenOptional = refreshTokenRepository.findByToken(refreshToken);

        if (tokenOptional.isPresent()) {
            RefreshToken token = tokenOptional.get();
            token.setRevoked(true);
            refreshTokenRepository.save(token);
        }
    }

    @Data
    private static class GitHubTokenResponse {
        private String access_token;
    }
}
