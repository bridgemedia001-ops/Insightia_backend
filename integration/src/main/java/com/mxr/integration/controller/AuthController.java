package com.mxr.integration.controller;

import java.util.Optional;

import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import com.mxr.integration.dto.RefreshTokenRequest;
import com.mxr.integration.dto.TokenResponse;
import com.mxr.integration.dto.UserProfileResponse;
import com.mxr.integration.model.User;
import com.mxr.integration.repo.UserRepository;
import com.mxr.integration.service.GitHubOAuthService;

@RestController
public class AuthController {

    private final GitHubOAuthService gitHubOAuthService;
    private final UserRepository userRepository;

    public AuthController(GitHubOAuthService gitHubOAuthService, UserRepository userRepository) {
        this.gitHubOAuthService = gitHubOAuthService;
        this.userRepository = userRepository;
    }

    @GetMapping("/auth/github")
    public RedirectView githubLogin(@RequestParam(required = false, defaultValue = "web") String source) {
        String authUrl = gitHubOAuthService.getGitHubAuthorizationUrl(source);
        return new RedirectView(authUrl);
    }

    @GetMapping("/auth/github/callback")
    public ResponseEntity<?> githubCallback(@RequestParam String code, @RequestParam String state) {
        TokenResponse response = gitHubOAuthService.exchangeCodeForTokens(code, null);

        if (state.startsWith("web__")) {
            // Web flow: set cookies and redirect to dashboard
            ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", response.getAccess_token())
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .sameSite("None")
                    .maxAge(180)
                    .build();
            ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", response.getRefresh_token())
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .sameSite("None")
                    .maxAge(300)
                    .build();

            return ResponseEntity.status(HttpStatus.FOUND)
                    .header("Set-Cookie", accessTokenCookie.toString())
                    .header("Set-Cookie", refreshTokenCookie.toString())
                    .header("Location", gitHubOAuthService.getFrontendUrl() + "/dashboard")
                    .build();
        } else {
            // CLI flow: return JSON response
            return ResponseEntity.ok(response);
        }
    }

    @GetMapping("/auth/me")
    public ResponseEntity<?> getCurrentUser(
            @CookieValue(value = "access_token", required = false) String cookieToken,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {

        String token = null;
        if (cookieToken != null) {
            token = cookieToken;
        } else if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            String username = gitHubOAuthService.extractUsernameFromToken(token);
            Optional<User> userOptional = userRepository.findByUsername(username);

            if (userOptional.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            User user = userOptional.get();
            UserProfileResponse profile = UserProfileResponse.builder()
                    .status("success")
                    .id(user.getId().toString())
                    .github_id(user.getGithubId())
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .avatar_url(user.getAvatarUrl())
                    .role(user.getRole().name())
                    .is_active(user.isActive())
                    .last_login_at(user.getLastLoginAt() != null ? user.getLastLoginAt().toString() : null)
                    .created_at(user.getCreatedAt() != null ? user.getCreatedAt().toString() : null)
                    .build();

            return ResponseEntity.ok(profile);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<?> refreshToken(
            @RequestBody(required = false) RefreshTokenRequest request,
            @CookieValue(value = "refresh_token", required = false) String cookieToken) {

        String refreshToken = null;
        boolean isWebFlow = false;

        if (request != null && request.getRefresh_token() != null) {
            refreshToken = request.getRefresh_token();
        } else if (cookieToken != null) {
            refreshToken = cookieToken;
            isWebFlow = true;
        }

        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            TokenResponse response = gitHubOAuthService.refreshAccessToken(refreshToken);

            if (isWebFlow) {
                // Web flow: set new cookies
                ResponseCookie accessTokenCookie = ResponseCookie.from("access_token", response.getAccess_token())
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .sameSite("None")
                        .maxAge(180)
                        .build();
                ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", response.getRefresh_token())
                        .httpOnly(true)
                        .secure(true)
                        .path("/")
                        .sameSite("None")
                        .maxAge(300)
                        .build();

                return ResponseEntity.ok()
                        .header("Set-Cookie", accessTokenCookie.toString())
                        .header("Set-Cookie", refreshTokenCookie.toString())
                        .build();
            } else {
                // CLI flow: return JSON response
                return ResponseEntity.ok(response);
            }
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(
            @RequestBody(required = false) RefreshTokenRequest request,
            @CookieValue(value = "refresh_token", required = false) String cookieToken) {

        String refreshToken = null;

        if (request != null && request.getRefresh_token() != null) {
            refreshToken = request.getRefresh_token();
        } else if (cookieToken != null) {
            refreshToken = cookieToken;
        }

        if (refreshToken != null) {
            gitHubOAuthService.logout(refreshToken);
        }

        // Clear cookies for web flow
        ResponseCookie clearedRefreshCookie = ResponseCookie.from("refresh_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(0)
                .build();
        ResponseCookie clearedAccessCookie = ResponseCookie.from("access_token", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .sameSite("None")
                .maxAge(0)
                .build();

        return ResponseEntity.noContent()
                .header("Set-Cookie", clearedRefreshCookie.toString())
                .header("Set-Cookie", clearedAccessCookie.toString())
                .build();
    }
}
