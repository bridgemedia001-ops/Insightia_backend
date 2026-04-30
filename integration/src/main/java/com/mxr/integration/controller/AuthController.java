package com.mxr.integration.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

import com.mxr.integration.dto.RefreshTokenRequest;
import com.mxr.integration.dto.TokenResponse;
import com.mxr.integration.service.GitHubOAuthService;

@RestController
public class AuthController {

    private final GitHubOAuthService gitHubOAuthService;

    public AuthController(GitHubOAuthService gitHubOAuthService) {
        this.gitHubOAuthService = gitHubOAuthService;
    }

    @GetMapping("/auth/github")
    public RedirectView githubLogin(@RequestParam(required = false, defaultValue = "web") String state, @RequestParam(required = false) String code_challenge) {
        String authUrl = gitHubOAuthService.getGitHubAuthorizationUrl(state, code_challenge);
        return new RedirectView(authUrl);
    }

    @GetMapping("/auth/github/callback")
    public ResponseEntity<TokenResponse> githubCallback(@RequestParam String code,
            @RequestParam String state, @RequestParam(required = false) String code_verifier) {
        TokenResponse response = gitHubOAuthService.exchangeCodeForTokens(code, code_verifier);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/refresh")
    public ResponseEntity<TokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        try {
            TokenResponse response = gitHubOAuthService.refreshAccessToken(request.getRefresh_token());
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/auth/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshTokenRequest request) {
        gitHubOAuthService.logout(request.getRefresh_token());
        return ResponseEntity.noContent().build();
    }
}
