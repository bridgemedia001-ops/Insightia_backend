package com.mxr.integration.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GitHubUserResponse {
    private Long id;
    private String login;
    private String email;
    private String avatar_url;
}
