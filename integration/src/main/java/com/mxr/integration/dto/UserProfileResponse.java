package com.mxr.integration.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse {
    private String status;
    private String id;
    private String github_id;
    private String username;
    private String email;
    private String avatar_url;
    private String role;
    private boolean is_active;
    private String last_login_at;
    private String created_at;
}
