package com.mxr.integration.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.mxr.integration.security.JwtAuthenticationFilter;
import com.mxr.integration.security.RoleAuthorizationFilter;
import com.mxr.integration.filter.ApiVersionFilter;
import com.mxr.integration.filter.RateLimitFilter;
import com.mxr.integration.filter.RequestLoggingFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig implements WebMvcConfigurer {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RoleAuthorizationFilter roleAuthorizationFilter;
    private final ApiVersionFilter apiVersionFilter;
    private final RateLimitFilter rateLimitFilter;
    private final RequestLoggingFilter requestLoggingFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
            RoleAuthorizationFilter roleAuthorizationFilter, ApiVersionFilter apiVersionFilter,
            RateLimitFilter rateLimitFilter, RequestLoggingFilter requestLoggingFilter,
            CorsConfigurationSource corsConfigurationSource) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.roleAuthorizationFilter = roleAuthorizationFilter;
        this.apiVersionFilter = apiVersionFilter;
        this.rateLimitFilter = rateLimitFilter;
        this.requestLoggingFilter = requestLoggingFilter;
        this.corsConfigurationSource = corsConfigurationSource;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/").permitAll()
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .requestMatchers("/api/profiles").authenticated()
                        .requestMatchers("/api/profiles/**").authenticated()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(requestLoggingFilter).addPathPatterns("/**");
        registry.addInterceptor(rateLimitFilter).addPathPatterns("/**");
        registry.addInterceptor(apiVersionFilter).addPathPatterns("/api/**");
        registry.addInterceptor(roleAuthorizationFilter).addPathPatterns("/api/**");
    }
}
