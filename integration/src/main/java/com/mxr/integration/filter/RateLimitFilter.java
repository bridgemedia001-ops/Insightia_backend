package com.mxr.integration.filter;

import java.io.IOException;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class RateLimitFilter implements HandlerInterceptor {

    private static final int AUTH_RATE_LIMIT = 10;
    private static final int GENERAL_RATE_LIMIT = 60;
    private static final long RATE_LIMIT_WINDOW_SECONDS = 60;

    private final ConcurrentHashMap<String, RateLimitInfo> authRateLimits = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RateLimitInfo> generalRateLimits = new ConcurrentHashMap<>();

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        String clientIp = getClientIp(request);
        String path = request.getRequestURI();
        long currentTime = Instant.now().getEpochSecond();

        ConcurrentHashMap<String, RateLimitInfo> rateLimitMap = path.startsWith("/auth/") ? authRateLimits
                : generalRateLimits;
        int rateLimit = path.startsWith("/auth/") ? AUTH_RATE_LIMIT : GENERAL_RATE_LIMIT;

        RateLimitInfo info = rateLimitMap.computeIfAbsent(clientIp, k -> new RateLimitInfo(currentTime));

        if (currentTime - info.windowStart > RATE_LIMIT_WINDOW_SECONDS) {
            info.windowStart = currentTime;
            info.requestCount.set(0);
        }

        if (info.requestCount.incrementAndGet() > rateLimit) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"error\",\"message\":\"Rate limit exceeded\"}");
            return false;
        }

        return true;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static class RateLimitInfo {
        long windowStart;
        AtomicInteger requestCount;

        RateLimitInfo(long windowStart) {
            this.windowStart = windowStart;
            this.requestCount = new AtomicInteger(0);
        }
    }
}
