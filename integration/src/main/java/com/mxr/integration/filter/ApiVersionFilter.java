package com.mxr.integration.filter;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class ApiVersionFilter implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws IOException {

        String path = request.getRequestURI();

        if (!path.startsWith("/api/")) {
            return true;
        }

        String apiVersion = request.getHeader("X-API-Version");

        if (apiVersion == null || !apiVersion.equals("1")) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().write("{\"status\":\"error\",\"message\":\"API version header required\"}");
            return false;
        }

        return true;
    }
}
