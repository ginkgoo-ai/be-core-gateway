package com.ginkgooai.core.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component
@Order(1)
public class LoggingFilter implements Filter {
    private static final Logger log = LoggerFactory.getLogger(LoggingFilter.class);
    private static final List<String> JSON_CONTENT_TYPES = Arrays.asList(
        "application/json",
        "application/json;charset=UTF-8",
        "application/json;charset=utf-8"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) 
            throws IOException, ServletException {
        
        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper((HttpServletRequest) request);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper((HttpServletResponse) response);
        
        long startTime = System.currentTimeMillis();
        
        try {
            logRequest(requestWrapper);
            chain.doFilter(requestWrapper, responseWrapper);
            logResponse(responseWrapper, System.currentTimeMillis() - startTime);
        } finally {
            responseWrapper.copyBodyToResponse();
        }
    }

    private void logRequest(ContentCachingRequestWrapper request) throws IOException {
        log.info("=========================== Request Start ===========================");
        log.info("URI: {} {}", request.getMethod(), request.getRequestURI());
        log.info("Query String: {}", request.getQueryString());
        
        Collections.list(request.getHeaderNames()).forEach(headerName -> 
            log.info("Header {}: {}", headerName, request.getHeader(headerName)));
        
        String contentType = request.getContentType();
        
        byte[] content = request.getContentAsByteArray();
        if (content.length > 0) {
            String contentBody = new String(content, request.getCharacterEncoding());
            if (isJsonContent(contentType)) {
                log.info("Request Body (JSON): {}", formatJson(contentBody));
            } else if (contentType != null && contentType.contains("form")) {
                log.info("Request Body (Form): {}", formatFormData(contentBody));
            } else {
                log.info("Request Body: {}", contentBody);
            }
        }
    }

    private void logResponse(ContentCachingResponseWrapper response, long timeElapsed) throws IOException {
        String contentType = response.getContentType();
        byte[] content = response.getContentAsByteArray();
        
        log.info("Response Status: {}", response.getStatus());
        log.info("Time Elapsed: {}ms", timeElapsed);
        
        if (content.length > 0) {
            String responseBody = new String(content, response.getCharacterEncoding());
            if (isJsonContent(contentType)) {
                log.info("Response Body (JSON): {}", formatJson(responseBody));
            } else {
                log.info("Response Body: {}", responseBody);
            }
        }
        log.info("=========================== Request End ===========================\n");
    }

    private boolean isJsonContent(String contentType) {
        if (contentType == null) return false;
        String lowerContentType = contentType.toLowerCase();
        return JSON_CONTENT_TYPES.stream()
            .anyMatch(lowerContentType::contains);
    }

    private String formatJson(String content) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Object json = mapper.readValue(content, Object.class);
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            log.warn("Failed to format JSON content", e);
            return content;
        }
    }

    private String formatFormData(String content) {
        try {
            StringBuilder formatted = new StringBuilder();
            String[] pairs = content.split("&");
            for (String pair : pairs) {
                String[] keyValue = pair.split("=");
                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8.name());
                String value = keyValue.length > 1 ? 
                    URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8.name()) : "";
                formatted.append(key).append(" = ").append(value).append("\n");
            }
            return formatted.toString();
        } catch (Exception e) {
            log.warn("Failed to format form data", e);
            return content;
        }
    }
}
