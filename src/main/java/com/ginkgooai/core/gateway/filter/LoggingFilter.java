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
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
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

    private static final List<String> STREAM_CONTENT_TYPES = Arrays.asList(
            "application/octet-stream",
            "application/pdf",
            "image/",
            "video/",
            "audio/",
            "multipart/form-data"
    );

    private static final List<String> EXCLUDE_PATHS = Arrays.asList(
            "/actuator",
        "/health",
            "/swagger",
            "/v3/api-docs",
            "/favicon.ico",
            "/static",
			"/webjars", "/stream" // Exclude SSE stream endpoints
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

		String requestUri = httpRequest.getRequestURI();

		// Skip logging for SSE stream endpoints and other excluded paths
		if (shouldExclude(requestUri) || isSSEStream(requestUri)) {
			log.debug("Skipping logging for path: {}", requestUri);
            chain.doFilter(request, response);
            return;
        }

        ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(httpRequest);
        ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(httpResponse);

        long startTime = System.currentTimeMillis();
        try {
            chain.doFilter(requestWrapper, responseWrapper);

            logApiInfo(requestWrapper, responseWrapper, System.currentTimeMillis() - startTime);
        } finally {
            responseWrapper.copyBodyToResponse();

        }
    }

    private boolean shouldExclude(String uri) {
        return EXCLUDE_PATHS.stream().anyMatch(uri::startsWith);
    }

	private boolean isSSEStream(String uri) {
		return uri.endsWith("/stream");
	}

    private void logApiInfo(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response, long timeElapsed) {
        try {
            String requestBody = getRequestBody(request);
            String responseBody = isStreamContent(response.getContentType()) ? "[Stream Response Size : " + response.getContentSize() : getResponseBody(response);

            log.info("API Call - {} {} - Status: {} - Time: {}ms\nRequest: {}\nResponse: {}",
                    request.getMethod(),
                    request.getRequestURI(),
                    response.getStatus(),
                    timeElapsed,
                    requestBody,
                    responseBody
            );
        } catch (Exception e) {
            log.warn("Failed to log API info", e);
        }
    }

    private String getRequestBody(ContentCachingRequestWrapper request) throws UnsupportedEncodingException {
        String contentType = request.getContentType();
        byte[] content = request.getContentAsByteArray();
        if (content.length == 0) {
            return request.getQueryString() != null ? "Query: " + request.getQueryString() : "";
        }

        String contentBody = new String(content, request.getCharacterEncoding());
        if (isJsonContent(contentType)) {
            return formatJson(contentBody);
        }
        return contentBody;
    }

    private String getResponseBody(ContentCachingResponseWrapper response) throws UnsupportedEncodingException {
        String contentType = response.getContentType();
        byte[] content = response.getContentAsByteArray();
        if (content.length == 0) {
            return "";
        }

        String responseBody = new String(content, response.getCharacterEncoding());
        if (isJsonContent(contentType)) {
            return formatJson(responseBody);
        }
        return responseBody;
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
            return mapper.writeValueAsString(json); // 不使用 pretty print，使日志更紧凑
        } catch (Exception e) {
            return content;
        }
    }

    private boolean isStreamContent(String contentType) {
        if (contentType == null) return false;
        String lowerContentType = contentType.toLowerCase();
        return STREAM_CONTENT_TYPES.stream()
                .anyMatch(lowerContentType::startsWith);
    }
}
