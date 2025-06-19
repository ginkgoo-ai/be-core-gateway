package com.ginkgooai.core.gateway.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.*;

@Component
@Slf4j
public class CaseInsensitiveResponseHeaderFilter implements Filter {

    private static final Set<String> CORS_HEADERS = Set.of(
            "access-control-allow-origin",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-allow-credentials",
            "access-control-max-age"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		// Skip for SSE stream endpoints to avoid interfering with streaming headers
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			String requestUri = httpRequest.getRequestURI();
			if (requestUri.endsWith("/stream")) {
				log.debug("Skipping header processing for SSE stream endpoint: {}", requestUri);
				chain.doFilter(request, response);
				return;
			}
		}
        
        if (response instanceof HttpServletResponse) {
            HttpServletResponse originalResponse = (HttpServletResponse) response;
            CaseInsensitiveResponseHeaderWrapper responseWrapper = new CaseInsensitiveResponseHeaderWrapper(originalResponse);
            chain.doFilter(request, responseWrapper);

            // 获取当前所有响应头，并清除原始响应中的所有响应头
            Collection<String> currentHeaderNames = originalResponse.getHeaderNames();
            if (currentHeaderNames != null) {
                for (String headerName : currentHeaderNames) {
                    originalResponse.setHeader(headerName, null);
                }
            }

            // 处理 CORS 响应头
            Collection<String> headerNames = responseWrapper.getHeaderNames();
            for (String headerName : headerNames) {
                String lowerCaseHeader = headerName.toLowerCase();
                if (CORS_HEADERS.contains(lowerCaseHeader)) {
                    String value = responseWrapper.getHeader(headerName);
                    if (value != null) {
                        originalResponse.setHeader(headerName, value);
                        log.trace("Setting CORS header: {} = {}", headerName, value);
                    }
                }
            }

            // 处理其他响应头
            Map<String, String> dedupedHeaders = new HashMap<>();
            for (String headerName : headerNames) {
                String lowerCaseHeader = headerName.toLowerCase();
                if (!CORS_HEADERS.contains(lowerCaseHeader)) {
                    if (!dedupedHeaders.containsKey(lowerCaseHeader)) {
                        log.trace("Adding header: {}", headerName);
                        dedupedHeaders.put(lowerCaseHeader, responseWrapper.getHeader(headerName));
                    }
                }
            }

            // 设置去重后的响应头
            dedupedHeaders.forEach((headerName, value) -> {
                originalResponse.setHeader(headerName, value);
                log.trace("Setting header: {} = {}", headerName, value);
            });
        } else {
            chain.doFilter(request, response);
        }
    }

    private static class CaseInsensitiveResponseHeaderWrapper extends HttpServletResponseWrapper {

        private final Map<String, List<String>> headers = new HashMap<>();

        public CaseInsensitiveResponseHeaderWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public void setHeader(String name, String value) {
            headers.put(name, new ArrayList<>(Collections.singletonList(value)));
        }

        @Override
        public void addHeader(String name, String value) {
            headers.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }

        @Override
        public Collection<String> getHeaderNames() {
            return headers.keySet();
        }

        @Override
        public String getHeader(String name) {
            List<String> values = headers.get(name);
            return (values != null && !values.isEmpty()) ? values.get(0) : null;
        }

        @Override
        public Collection<String> getHeaders(String name) {
            List<String> values = headers.get(name);
            return values != null ? values : Collections.emptyList();
        }

        public void clearHeaders() {
            headers.clear();
        }
    }
}
