package com.ginkgooai.core.gateway.filter;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
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
        if (response instanceof HttpServletResponse) {
            CaseInsensitiveResponseHeaderWrapper responseWrapper = new CaseInsensitiveResponseHeaderWrapper((HttpServletResponse) response);
            chain.doFilter(request, responseWrapper);

            // 先处理 CORS 响应头
            Collection<String> headerNames = responseWrapper.getHeaderNames();
            for (String headerName : headerNames) {
                String lowerCaseHeader = headerName.toLowerCase();
                if (CORS_HEADERS.contains(lowerCaseHeader)) {
                    String value = responseWrapper.getHeader(headerName);
                    if (value != null) {
                        ((HttpServletResponse) response).setHeader(headerName, value);
                        log.debug("Setting CORS header: {} = {}", headerName, value);
                    }
                }
            }

            Map<String, String> dedupedHeaders = new HashMap<>();
            for (String headerName : headerNames) {
                String lowerCaseHeader = headerName.toLowerCase();
                if (!CORS_HEADERS.contains(lowerCaseHeader)) {
                    if (!dedupedHeaders.containsKey(lowerCaseHeader)) {
                        log.debug("Adding header: {}", headerName);
                        dedupedHeaders.put(lowerCaseHeader, responseWrapper.getHeader(headerName));
                    }
                }
            }

            responseWrapper.clearHeaders();
            dedupedHeaders.forEach(responseWrapper::setHeader);
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
