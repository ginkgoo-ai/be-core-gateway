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

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (response instanceof HttpServletResponse) {
            CaseInsensitiveResponseHeaderWrapper responseWrapper = new CaseInsensitiveResponseHeaderWrapper((HttpServletResponse) response);
            chain.doFilter(request, responseWrapper);

            Map<String, String> dedupedHeaders = new HashMap<>();
            Collection<String> headerNames = responseWrapper.getHeaderNames();
            if (headerNames != null) {
                for (String headerName : headerNames) {
                    String lowerCaseHeader = headerName.toLowerCase();
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
