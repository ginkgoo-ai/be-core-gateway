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

            Map<String, List<String>> allHeaders = responseWrapper.getAllHeaders();
            
            // 清除原始响应中的所有响应头
            Collection<String> headerNames = ((HttpServletResponse) response).getHeaderNames();
            if (headerNames != null) {
                for (String headerName : headerNames) {
                    ((HttpServletResponse) response).setHeader(headerName, null);
                }
            }

            // 使用Map来去重响应头
            Map<String, Set<String>> dedupedHeaders = new HashMap<>();
            allHeaders.forEach((headerName, values) -> {
                String lowerHeaderName = headerName.toLowerCase();
                dedupedHeaders.computeIfAbsent(lowerHeaderName, k -> new HashSet<>()).addAll(values);
            });

            // 记录去重前的响应头
            log.debug("Original headers: {}", allHeaders);
            log.debug("Deduped headers: {}", dedupedHeaders);

            // 清除包装器中的响应头
            responseWrapper.clearHeaders();

            // 使用setHeader而不是addHeader来设置响应头
            dedupedHeaders.forEach((headerName, values) -> {
                if (!values.isEmpty()) {
                    // 如果有多个值，用逗号分隔
                    String combinedValue = String.join(", ", values);
                    ((HttpServletResponse) response).setHeader(headerName, combinedValue);
                    log.debug("Setting header: {} = {}", headerName, combinedValue);
                }
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
            String lowerName = name.toLowerCase();
            headers.put(lowerName, new ArrayList<>(Collections.singletonList(value)));
        }

        @Override
        public void addHeader(String name, String value) {
            String lowerName = name.toLowerCase();
            headers.computeIfAbsent(lowerName, k -> new ArrayList<>()).add(value);
        }

        @Override
        public Collection<String> getHeaderNames() {
            return headers.keySet();
        }

        @Override
        public String getHeader(String name) {
            String lowerName = name.toLowerCase();
            List<String> values = headers.get(lowerName);
            return (values != null && !values.isEmpty()) ? values.get(0) : null;
        }

        @Override
        public Collection<String> getHeaders(String name) {
            String lowerName = name.toLowerCase();
            List<String> values = headers.get(lowerName);
            return values != null ? values : Collections.emptyList();
        }

        public Map<String, List<String>> getAllHeaders() {
            return new HashMap<>(headers);
        }

        public void clearHeaders() {
            headers.clear();
        }
    }
}
