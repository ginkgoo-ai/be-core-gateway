package com.ginkgooai.core.gateway.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;

@Slf4j
public class CachingRequestBodyFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

		// Skip caching for SSE stream endpoints to avoid interfering with streaming
		String requestUri = request.getRequestURI();
		boolean isSSEStream = requestUri.contains("/stream");

		if (isSSEStream) {
			log.debug("Skipping request body caching for SSE stream endpoint: {}", requestUri);
			filterChain.doFilter(request, response);
			return;
		}

		boolean webhook = requestUri.contains("webhook");
        if(webhook){
            Enumeration<String> headerNames = request.getHeaderNames();
            while(headerNames.hasMoreElements()){
                String headerName = headerNames.nextElement();
                String headerValue = request.getHeader(headerName);
                log.info("Header: {} = {}", headerName, headerValue);
            }
        }

        CachedBodyHttpServletRequest cachedBodyRequest = new CachedBodyHttpServletRequest(request);
        filterChain.doFilter(cachedBodyRequest, response);
    }
}
