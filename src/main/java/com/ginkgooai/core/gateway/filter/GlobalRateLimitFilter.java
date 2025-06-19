package com.ginkgooai.core.gateway.filter;

import com.ginkgooai.core.common.utils.IpUtils;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.AsyncBucketProxy;
import io.github.bucket4j.distributed.proxy.AsyncProxyManager;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * A simple implementation of a global rate limit filter using Bucket4j
 *
 * @see org.springframework.cloud.gateway.server.mvc.filter.Bucket4jFilterFunctions
 * Since Bucket4jFilterFunctions not support route yaml configuration , use this filter instead
 */

@Component
@Order(1)
public class GlobalRateLimitFilter extends OncePerRequestFilter {

    private static final String RATE_LIMIT_REMAINING_HEADER = "X-RateLimit-Remaining";
    private final AsyncProxyManager<String> proxyManager;
    @Value("${app.rate-limit.capacity:100}")
    private int rateLimitCapacity;

    @Value("${app.rate-limit.period-minutes:1}")
    private int rateLimitPeriodMinutes;

    public GlobalRateLimitFilter(AsyncProxyManager<String> proxyManager) {
        this.proxyManager = proxyManager;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {

        if (shouldSkipRateLimit(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = resolveKey(request);
        BucketConfiguration configuration = BucketConfiguration.builder()
            .addLimit(Bandwidth.builder()
                .capacity(rateLimitCapacity)
                .refillGreedy(rateLimitCapacity, Duration.ofMinutes(rateLimitPeriodMinutes))
                .build())
            .build();

        AsyncBucketProxy bucket = proxyManager.builder().build(key, configuration);
        CompletableFuture<ConsumptionProbe> probe = bucket.tryConsumeAndReturnRemaining(1);
        ConsumptionProbe consumptionProbe = probe.get();

        response.setHeader(RATE_LIMIT_REMAINING_HEADER, String.valueOf(consumptionProbe.getRemainingTokens()));

        if (consumptionProbe.isConsumed()) {
            filterChain.doFilter(request, response);
        } else {
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        }
    }

    private boolean shouldSkipRateLimit(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/actuator") ||
            path.startsWith("/swagger") ||
            path.startsWith("/health") ||
				path.startsWith("/v3/api-docs") || path.endsWith("/stream"); // Skip rate
																				// limiting
																				// for SSE
																				// stream
																				// endpoints
    }

    private String resolveKey(HttpServletRequest request) {
        if (request.getUserPrincipal() != null) {
            return request.getUserPrincipal().getName();
        }
        return IpUtils.getClientIpAddress(request);
    }
}