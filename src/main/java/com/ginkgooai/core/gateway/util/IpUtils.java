package com.ginkgooai.core.gateway.util;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Service;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.regex.Pattern;
import java.util.concurrent.TimeUnit;

/**
 * Utility class for extracting and normalizing client IP addresses.
 * Supports both IPv4 and IPv6 addresses, with special handling for
 * Cloudflare and proxy headers.
 */
@Slf4j
@Service
public final class IpUtils {
    private static final String UNKNOWN = "unknown";
    private static final String LOCALHOST_IPV4 = "127.0.0.1";
    private static final String LOCALHOST_IPV6 = "0:0:0:0:0:0:0:1";
    private static final int MAX_IP_LENGTH = 45;
    
    private static final Pattern IPV4_PATTERN = Pattern.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    );
    
    private static final Pattern IPV6_PATTERN = Pattern.compile(
        "^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$|^([0-9A-Fa-f]{1,4}:){1,7}:|^:[0-9A-Fa-f:]*$"
    );

    private static final List<String> PRIORITY_HEADERS = List.of(
        "True-Client-IP",    // Cloudflare True-Client-IP (highest priority)
        "CF-Connecting-IP",  // Alternative Cloudflare header
        "X-Forwarded-For",
        "X-Real-IP",
        "Proxy-Client-IP"
    );

    private static final LoadingCache<String, String> IP_CACHE = CacheBuilder.newBuilder()
        .maximumSize(1000)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build(new CacheLoader<>() {
            @Override
            public String load(String key) {
                return UNKNOWN;
            }
        });

    private static Counter ipResolutionCounter;
    private static Counter ipResolutionFailedCounter;

    /**
     * Initialize metrics if a MeterRegistry is available
     */
    public static void initializeMetrics(MeterRegistry registry) {
        ipResolutionCounter = Counter.builder("ip_resolution_total")
            .description("Total number of IP resolutions")
            .register(registry);
        
        ipResolutionFailedCounter = Counter.builder("ip_resolution_failed")
            .description("Number of failed IP resolutions")
            .register(registry);
    }

    /**
     * Get client IP from ServerHttpRequest with Cloudflare support
     * @param request The ServerHttpRequest
     * @return The client IP address, or "unknown" if not found
     */
    public static String getClientIp(ServerHttpRequest request) {
        if (ipResolutionCounter != null) {
            ipResolutionCounter.increment();
        }

        try {
            String cacheKey = generateCacheKey(request);
            String cachedIp = IP_CACHE.getIfPresent(cacheKey);
            if (cachedIp != null) {
                return cachedIp;
            }

            String ip = extractClientIp(request);
            if (isValidIp(ip)) {
                IP_CACHE.put(cacheKey, ip);
            }
            return ip;
        } catch (Exception e) {
            if (ipResolutionFailedCounter != null) {
                ipResolutionFailedCounter.increment();
            }
            log.error("Failed to extract client IP", e);
            return UNKNOWN;
        }
    }

    private static String extractClientIp(ServerHttpRequest request) {
        String ip = null;
        HttpHeaders headers = request.getHeaders();

        // Try each header in priority order
        for (String headerName : PRIORITY_HEADERS) {
            ip = headers.getFirst(headerName);
            if (isValidIp(ip)) {
                log.debug("Found IP {} in header: {}", ip, headerName);
                break;
            }
        }

        // Fallback to remote address if no valid IP found in headers
        if (!isValidIp(ip) && request.getRemoteAddress() != null) {
            ip = request.getRemoteAddress().getAddress().getHostAddress();
            log.debug("Using remote address: {}", ip);
        }

        // Handle X-Forwarded-For multiple IPs
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
            log.debug("Extracted first IP from multiple IPs: {}", ip);
        }

        return normalizeIp(ip);
    }

    private static boolean isValidIp(String ip) {
        if (ip == null || ip.isEmpty() || UNKNOWN.equalsIgnoreCase(ip)) {
            return false;
        }

        ip = ip.trim();
        if (ip.length() > MAX_IP_LENGTH) {
            return false;
        }

        // Check if IPv4
        if (!ip.contains(":")) {
            return IPV4_PATTERN.matcher(ip).matches();
        }

        // Check if IPv6
        return IPV6_PATTERN.matcher(ip).matches() || LOCALHOST_IPV6.equals(ip);
    }

    private static String normalizeIp(String ip) {
        if (ip == null) {
            return UNKNOWN;
        }

        // Convert localhost IPv6 to IPv4
        if (LOCALHOST_IPV6.equals(ip)) {
            return LOCALHOST_IPV4;
        }

        // Handle IPv6 address
        if (ip.contains(":")) {
            return normalizeIpv6(ip);
        }

        return ip;
    }

    private static String normalizeIpv6(String ip) {
        try {
            InetAddress inetAddress = InetAddress.getByName(ip);
            if (inetAddress instanceof Inet6Address) {
                // Handle IPv4-mapped IPv6 addresses
                if (ip.startsWith("::ffff:")) {
                    return ip.substring(7);
                }

                // Get standard format first
                String normalizedIp = inetAddress.getHostAddress()
                    .replaceAll("(^|:)(0+(:|$))", "$1$2")
                    .replaceAll("::+", ":");

                // Replace colons with underscores and remove any trailing underscore
                return "ipv6_" + normalizedIp.replace(":", "_").replaceAll("_$", "");
            }
        } catch (UnknownHostException e) {
            log.warn("Failed to normalize IPv6 address: {}", ip, e);
        }
        return ip;
    }

    private static String generateCacheKey(ServerHttpRequest request) {
        StringBuilder key = new StringBuilder();
        if (request.getRemoteAddress() != null) {
            key.append(request.getRemoteAddress().toString());
        }
        
        for (String header : PRIORITY_HEADERS) {
            String headerValue = request.getHeaders().getFirst(header);
            if (headerValue != null) {
                key.append("#").append(headerValue);
            }
        }
        
        return key.toString();
    }
}
