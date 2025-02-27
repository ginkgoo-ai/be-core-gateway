package com.ginkgooai.core.gateway.handler;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.cloud.gateway.server.mvc.common.MvcUtils;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.multipart.MultipartHttpServletRequest;
import org.springframework.web.multipart.support.StandardMultipartHttpServletRequest;
import org.springframework.web.multipart.support.StandardServletMultipartResolver;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * This class is a custom class because {@link org.springframework.cloud.gateway.server.mvc.handler.GatewayMvcMultipartResolver}
 * still has bug on query parameter
 *
 * @see org.springframework.cloud.gateway.server.mvc.handler.GatewayMvcMultipartResolver
 */

@Component
public class CustomMultipartResolver extends StandardServletMultipartResolver {

    @Override
    public boolean isMultipart(HttpServletRequest request) {
        return super.isMultipart(request);
    }

    @Override
    public MultipartHttpServletRequest resolveMultipart(HttpServletRequest request) throws MultipartException {
        String queryString = request.getQueryString();
        StringBuffer requestURL = request.getRequestURL();
        if (StringUtils.hasText(queryString)) {
            requestURL.append('?').append(queryString);
        }
        UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(requestURL.toString());
        MultiValueMap<String, String> queryParams = uriComponentsBuilder.build().getQueryParams();

        return new CustomMultipartResolver.GatewayMultipartHttpServletRequest(request, queryParams);
    }

    private static boolean isGatewayRequest(HttpServletRequest request) {
        return request.getAttribute(MvcUtils.GATEWAY_ROUTE_ID_ATTR) != null
                || request.getAttribute(MvcUtils.GATEWAY_REQUEST_URL_ATTR) != null;
    }

    /**
     * StandardMultipartHttpServletRequest wrapper that will not parse multipart if it is
     * a gateway request. A gateway request has certain request attributes set.
     */
    static class GatewayMultipartHttpServletRequest extends StandardMultipartHttpServletRequest {

        private final MultiValueMap<String, String> queryParams;

        GatewayMultipartHttpServletRequest(HttpServletRequest request, MultiValueMap<String, String> queryParams) {
            super(request, true);
            this.queryParams = queryParams;
        }

        @Override
        protected void initializeMultipart() {
            if (!isGatewayRequest(getRequest())) {
                super.initializeMultipart();
            }
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            if (isGatewayRequest(getRequest())) {
                return getQueryParameterMap();
            }
            return super.getParameterMap();
        }

        private Map<String, String[]> getQueryParameterMap() {
            Map<String, String[]> result = new LinkedHashMap<>();
            Enumeration<String> names = getParameterNames();
            while (names.hasMoreElements()) {
                String name = names.nextElement();
                result.put(name, getParameterValues(name));
            }
            return result;
        }

        @Override
        public String getParameter(String name) {
            return this.queryParams.getFirst(name);
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(this.queryParams.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            return StringUtils.toStringArray(this.queryParams.get(name));
        }

    }
}
