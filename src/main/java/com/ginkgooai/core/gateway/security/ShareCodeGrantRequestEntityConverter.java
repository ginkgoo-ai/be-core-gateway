package com.ginkgooai.core.gateway.security;

import com.ginkgooai.core.common.security.CustomGrantTypes;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.net.URI;

public class ShareCodeGrantRequestEntityConverter implements 
        Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private final OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    public ShareCodeGrantRequestEntityConverter() {
        this.defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest request) {
        ClientRegistration clientRegistration = request.getClientRegistration();
        OAuth2AuthorizationExchange authorizationExchange = request.getAuthorizationExchange();
        
        // Check if this is a guest code request
        String shareCode = (String) authorizationExchange.getAuthorizationRequest()
            .getAdditionalParameters().get("share_code");
        String resourceId = (String) authorizationExchange.getAuthorizationRequest()
                .getAdditionalParameters().get("resource_id");

        if (StringUtils.hasText(shareCode) && StringUtils.hasText(resourceId)) {
            // This is a guest code request, create custom token request
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, CustomGrantTypes.SHARE_CODE.getValue());
            parameters.add("share_code", shareCode);
            parameters.add("resource_id", resourceId);
            
            URI uri = URI.create(clientRegistration.getProviderDetails().getTokenUri());
            
            return RequestEntity
                    .post(uri)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(parameters);
        }
        
        // Fall back to default converter for standard OAuth2 flows
        return this.defaultConverter.convert(request);
    }
}
