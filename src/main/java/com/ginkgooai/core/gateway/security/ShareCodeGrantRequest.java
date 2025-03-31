package com.ginkgooai.core.gateway.security;

import com.ginkgooai.core.common.security.CustomGrantTypes;
import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.Map;

/**
 * A request for a guest code grant.
 */
public class ShareCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {

    private static final AuthorizationGrantType GRANT_TYPE = CustomGrantTypes.SHARE_CODE;

    private final String shareCode;
    private final Map<String, Object> additionalParameters;

    /**
     * Constructs a {@code ShareCodeGrantRequest}.
     * @param clientRegistration the client registration
     * @param shareCode the guest code
     */
    public ShareCodeGrantRequest(ClientRegistration clientRegistration,
                                 String shareCode) {
        this(clientRegistration, shareCode, new HashMap<>());
    }

    /**
     * Constructs a {@code ShareCodeGrantRequest} with additional parameters.
     * @param clientRegistration the client registration
     * @param shareCode the guest code
     * @param additionalParameters the additional parameters
     */
    public ShareCodeGrantRequest(ClientRegistration clientRegistration,
                                 String shareCode,
                                 Map<String, Object> additionalParameters) {
        super(GRANT_TYPE, clientRegistration);
        Assert.hasText(shareCode, "shareCode cannot be empty");
        this.shareCode = shareCode;
        this.additionalParameters = additionalParameters != null ? 
                new HashMap<>(additionalParameters) : new HashMap<>();
    }

    /**
     * Returns the guest code.
     * @return the guest code
     */
    public String getShareCode() {
        return this.shareCode;
    }


    /**
     * Returns the additional parameters.
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
