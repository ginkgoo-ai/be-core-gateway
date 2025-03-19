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
public class GuestCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
    
    private static final AuthorizationGrantType GUEST_CODE_GRANT_TYPE = CustomGrantTypes.GUEST_CODE;
    
    private final String guestCode;
    private final String resourceId;
    private final Map<String, Object> additionalParameters;

    /**
     * Constructs a {@code GuestCodeGrantRequest}.
     * @param clientRegistration the client registration
     * @param guestCode the guest code
     * @param resourceId the resource ID
     */
    public GuestCodeGrantRequest(ClientRegistration clientRegistration, 
                                 String guestCode, 
                                 String resourceId) {
        this(clientRegistration, guestCode, resourceId, new HashMap<>());
    }

    /**
     * Constructs a {@code GuestCodeGrantRequest} with additional parameters.
     * @param clientRegistration the client registration
     * @param guestCode the guest code
     * @param resourceId the resource ID
     * @param additionalParameters the additional parameters
     */
    public GuestCodeGrantRequest(ClientRegistration clientRegistration, 
                                 String guestCode, 
                                 String resourceId,
                                 Map<String, Object> additionalParameters) {
        super(GUEST_CODE_GRANT_TYPE, clientRegistration);
        Assert.hasText(guestCode, "guestCode cannot be empty");
        Assert.hasText(resourceId, "resourceId cannot be empty");
        this.guestCode = guestCode;
        this.resourceId = resourceId;
        this.additionalParameters = additionalParameters != null ? 
                new HashMap<>(additionalParameters) : new HashMap<>();
    }

    /**
     * Returns the guest code.
     * @return the guest code
     */
    public String getGuestCode() {
        return this.guestCode;
    }

    /**
     * Returns the resource ID.
     * @return the resource ID
     */
    public String getResourceId() {
        return this.resourceId;
    }

    /**
     * Returns the additional parameters.
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
