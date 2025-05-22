package com.ginkgooai.core.gateway.config;

import com.ginkgooai.core.gateway.client.identity.UserClient;
import com.ginkgooai.core.gateway.filter.ShareCodeAuthenticationFilter;
import com.ginkgooai.core.gateway.filter.TokenEnabledCheckFilter;
import com.ginkgooai.core.gateway.security.ProblemDetailsAuthenticationEntryPoint;
import com.ginkgooai.core.gateway.security.ShareCodeAuthorizationRequestResolver;
import com.ginkgooai.core.gateway.security.ShareCodeGrantRequestEntityConverter;
import com.ginkgooai.core.gateway.security.ShareCodeTokenResponseClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.*;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.base-uri}")
    private String appBaseUri;

    @Value("${app.domain-name}")
    private String domainName;

    @Value("${app.api-uri}")
    private String apiBaseUri;

	@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
	private String issuerUri;

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {
		DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(
				clientRegistrationRepository, "/oauth2/authorization");

        // Enable PKCE
        // resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        return resolver;
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

	@Bean
	public TokenEnabledCheckFilter tokenEnabledCheckFilter(UserClient userClient) {
		return new TokenEnabledCheckFilter(userClient);
	}

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
			OAuth2AuthorizationRequestResolver authorizationRequestResolver,
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientService authorizedClientService, UserClient userClient) throws Exception {

		CookieCsrfTokenRepository cookieCsrfTokenRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        cookieCsrfTokenRepository.setCookieCustomizer(cookie -> cookie.domain(domainName));
		CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);

        ShareCodeTokenResponseClient tokenResponseClient = new ShareCodeTokenResponseClient();

        ShareCodeAuthenticationFilter shareCodeFilter = new ShareCodeAuthenticationFilter(
				clientRegistrationRepository, authorizedClientService, tokenResponseClient, "ginkgoo-web-client",
				appBaseUri);

		// Create token enabled check filter to verify if user accounts are enabled
		TokenEnabledCheckFilter tokenEnabledCheckFilter = new TokenEnabledCheckFilter(userClient);

		http.cors(Customizer.withDefaults())
			.csrf(csrf -> csrf.disable())
                // .csrf(csrf ->
                // csrf
                // .csrfTokenRepository(cookieCsrfTokenRepository)
                // .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                // .ignoringRequestMatchers("/logout")
                // )
                .authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/health", "/login", "/error",
                                // Swagger
						"/swagger-ui/**", "/v3/api-docs/**", "/api/messaging/webhook")
				.permitAll()
				.requestMatchers("/api/oauth2/guest")
				.permitAll() // Allow guest
								// code entry
                        .anyRequest().authenticated())
                .sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.maximumSessions(1)
				.sessionRegistry(sessionRegistry())
				.maxSessionsPreventsLogin(false))
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(new ProblemDetailsAuthenticationEntryPoint())
                        .accessDeniedHandler(new ProblemDetailsAuthenticationEntryPoint()))
			.oauth2Login(oauth2Login -> oauth2Login.loginPage("/login")
				.authorizationEndpoint(authorization -> authorization
					.authorizationRequestResolver(new ShareCodeAuthorizationRequestResolver(
                                                clientRegistrationRepository,
							"/oauth2/authorization", "ginkgoo-web-client"))

                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseClient(accessTokenResponseClient()))
				.successHandler(new SimpleUrlAuthenticationSuccessHandler("/authorized"))
				.failureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error=true")))
			.logout(logout -> logout.logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler(cookieCsrfTokenRepository))
                        // .logoutSuccessHandler(new
                        // HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                        .logoutSuccessHandler(
                                oidcLogoutSuccessHandler(clientRegistrationRepository))
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID")
				.deleteCookies("SESSION")
				.clearAuthentication(true))
			.oauth2Client(oauth2Client -> oauth2Client.authorizationCodeGrant(
					codeGrant -> codeGrant.authorizationRequestResolver(authorizationRequestResolver)
						.authorizationRequestRepository(authorizationRequestRepository())))
			.oauth2ResourceServer(
					oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
			.addFilterBefore(shareCodeFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterAfter(tokenEnabledCheckFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

	@Bean
	public JwtDecoder jwtDecoder() {
		return JwtDecoders.fromIssuerLocation(issuerUri);
	}

	public JwtAuthenticationConverter jwtAuthenticationConverter() {
		JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();

		jwtConverter.setPrincipalClaimName("email");
		jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			List<String> roles = getClaimAsList(jwt, "role");
			if (roles != null) {
				for (String role : roles) {
					authorities.add(new SimpleGrantedAuthority(role.toUpperCase()));
				}
			}

			List<String> scopes = getClaimAsList(jwt, "scope");
			if (scopes != null) {
				for (String scope : scopes) {
					authorities.add(new SimpleGrantedAuthority(scope));
				}
			}

			return authorities;
		});

		return jwtConverter;
	}

	private List<String> getClaimAsList(Jwt jwt, String claimName) {
		Object claimValue = jwt.getClaim(claimName);

		if (claimValue == null) {
			return null;
		}

		if (claimValue instanceof List) {
			return (List<String>) claimValue;
		}

		if (claimValue instanceof String) {
			return List.of(((String) claimValue).split(" "));
		}

		return null;
	}

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
		DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();
        client.setRequestEntityConverter(new ShareCodeGrantRequestEntityConverter());
        return client;
    }

    private AuthenticationEntryPoint authenticationEntryPoint() {
		AuthenticationEntryPoint authenticationEntryPoint = new LoginUrlAuthenticationEntryPoint(
				"/oauth2/authorization/ginkgoo-web-client");
        MediaTypeRequestMatcher textHtmlMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
        textHtmlMatcher.setUseEquals(true);

        LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
        entryPoints.put(textHtmlMatcher, authenticationEntryPoint);

		DelegatingAuthenticationEntryPoint delegatingAuthenticationEntryPoint = new DelegatingAuthenticationEntryPoint(
				entryPoints);
		delegatingAuthenticationEntryPoint.setDefaultEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
        return delegatingAuthenticationEntryPoint;
    }

    private LogoutHandler logoutHandler(CsrfTokenRepository csrfTokenRepository) {
		return new CompositeLogoutHandler(new SecurityContextLogoutHandler(),
                new CsrfLogoutHandler(csrfTokenRepository));
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository) {
		OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
				clientRegistrationRepository);

        oidcLogoutSuccessHandler.setPostLogoutRedirectUri(URI.create(apiBaseUri).toString());

        return oidcLogoutSuccessHandler;
    }
}
