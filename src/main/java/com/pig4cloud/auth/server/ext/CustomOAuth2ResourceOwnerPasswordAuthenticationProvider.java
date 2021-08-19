package com.pig4cloud.auth.server.ext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.util.Assert;

import java.util.Set;

public class CustomOAuth2ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

	private static final Logger LOGGER = LogManager.getLogger(CustomOAuth2ResourceOwnerPasswordAuthenticationProvider.class);

	private final OAuth2AuthorizationService authorizationService;
	private final JwtEncoder jwtEncoder;
	private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = (context) -> {};
	private ProviderSettings providerSettings;
	private UserDetailsService detailsService;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationProvider} using the provided parameters.
	 *  @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 * @param userDetailsService
	 */
	public CustomOAuth2ResourceOwnerPasswordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
	                                                               JwtEncoder jwtEncoder, UserDetailsService userDetailsService) {
		this.authorizationService = authorizationService;
		this.jwtEncoder = jwtEncoder;
		this.detailsService = userDetailsService;
	}

	public final void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	@Autowired(required = false)
	public void setProviderSettings(ProviderSettings providerSettings) {
		this.providerSettings = providerSettings;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		ResourceOwnerPasswordAuthenticationToken resouceOwnerPasswordAuthentication = (ResourceOwnerPasswordAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(resouceOwnerPasswordAuthentication);

		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT));
		}

		UserDetails user = null;
		try {
			user = detailsService.loadUserByUsername("lengleng");
		} catch (Exception ex) {
			LOGGER.error("problem in authenticate", ex);
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR), ex);
		}

		Set<String> authorizedScopes = registeredClient.getScopes();		// Default to configured scopes
		/**
		if (!CollectionUtils.isEmpty(resouceOwnerPasswordAuthentication.getScopes())) {
			Set<String> unauthorizedScopes = resouceOwnerPasswordAuthentication.getScopes().stream()
					.filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
					.collect(Collectors.toSet());
			if (!CollectionUtils.isEmpty(unauthorizedScopes)) {
				throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE));
			}
			authorizedScopes = new LinkedHashSet<>(resouceOwnerPasswordAuthentication.getScopes());
		}
		*/
		String issuer = this.providerSettings != null ? this.providerSettings.getIssuer() : null;

		JoseHeader.Builder headersBuilder = JwtUtils.headers();
		JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
				registeredClient, issuer, clientPrincipal.getName(), authorizedScopes);

		// @formatter:off
		JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizedScopes(authorizedScopes)
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrant(resouceOwnerPasswordAuthentication)
				.put("user_principal", user)
				.build();
		// @formatter:on

		this.jwtCustomizer.customize(context);

		JoseHeader headers = context.getHeaders().build();
		JwtClaimsSet claims = context.getClaims().build();
		Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
				jwtAccessToken.getExpiresAt(), authorizedScopes);

		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.token(accessToken,
						(metadata) ->
								metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims()))
				.attribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, authorizedScopes)
				.build();
		// @formatter:on

		this.authorizationService.save(authorization);

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		boolean supports = ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
		LOGGER.debug("supports authentication=" + authentication + " returning " + supports);
		return supports;
	}

	private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {

		OAuth2ClientAuthenticationToken clientPrincipal = null;

		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}

		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}

		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT));
	}

	private UsernamePasswordAuthenticationToken getAuthenticatedUsertElseThrowInvalidUser(Authentication authentication) {

		UsernamePasswordAuthenticationToken userPrincipal = null;

		if (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			userPrincipal = (UsernamePasswordAuthenticationToken) authentication.getPrincipal();
		}

		if (userPrincipal != null && userPrincipal.isAuthenticated()) {
			return userPrincipal;
		}

		String errorMessage = String.format("Invalid username: %s or password", OAuth2ParameterNames.USERNAME);
		throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, errorMessage, ""));
	}

}
