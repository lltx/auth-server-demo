package com.pig4cloud.auth.server.ext;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = -6067207202119450764L;

	private final AuthorizationGrantType authorizationGrantType;
	private final Authentication clientPrincipal;
	private final Authentication userPrincipal;
	private final Map<String, Object> additionalParameters;

	/**
	 * Constructs an {@code OAuth2ClientCredentialsAuthenticationToken} using the provided parameters.
	 *
	 * @param clientPrincipal the authenticated client principal
	 */

	public ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
			Authentication clientPrincipal, Authentication userPrincipal, @Nullable Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.authorizationGrantType = authorizationGrantType;
		this.clientPrincipal = clientPrincipal;
		this.userPrincipal = userPrincipal;
		this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
	}

	/**
	 * Returns the authorization grant type.
	 *
	 * @return the authorization grant type
	 */
	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	public Object getUserPrincipal() {
		return this.userPrincipal;
	}

	/**
	 * Returns the additional parameters.
	 *
	 * @return the additional parameters
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

}
