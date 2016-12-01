/*******************************************************************************
 * Copyright (c) 2012-2016 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package org.eclipse.che.security.oauth1;


import org.eclipse.che.api.auth.oauth.OAuthAuthorizationHeaderProvider;
import org.eclipse.che.api.core.BadRequestException;
import org.eclipse.che.api.core.ConflictException;
import org.eclipse.che.api.core.ForbiddenException;
import org.eclipse.che.api.core.NotFoundException;
import org.eclipse.che.api.core.ServerException;
import org.eclipse.che.api.core.UnauthorizedException;
import org.eclipse.che.api.core.rest.HttpJsonRequestFactory;
import org.eclipse.che.api.core.rest.shared.dto.Link;
import org.eclipse.che.dto.server.DtoFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotNull;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;


/**
 * Allow get token from OAuth service over http.
 *
 * @author Igor Vinokur
 */
public class RemoteOAuthAuthorizationHeaderProvider implements OAuthAuthorizationHeaderProvider {
    private static final Logger LOG = LoggerFactory.getLogger(RemoteOAuthAuthorizationHeaderProvider.class);

    private final String apiEndpoint;

    private final HttpJsonRequestFactory httpJsonRequestFactory;

    @Inject
    public RemoteOAuthAuthorizationHeaderProvider(@Named("che.api") String apiEndpoint, HttpJsonRequestFactory httpJsonRequestFactory) {
        this.apiEndpoint = apiEndpoint;
        this.httpJsonRequestFactory = httpJsonRequestFactory;
    }

    @Override
    public String getAuthorizationHeader(@NotNull String oauthProviderName,
                                         @NotNull String userId,
                                         @NotNull String requestMethod,
                                         @NotNull String requestUrl,
                                         @NotNull Map<String, String> requestParameters)
            throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        if (userId.isEmpty()) {
            return null;
        }
        UriBuilder ub = UriBuilder.fromUri(apiEndpoint)
                                  .path(OAuthAuthenticationService.class)
                                  .path(OAuthAuthenticationService.class, "authorization")
                                  .queryParam("oauth_provider", oauthProviderName)
                                  .queryParam("user_id", userId)
                                  .queryParam("request_method", requestMethod)
                                  .queryParam("request_url", requestUrl);
        try {
            Link getTokenLink = DtoFactory.newDto(Link.class).withHref(ub.build().toString()).withMethod("GET");
            return httpJsonRequestFactory.fromLink(getTokenLink)
                                         .request().asString();
        } catch (NotFoundException ne) {
            LOG.warn("Token not found for user {}", userId);
            return null;
        } catch (ServerException | UnauthorizedException | ForbiddenException | ConflictException | BadRequestException e) {
            LOG.warn("Exception on token retrieval, message : {}", e.getLocalizedMessage());
            return null;
        }
    }
}
