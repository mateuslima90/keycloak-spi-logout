package com.mkth.keycloak.spi.resources.auth;

import org.jboss.logging.Logger;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.AuthorizeClientUtil;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.resources.Cors;
import org.keycloak.services.util.MtlsHoKTokenUtil;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.core.*;


public class LogoutRealmResource extends LogoutRealmResourceProvider {

    private static final Logger logger = Logger.getLogger(LogoutRealmResource.class);

    private KeycloakSession session;

    @Context
    private ClientConnection clientConnection;

    @Context
    private HttpRequest request;

    @Context
    private HttpHeaders headers;

    private final RealmModel realm;

    private final TokenService tokenService;

    private EventBuilder event;

    private Cors cors;

    public LogoutRealmResource(final KeycloakSession session,
                          final EventBuilder event) {
        this.session = session;
        this.event = event;
        this.realm = session.getContext().getRealm();
        this.tokenService = new TokenService(session, realm);
    }

    /**
     * Logout a session via a non-browser invocation.  Similar signature to refresh token except there is no grant_type.
     * You must pass in the refresh token and
     * authenticate the client if it is not public.
     *
     * If the client is a confidential client
     * you must include the client-id and secret in an Basic Auth Authorization header.
     *
     * If the client is a public client, then you must include a "client_id" form parameter.
     *
     * returns 204 if successful, 400 if not with a json error response.
     *
     * @return
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response logoutToken() {
        MultivaluedMap<String, String> form = request.getDecodedFormParameters();
        checkSsl();

        event.event(EventType.LOGOUT);

        ClientModel client = authorizeClient();
        String accessToken = form.getFirst(OAuth2Constants.ACCESS_TOKEN);

        if (accessToken == null) {
            event.error(Errors.INVALID_TOKEN);
            throw new ErrorResponseException(OAuthErrorException.INVALID_REQUEST, "No Access Token", Response.Status.BAD_REQUEST);
        }

        AccessToken token = null;
        try {

            token = tokenService.verifyAndParseToken(accessToken, AccessToken.class);

            boolean offline = TokenUtil.TOKEN_TYPE_OFFLINE.equals(token.getType());

            UserSessionModel userSessionModel;
            if (offline) {
                UserSessionManager sessionManager = new UserSessionManager(session);
                userSessionModel = sessionManager.findOfflineUserSession(realm, token.getSessionState());
            } else {
                userSessionModel = session.sessions().getUserSession(realm, token.getSessionState());
            }

            if (userSessionModel != null) {
                checkTokenIssuedAt(token, userSessionModel);
                logout(userSessionModel, offline);
            }
        } catch (OAuthErrorException e) {
            // KEYCLOAK-6771 Certificate Bound Token
            if (MtlsHoKTokenUtil.CERT_VERIFY_ERROR_DESC.equals(e.getDescription())) {
                event.error(Errors.NOT_ALLOWED);
                throw new ErrorResponseException(e.getError(), e.getDescription(), Response.Status.UNAUTHORIZED);
            } else {
                event.error(Errors.INVALID_TOKEN);
                throw new ErrorResponseException(e.getError(), e.getDescription(), Response.Status.BAD_REQUEST);
            }
        } catch (VerificationException e) {
            e.printStackTrace();
        }

        return Cors.add(request, Response.noContent()).auth().allowedOrigins(session, client).allowedMethods("POST").exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS).build();
    }

    private void logout(UserSessionModel userSession, boolean offline) {
        AuthenticationManager.backchannelLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, true, offline);
        event.user(userSession.getUser()).session(userSession).success();
    }

    private ClientModel authorizeClient() {
        ClientModel client = AuthorizeClientUtil.authorizeClient(session, event).getClient();

        if (client.isBearerOnly()) {
            throw new ErrorResponseException(Errors.INVALID_CLIENT, "Bearer-only not allowed", Response.Status.BAD_REQUEST);
        }

        return client;
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https") && realm.getSslRequired().isRequired(clientConnection)) {
            throw new ErrorResponseException("invalid_request", "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    private void checkTokenIssuedAt(IDToken token, UserSessionModel userSession) throws OAuthErrorException {
        if (token.getIssuedAt() + 1 < userSession.getStarted()) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Refresh toked issued before the user session started");
        }
    }

    private Response initiateBrowserLogout(UserSessionModel userSession, String redirect, String state, String initiatingIdp ) {
        if (redirect != null) userSession.setNote(OIDCLoginProtocol.LOGOUT_REDIRECT_URI, redirect);
        if (state != null) userSession.setNote(OIDCLoginProtocol.LOGOUT_STATE_PARAM, state);
        userSession.setNote(AuthenticationManager.KEYCLOAK_LOGOUT_PROTOCOL, OIDCLoginProtocol.LOGIN_PROTOCOL);
        logger.debug("Initiating OIDC browser logout");
        Response response =  AuthenticationManager.browserLogout(session, realm, userSession, session.getContext().getUri(), clientConnection, headers, initiatingIdp);
        logger.debug("finishing OIDC browser logout");
        return response;
    }
}
