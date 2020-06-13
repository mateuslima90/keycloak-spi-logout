package com.mkth.keycloak.spi.resources.auth;

import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;

import java.net.URI;

public class TokenService {

    private KeycloakSession session;
    private RealmModel realm;


    public TokenService(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
    }

    public <T extends JsonWebToken> T verifyAndParseToken(String tokenInpout, Class<T> clazz) throws VerificationException {
        TokenVerifier<T> accessTokenVerifier = TokenVerifier.create(tokenInpout, clazz)


        //session.getContext().getUri().getBaseUri()

                .realmUrl(Urls.realmIssuer(URI.create("http://127.0.0.1:8080/auth/"), realm.getName()));

        JWSHeader header = accessTokenVerifier.getHeader();

        SignatureVerifierContext verifierContext = session.getProvider(
                SignatureProvider.class,
                header.getAlgorithm().name())
                .verifier(header.getKeyId());

        accessTokenVerifier.verifierContext(verifierContext);

        return accessTokenVerifier.verify().getToken();
    }

    public <T extends JsonWebToken> String signAndEncodeToken(T token) { return session.tokens().encode(token); }
}
