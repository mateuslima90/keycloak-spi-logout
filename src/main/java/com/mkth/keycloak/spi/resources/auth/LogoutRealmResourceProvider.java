package com.mkth.keycloak.spi.resources.auth;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.core.Context;

public class LogoutRealmResourceProvider implements RealmResourceProvider {

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    public LogoutRealmResourceProvider() {
        ResteasyProviderFactory.getInstance().injectProperties(this);
    }


    @Override
    public Object getResource() {

        RealmModel realm = session.getContext().getRealm();
        EventBuilder event = new EventBuilder(realm, session, clientConnection);

        LogoutRealmResourceProvider endpoint = new LogoutRealmResource(session, event);

        ResteasyProviderFactory.getInstance().injectProperties(endpoint);

        return endpoint;
    }

    @Override
    public void close() { }
}
