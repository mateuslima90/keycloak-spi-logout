package com.mkth.keycloak.spi.resources.auth;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class LogoutRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "mkth-logout";


    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new LogoutRealmResourceProvider();
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
