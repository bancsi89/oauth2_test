package com.networknt.oauth.token;

import com.networknt.health.HealthGetHandler;
import com.networknt.info.ServerInfoGetHandler;
import com.networknt.oauth.token.handler.Oauth2DerefGetHandler;
import com.networknt.oauth.token.handler.Oauth2SigningPostHandler;
import com.networknt.oauth.token.handler.Oauth2TokenPostHandler;
import com.networknt.handler.HandlerProvider;
import io.undertow.Handlers;
import io.undertow.server.HttpHandler;
import io.undertow.util.Methods;

public class PathHandlerProvider implements HandlerProvider {
    @Override
    public HttpHandler getHandler() {
        HttpHandler handler = Handlers.routing()
            .add(Methods.GET, "/health", new HealthGetHandler())
            .add(Methods.GET, "/server/info", new ServerInfoGetHandler())
            .add(Methods.POST, "/oauth2/token", new Oauth2TokenPostHandler())
            .add(Methods.GET, "/oauth2/deref/{token}", new Oauth2DerefGetHandler())
            .add(Methods.POST, "/oauth2/signing", new Oauth2SigningPostHandler())
        ;
        return handler;
    }
}

