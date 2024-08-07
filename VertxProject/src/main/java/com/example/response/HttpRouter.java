package com.example.response;

import com.example.config.BrokerConfig;
import com.example.config.ConfigLoader;
import com.example.controller.UserController;
import com.example.datasource.ProjectConfiguration;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.Promise;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HttpRouter extends AbstractVerticle {

    private static final Logger LOG = LoggerFactory.getLogger(HttpRouter.class);

    @Override
    public void start(Promise<Void> startPromise) throws Exception {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        ConfigLoader.load(vertx)
                .onFailure(startPromise::fail)
                .onSuccess(
                        configuration ->{
                            LOG.info("Retrieved configuration : {} " , configuration);
                            handleRoutes(startPromise,configuration, router);
                        });

    }

    public void handleRoutes(Promise<Void> startPromise, BrokerConfig config, Router router)
    {
        UserController.router(router);

        vertx.createHttpServer().requestHandler(router)
                .exceptionHandler(error -> {
                    LOG.error("HTTP server error: ", error.getCause());
                })
                .listen(config.getServerPort(), http -> {
                    if(http.succeeded()){
                        startPromise.complete();
//                        Database database = DB.getDefault();
                        ProjectConfiguration.setup();
                        LOG.info("HTTP server started on port {} ", config.getServerPort());
                    }else startPromise.fail(http.cause());
                });
    }
}