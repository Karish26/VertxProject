package com.example.response;

import com.example.config.ConfigLoader;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class MainVerticle extends AbstractVerticle
{

    public static final Logger LOG = LoggerFactory.getLogger(MainVerticle.class);

    public static final int numberOfInstances = Runtime.getRuntime().availableProcessors() / 2;

    @Override
    public void start(Promise<Void> startPromise) throws Exception
    {
        System.setProperty(ConfigLoader.SERVER_PORT, "8888");
        vertx.deployVerticle(HttpRouter.class.getName(), new DeploymentOptions().setInstances(numberOfInstances))
                .onFailure(startPromise::fail)
                .onSuccess(e -> {
                    LOG.info("{} Deployed with id {}", HttpRouter.class.getName(), e);
                    startPromise.complete();
                });
    }
}
