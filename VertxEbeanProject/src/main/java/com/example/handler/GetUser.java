package com.example.handler;

import com.example.libs.User;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public enum GetUser implements Handler<RoutingContext>
{
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(Handler.class);
    @Override
    public void handle(RoutingContext routingContext)
    {
        Database database = DB.getDefault();
        logger.info("Handling getAllUsers request");

        try {
            List<User> users = database.find(User.class).findList();
            JsonArray jsonUsers = new JsonArray();
            for (User user : users) {
                jsonUsers.add(new JsonObject()
                        .put("name", user.getName())
                        .put("email", user.getEmail()));
            }

            routingContext.response()
                    .setStatusCode(200)
                    .putHeader("Content-Type", "application/json")
                    .end(jsonUsers.encodePrettily());
        } catch (Exception e) {
            logger.error("Internal server error: {}", e.getMessage(), e);
            routingContext.response()
                    .setStatusCode(500)
                    .end("Internal server error: " + e.getMessage());
        }
    }
}