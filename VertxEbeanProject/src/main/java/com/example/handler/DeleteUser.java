package com.example.handler;

import com.example.libs.User;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum DeleteUser implements Handler<RoutingContext>
{
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(Handler.class);
    @Override
    public void handle(RoutingContext routingContext)
    {
        Database database = DB.getDefault();
        logger.info("Handling deleteUser request");

        String email = routingContext.request().getParam("email");
        if (email == null) {
            routingContext.response()
                    .setStatusCode(400)
                    .end("Email parameter is required  "+email);
            return;
        }

        try {
            User existingUser = database.find(User.class).where().eq("email", email).findOne();
            if (existingUser == null) {
                routingContext.response()
                        .setStatusCode(404)
                        .end("User not found with email: " + email);
                return;
            }

            database.delete(existingUser);

            routingContext.response()
                    .setStatusCode(200)
                    .end("User deleted successfully");
        } catch (Exception e) {
            logger.error("Internal server error: {}", e.getMessage(), e);
            routingContext.response()
                    .setStatusCode(500)
                    .end("Internal server error: " + e.getMessage());
        }
    }
}
