package com.example.handler;

import com.example.libs.User;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.core.Handler;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public enum UpdateUser implements Handler<RoutingContext>
{
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(Handler.class);
    @Override
    public void handle(RoutingContext routingContext)
    {
        Database database = DB.getDefault();
        logger.info("Handling updateUser request");

        // Log request headers and body for debugging
        logger.info("Request headers: {}", routingContext.request().headers());
        logger.info("Request body as string: {}", routingContext.getBodyAsString());

        try {
            JsonObject json = routingContext.getBodyAsJson();
            if (json == null) {
                throw new IllegalArgumentException("Request body is empty or not in JSON format");
            }

            logger.info("Request body as JSON: {}", json);

            String email = json.getString("email");
            String newName = json.getString("name");

            if (email == null || newName == null) {
                throw new IllegalArgumentException("Missing required fields: name and/or email");
            }

            // Fetch the user by email
            User existingUser = database.find(User.class).where().eq("email", email).findOne();
            if (existingUser == null) {
                throw new IllegalArgumentException("User not found with email: " + email);
            }

            // Update the user's name
            existingUser.setName(newName);

            // Save the updated user
            database.save(existingUser);

            // Log and respond with success
            logger.info("Updated user: {}", existingUser);
            routingContext.response()
                    .setStatusCode(200)
                    .end("User updated successfully");

        } catch (DecodeException e) {
            // Handle case where the request body is not valid JSON
            logger.error("Invalid JSON: {}", e.getMessage());
            routingContext.response()
                    .setStatusCode(400)
                    .end("Invalid JSON format: " + e.getMessage());
        } catch (IllegalArgumentException e) {
            // Handle case where JSON is invalid or missing required fields
            logger.error("Invalid input: {}", e.getMessage());
            routingContext.response()
                    .setStatusCode(400)
                    .end("Invalid input: " + e.getMessage());
        } catch (Exception e) {
            // Handle other exceptions such as database errors
            logger.error("Internal server error: {}", e.getMessage(), e);
            routingContext.response()
                    .setStatusCode(500)
                    .end("Internal server error: " + e.getMessage());
        }
    }
}