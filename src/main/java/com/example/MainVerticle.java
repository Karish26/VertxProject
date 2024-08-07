package com.example;

import com.example.libs.User;
import com.example.security.AuthHandler;
import com.example.security.AuthProvider;
import io.vertx.core.AbstractVerticle;
import io.vertx.core.json.JsonObject;
import io.vertx.core.json.JsonArray;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.RequestBody;
import io.vertx.ext.web.Router;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.JWTAuthHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.vertx.core.json.DecodeException;
import java.util.*;
import io.vertx.ext.auth.jwt.JWTAuth;


public class MainVerticle extends AbstractVerticle
{
    JWTAuthOptions config = new JWTAuthOptions();
    JWTAuth provider = JWTAuth.create(vertx, config);

    private static final Logger logger = LoggerFactory.getLogger(MainVerticle.class);

    private void createUser(RoutingContext routingContext) {
        Database database = DB.getDefault();
        logger.info("Handling createUser request");

        // Log request headers and body for debugging
        logger.info("Request headers: {}", routingContext.request().headers());
        logger.info("Request body as string: {}", routingContext.getBodyAsString());

        try {

            RequestBody body = routingContext.body();
            System.out.printf("Request body: %s\n", body);

            System.out.printf("JSON ::" + body.asJsonObject());

            JsonObject jsonObject = body.asJsonObject();

            System.out.printf("Create USER :: " + jsonObject);

            // Karishma to handle for email
//
            User user = new User();
            user.setName(jsonObject.getString("name"));
            user.setEmail(jsonObject.getString("email"));

            database.save(user);
            System.out.println(user.getEmail());

            routingContext.response()
                    .setStatusCode(201)
                    .end("User created successfully");
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
            e.printStackTrace();
            // Handle other exceptions such as database errors
            logger.error("Internal server error: {}", e.getMessage(), e);
            routingContext.response()
                    .setStatusCode(500)
                    .end("Internal server error: " + e.getMessage());
        }
    }

    private void updateUser(RoutingContext routingContext) {
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

    private void getAllUsers(RoutingContext routingContext)
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

    private void deleteUser(RoutingContext routingContext) {
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
    @Override
    public void start() {

        Router router = Router.router(vertx);
//        router.route().handler(BodyHandler.create()); // Enable BodyHandler

        router.route().handler(BodyHandler.create())
                .failureHandler(error -> {
                    if(error.response().ended()){
                        return;
                    }
                    error.response()
                            .setStatusCode(500)
                            .end(new JsonObject().put("message", "Something went Wrong").toBuffer());
                });
        router.post("/api/create").handler(this::createUser);
        router.post("/api/update").handler(this::updateUser);
        router.get("/api/users").handler(this::getAllUsers);
        router.delete("/api/delete").handler(this::deleteUser);
        router.post("/login").handler(new AuthHandler(provider));
//        router.post("/api/*").handler();
        vertx.createHttpServer().requestHandler(router).listen(8888, http -> {
            if (http.succeeded()) {
                logger.info("HTTP server started on port 8888");
                //System.out.println("HTTP server started on port 8888");
                Database setup = DBConfig.setup();
                System.out.printf("Database setup successfully" + setup.toString());
            } else {
                logger.error("HTTP server failed to start", http.cause());
            }
        });

        router.get("/health").handler(event -> {
            event.response().end("OK");
        });

        String username = "karishma";
    }
}
