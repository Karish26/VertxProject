package com.example.handler;

import io.vertx.core.Handler;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import io.ebean.Database;
import io.ebean.DB;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.example.libs.User; // Ensure this import matches your User class package



public enum CreateUser implements Handler<RoutingContext> {
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(Handler.class);
    @Override
    public void handle(RoutingContext routingContext) {
        Database database = DB.getDefault();
        logger.info("Handling createUser request");

        // Log request headers and body for debugging
        logger.info("Request headers: {}", routingContext.request().headers());

        try {

            JsonObject jsonObject = routingContext.body().asJsonObject();


            System.out.printf("JSON ::" + jsonObject);

//            JsonObject jsonObject = body.asJsonObject();

//            System.out.printf("Create USER :: " + jsonObject);

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


    @Data
    @EqualsAndHashCode(callSuper = false)
    class UserRequest{

        private String email;

        private String name;

    }
}
