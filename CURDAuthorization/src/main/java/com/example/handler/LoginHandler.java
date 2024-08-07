package com.example.handler;

import com.example.response.MainVerticle;
import com.example.libs.User;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public enum LoginHandler implements Handler<RoutingContext>
{
    INSTANCE;
    private static final Logger logger = LoggerFactory.getLogger(MainVerticle.class);
    public String generateJWTToken(String userName, JWTAuth provider) {
        String token = null;
        try {
            token = provider.generateToken(
                    new JsonObject().put("sub", userName), new JWTOptions());

        } catch (Exception e) {
            logger.error("Error in generating token : {}", e.getMessage());
        }
        return token;
    }


    public void handle(RoutingContext rc, Vertx vertx) {
        logger.info("Login Handler");
        try {
            JWTAuthOptions config = new JWTAuthOptions()
                    .addPubSecKey(new PubSecKeyOptions()
                            .setAlgorithm("HS256") // Algorithm used for signing the tokens
                            .setBuffer("karishma"));

            JWTAuth provider = JWTAuth.create(vertx, config);
            JsonObject user = rc.getBodyAsJson();
            String name = user.getString("name");
            String email = user.getString("email");
            System.out.println(name + " " + email);
            boolean authenticated = authenticate(email, name);
            System.out.println(authenticated);
            if (authenticated) {
                String token = generateJWTToken(email, provider);
                System.out.println("Token :: " + token);
                JsonObject response = new JsonObject().put("token", token);
                rc.response()
                        .putHeader("content-type", "application/json")
                        .end(response.encodePrettily());
            }
            else
            {
                rc.response()
                        .setStatusCode(401)
                        .end("Authentication failed");
            }
        } catch (Exception e)
        {
            logger.error("Error in login handler", e);
            rc.response()
                    .setStatusCode(500)
                    .end("Internal Server Error");
        }
    }

    @Override
    public void handle(RoutingContext rc)
    {
        Vertx vertx = Vertx.vertx();
        handle(rc, vertx);
    }

    private static boolean authenticate(String email, String username) {
        System.out.println(email + " " + username);
        Database database = DB.getDefault();
        if (email == null || username == null) {
            System.out.println("1");
            throw new IllegalArgumentException("Missing required fields: name and/or email");
        }
        User existingEmail = database.find(User.class).where().eq("email", email).findOne();
        User existingName = database.find(User.class).where().eq("name", username).findOne();
        if (existingEmail == null) {
            System.out.println("2");
            throw new IllegalArgumentException("User not found with email: " + email);
        }
        if (existingName == null) {
            System.out.println("3");
            throw new IllegalArgumentException("User not found with name: " + username);
        }

        if (!existingEmail.getId().equals(existingName.getId())) {
            System.out.println("4");
            throw new IllegalArgumentException("Email and username do not correspond to the same user");
        }
        System.out.println("This is working fine");
        return true;
    }
}
