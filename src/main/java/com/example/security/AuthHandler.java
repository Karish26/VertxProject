package com.example.security;
import com.example.MainVerticle;
import com.example.libs.User;
import io.ebean.DB;
import io.ebean.Database;
import io.vertx.core.Handler;
import io.vertx.ext.auth.JWTOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthHandler implements Handler<RoutingContext>
{
    private static final Logger logger = LoggerFactory.getLogger(MainVerticle.class);
    private static JWTAuth jwtAuthProvider;

    public AuthHandler(JWTAuth jwtAuth) {
        this.jwtAuthProvider= jwtAuth;
    }

     public static String JWTTokenGenerator(String email)
     {
         System.out.println("JWTTokenGenerator");
         JsonObject claims  =  new JsonObject().put("sub", email);
         JWTOptions options = new JWTOptions().setExpiresInMinutes(60); // Token expiry time in minutes
         System.out.println(claims+" "+options);
         return jwtAuthProvider.generateToken(claims, options);
     }

     public static boolean authenticate(String email, String username)
     {
         System.out.println(email+" "+username);
         Database database = DB.getDefault();
         if (email == null || username == null)
         {
             throw new IllegalArgumentException("Missing required fields: name and/or email");
         }
         User existingEmail = database.find(User.class).where().eq("email", email).findOne();
         User existingName = database.find(User.class).where().eq("name", username).findOne();
         if (existingEmail == null) {
             throw new IllegalArgumentException("User not found with email: " + email);
         }
         if (existingName == null) {
             throw new IllegalArgumentException("User not found with name: " + email);
         }

         if (!existingEmail.getId().equals(existingName.getId())) {
             throw new IllegalArgumentException("Email and username do not correspond to the same user");
         }
         return true;
     }
    @Override
    public void handle(RoutingContext rc)
    {
        logger.info("Login Handler");
        Database database = DB.getDefault();
        try
        {
            JsonObject user = rc.getBodyAsJson();
            String name = user.getString("name");
            String email = user.getString("email");

            System.out.println(name+" "+email);
            boolean authenticated = authenticate(email, name);
            System.out.println(authenticated);
            if (authenticated)
            {
                System.out.println(authenticated);
                String token = JWTTokenGenerator(email);
                System.out.println("Token :: " + token);
                JsonObject response = new JsonObject().put("token", token);
                rc.response()
                        .putHeader("content-type", "application/json")
                        .end(response.encodePrettily());
            } else {
                rc.response()
                        .setStatusCode(401)
                        .end("Authentication failed");
            }
        }
        catch (Exception e)
        {
            logger.error("Error in login handler", e);
            rc.response()
                    .setStatusCode(500)
                    .end("HII   ");
        }

    }
}
