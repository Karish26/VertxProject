package com.example.security;

import io.vertx.core.Vertx;
import io.vertx.ext.auth.PubSecKeyOptions;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;

public class AuthProvider
{
    public static JWTAuth createJwtAuthProvider(Vertx vertx)
    {
        JWTAuthOptions config = jwtAuthOptions();
        JWTAuth provider = JWTAuth.create(vertx, config);
        return provider;
    }

    public static JWTAuthOptions jwtAuthOptions()
    {
        return new JWTAuthOptions()
                .addPubSecKey(new PubSecKeyOptions()
                        .setAlgorithm("HS256") // Algorithm used for signing the tokens
                        .setBuffer("karishma")); // Replace with your actual secret key
    }
}