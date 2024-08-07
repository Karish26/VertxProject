package com.example.controller;

import com.example.handler.*;
import io.vertx.core.AbstractVerticle;
import com.example.handler.LoginHandler;
import io.vertx.ext.web.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
public class UserController extends AbstractVerticle
{

    public static final Logger LOG = LoggerFactory.getLogger(UserController.class);


    public static void router(Router router)
    {
        LOG.info("Route attached : {}", router);
        router.get("/users").handler(GetUser.INSTANCE);
        router.post("/create").handler(CreateUser.INSTANCE);
        router.post("/update").handler(UpdateUser.INSTANCE);
        //router.get("/employee/:id").handler(GetEmployeeHandler.INSTANCE);
//        router.put("/soft-delete-employee/:id").handler(SoftDeleteEmployeeHandler.INSTANCE);
        router.delete("/delete").handler(DeleteUser.INSTANCE);
        router.post("/login").handler(LoginHandler.INSTANCE);
    }

}
