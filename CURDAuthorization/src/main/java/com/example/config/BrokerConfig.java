package com.example.config;

import io.vertx.core.json.JsonObject;

public class BrokerConfig {

    int serverPort;

    String version;

    public static BrokerConfig from(JsonObject jsonObject){
        return new BrokerConfig()
                .setServerPort(jsonObject.getInteger("SERVER_PORT"))
                .setVersion(jsonObject.getString("version"));
    }

    public int getServerPort() {
        return serverPort;
    }

    public BrokerConfig setServerPort(int serverPort) {
        this.serverPort = serverPort;
        return this;
    }

    public String getVersion() {
        return version;
    }

    public BrokerConfig setVersion(String version) {
        this.version = version;
        return this;
    }
}
