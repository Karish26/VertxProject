package com.example;

import com.example.libs.User;
import io.ebean.Database;
import io.ebean.DatabaseFactory;
import io.ebean.config.DatabaseConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;

public class DBConfig {

    private static final Logger logger = LoggerFactory.getLogger(DBConfig.class);

    public static Database setup() {
        DatabaseConfig config = new DatabaseConfig();
        Properties properties = new Properties();
        properties.put("datasource.db.username", "root");
        properties.put("datasource.db.password", "1510");
        properties.put("datasource.db.databaseUrl", "jdbc:mysql://localhost:3306/cruddbvertex");
        properties.put("datasource.db.databaseDriver", "com.mysql.cj.jdbc.Driver");

        config.setDefaultServer(true);
        config.setDdlCreateOnly(true);
        config.setDdlGenerate(true);
        config.setDdlRun(true);
        config.loadFromProperties(properties);
        config.addPackage("com.example.libs");
        return DatabaseFactory.create(config);

    }

}