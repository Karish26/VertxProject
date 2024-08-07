import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar
import org.gradle.api.tasks.testing.logging.TestLogEvent.*

plugins {
    java
    application
    id("com.github.johnrengelman.shadow") version "7.1.2"
    id("io.ebean") version "12.12.1"
}

group = "com.example"
version = "1.0.0-SNAPSHOT"

repositories {
    mavenCentral()
}


val vertxVersion = "4.0.0"
val junitJupiterVersion = "5.9.1"
val vertexWebVersion = "4.3.8"
val ebeanVersion = "12.12.1"
val queryBeanVersion = "12.12.1"
val mysqlConnectorVersion = "8.0.28"
val hikariCPVersion = "4.0.3"

val jjwt_Api ="0.11.5"
val jjwt_IMPL = "0.11.5"
val jwtauth="4.3.3"
val vertexauthjwt = "4.3.4"
val vertexauthcommon = "4.3.4"


val mainVerticleName = "com.example.response.MainVerticle"
val launcherClassName = "io.vertx.core.Launcher"

val watchForChange = "src/*/"
val doOnChange = "${projectDir}/gradlew classes"

application {
    mainClass.set(launcherClassName)
}

dependencies {
    implementation(platform("io.vertx:vertx-stack-depchain:$vertxVersion"))
    implementation("io.vertx:vertx-core")
    testImplementation("io.vertx:vertx-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitJupiterVersion")
    implementation("io.vertx:vertx-sql-client-templates")
    implementation("io.vertx:vertx-mysql-client")
    implementation("io.vertx:vertx-web:$vertexWebVersion")
    implementation("io.ebean:ebean:$ebeanVersion")
    implementation("io.ebean:ebean-querybean:$queryBeanVersion")
    implementation("mysql:mysql-connector-java:$mysqlConnectorVersion")
    implementation ("com.zaxxer:HikariCP:$hikariCPVersion")
    // https://mvnrepository.com/artifact/org.projectlombok/lombok
    implementation("org.projectlombok:lombok:1.18.22")
    implementation ("io.vertx:vertx-auth-jwt:$vertxVersion")
    implementation ("io.vertx:vertx-auth-common:$vertxVersion")
    // https://mvnrepository.com/artifact/io.ebean/ebean-test
    testImplementation("io.ebean:ebean-test:$ebeanVersion")
    // SLF4J for logging
    implementation ("org.slf4j:slf4j-api:1.7.30")
    implementation ("org.slf4j:slf4j-simple:1.7.30")

    testImplementation("io.ebean:ebean-test:12.12.1")

    implementation ("io.vertx:vertx-auth-jwt:$jwtauth")
    implementation ("io.vertx:vertx-auth-common:$vertexauthcommon")
    runtimeOnly ("io.ebean:ebean-agent:$ebeanVersion")
    implementation ("ch.qos.logback:logback-classic:1.3.1")
    implementation ("io.vertx:vertx-config:4.3.3")

    implementation("io.vertx:vertx-config-yaml:4.3.3")

}

tasks.withType<ShadowJar> {
    archiveClassifier.set("fat")
    manifest {
        attributes(mapOf("MainVerticle" to mainVerticleName))
    }
    mergeServiceFiles()
}

tasks.withType<Test> {
    useJUnitPlatform()
    testLogging {
        events = setOf(PASSED, SKIPPED, FAILED)
    }
}



tasks.withType<JavaExec> {
    args = listOf("run", mainVerticleName, "--redeploy=$watchForChange", "--launcher-class=$launcherClassName", "--on-redeploy=$doOnChange")
}