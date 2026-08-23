plugins {
    id("java")
    id("com.gradleup.shadow")
}

dependencies {
    implementation("it.unimi.dsi:fastutil:8.5.18")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}

tasks {
    test {
        useJUnitPlatform()
    }

    shadowJar {
        minimize()
    }
}
