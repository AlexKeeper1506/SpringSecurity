package com.example.springsecurity.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class DataSourceConfiguration {
    @Bean
    public DataSource hikariPostgresConnection() {
        HikariConfig config = new HikariConfig("src/main/resources/hikari.properties");
        HikariDataSource dataSource = new HikariDataSource(config);
        return dataSource;
    }
}
