package com.lkjedu.boot;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Hello world!
 *
 */
@SpringBootApplication
@MapperScan("com.lkjedu.boot.mappers")
public class ApplicationSpringSecurity {
    public static void main( String[] args ) {
        SpringApplication.run(ApplicationSpringSecurity.class,args);
    }
}
