package com.lkjedu.boot.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ControllerTest {
    @RequestMapping("/")
    public String test(){
        return "成功~";
    }
    @RequestMapping("/login")
    public String login(){
        return "success";
    }
}
