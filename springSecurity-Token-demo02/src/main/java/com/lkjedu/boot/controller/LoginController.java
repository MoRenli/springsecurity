package com.lkjedu.boot.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Controller
public class LoginController {

    //这里根据我们Debug发现表单提交跟没走这个方法，而是走我们的SecurityConfig这类的http.formLogin()，所以这个我们也可是注释掉
//    @RequestMapping("/login")
//    public String login(){
//        System.out.println("登录");
//        return "redirect:/static/index.html";
//    }

    @PostMapping("/toIndex")
    public String toIndex(){
        return "redirect:/static/index.html";
    }
    @PostMapping("/toError")
    public String toError(){
        return "redirect:/static/error.html";
    }

//    @Secured("ROLE_aaa")
    @PreAuthorize("hasAnyRole('aaa')")
    @GetMapping("toVIP")
    public String toVIP(){
        return "redirect:/static/VIP.html";
    }
}
