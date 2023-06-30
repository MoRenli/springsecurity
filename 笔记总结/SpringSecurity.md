# SpringSecurity

# 1.SpringSecurity 框架简介

## 1.1概要

	Spring 是非常流行和成功的 Java 应用开发框架，Spring Security 正是 Spring 家族中的 成员。Spring Security 基于 Spring 框架，提供了一套 Web 应用安全性的完整解决方 案。

	正如你可能知道的关于安全方面的两个主要区域是“认证”和“授权”（或者访问控 制），一般来说，Web 应用的安全性包括用户认证（Authentication）和用户授权 （Authorization）两个部分，这两点也是 Spring Security 重要核心功能。

1. 用户认证指的是：验证某个用户是否为系统中的合法主体，也就是说用户能否访问 该系统。用户认证一般要求用户提供用户名和密码。系统通过校验用户名和密码来完成认 证过程。通俗点说就是系统认为用户是否能登录
2. 用户授权指的是验证某个用户是否有权限执行某个操作。在一个系统中，不同用户 所具有的权限是不同的。比如对一个文件来说，有的用户只能进行读取，而有的用户可以 进行修改。一般来说，系统会为不同的用户分配不同的角色，而每个角色则对应一系列的 权限。通俗点讲就是系统判断用户是否有权限去做某些事情

## 1.2 历史

	“Spring Security 开始于 2003 年年底,““spring 的 acegi 安全系统”。 起因是 Spring 开发者邮件列表中的一个问题,有人提问是否考虑提供一个基于 spring 的安全实现。

	Spring Security 以“The Acegi Secutity System for Spring” 的名字始于 2013 年晚些 时候。一个问题提交到 Spring 开发者的邮件列表，询问是否已经有考虑一个机遇 Spring  的安全性社区实现。那时候 Spring 的社区相对较小（相对现在）。实际上 Spring 自己在 2013 年只是一个存在于 ScourseForge 的项目，这个问题的回答是一个值得研究的领 域，虽然目前时间的缺乏组织了我们对它的探索。

	考虑到这一点，一个简单的安全实现建成但是并没有发布。几周后，Spring 社区的其他成 员询问了安全性，这次这个代码被发送给他们。其他几个请求也跟随而来。到 2014 年一 月大约有 20 万人使用了这个代码。这些创业者的人提出一个 SourceForge 项目加入是为 了，这是在 2004 三月正式成立。

	在早些时候，这个项目没有任何自己的验证模块，身份验证过程依赖于容器管理的安全性 和 Acegi 安全性。而不是专注于授权。开始的时候这很适合，但是越来越多的用户请求额 外的容器支持。容器特定的认证领域接口的基本限制变得清晰。还有一个相关的问题增加 新的容器的路径，这是最终用户的困惑和错误配置的常见问题。

	Acegi 安全特定的认证服务介绍。大约一年后，Acegi 安全正式成为了 Spring 框架的子项 目。1.0.0 最终版本是出版于 2006 -在超过两年半的大量生产的软件项目和数以百计的改 进和积极利用社区的贡献。

	Acegi 安全 2007 年底正式成为了 Spring 组合项目，更名为"Spring Security"。

## 1.3 同款产品对比

### 1.3.1 Spring Security

Spring 技术栈的组成部分。

​![image](assets/image-20230528162100-dyna51v.png)​

	通过提供完整可扩展的认证和授权支持保护你的应用程序。 

	https://spring.io/projects/spring-security

SpringSecurity 特点：

* 和 Spring 无缝整合。
* 全面的权限控制。
* 专门为 Web 开发而设计。

  * 旧版本不能脱离 Web 环境使用。
  * 新版本对整个框架进行了分层抽取，分成了核心模块和 Web 模块。单独 引入核心模块就可以脱离 Web 环境。
* 重量级。

### 1.3.2 Shiro

	Apache 旗下的轻量级权限控制框架。

​![image](assets/image-20230528162248-s7pzhb1.png)​

特点：

* 轻量级。Shiro 主张的理念是把复杂的事情变简单。针对对性能有更高要求 的互联网应用有更好表现。
* 通用性。

  * 好处：不局限于 Web 环境，可以脱离 Web 环境使用。
  * 缺陷：在 Web 环境下一些特定的需求需要手动编写代码定制。

	Spring Security 是 Spring 家族中的一个安全管理框架，实际上，在 Spring Boot 出现之 前，Spring Security 就已经发展了多年了，但是使用的并不多，安全管理这个领域，一直 是 Shiro 的天下。

	相对于 Shiro，在 SSM 中整合 Spring Security 都是比较麻烦的操作，所以，Spring  Security 虽然功能比 Shiro 强大，但是使用反而没有 Shiro 多（Shiro 虽然功能没有 Spring Security 多，但是对于大部分项目而言，Shiro 也够用了）。

	自从有了 Spring Boot 之后，Spring Boot 对于 Spring Security 提供了自动化配置方 案，可以使用更少的配置来使用 Spring Security。

因此，一般来说，常见的安全管理技术栈的组合是这样的：

* SSM + Shiro
* Spring Boot/Spring Cloud + Spring Security

**以上只是一个推荐的组合而已，如果单纯从技术上来说，无论怎么组合，都是可以运行 的**

## 1.4 模块划分

​![image](assets/image-20230528162452-nfg6rwc.png)​

# 2.SpringSecurity 入门案例

## 2.1 创建一个项目

​![image](assets/image-20230528162549-wgaao4k.png)​

​![image](assets/image-20230528162557-bu90lta.png)​

​![image](assets/image-20230528162604-210gy1v.png)​

​![image](assets/image-20230528162614-o36akxw.png)​

​`添加一个配置类:`​

```java
	@Configuration
	public class SecurityConfigextends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	 	http.formLogin() // 表单登录
		.and()
		 .authorizeRequests() // 认证配置
		.anyRequest() // 任何请求
		.authenticated(); // 都需要身份验证
		}
	}
```

## 运行这个项目

访问 localhost:8080

​![image](assets/image-20230528162810-0r7nvyx.png)​

默认的用户名：user

密码在项目启动的时候在控制台会打印，**注意每次启动的时候密码都回发生变化！**

​![image](assets/image-20230528162838-cyqxvah.png)​

	输入用户名，密码，这样表示可以访问了，404 表示我们没有这个控制器，但是我们可以 访问了。

​![image](assets/image-20230528162853-2nd65dp.png)​

## 2.3 权限管理中的相关概念

### 2.3.1 主体

英文单词：principa

	使用系统的用户或设备或从其他系统远程登录的用户等等。简单说就是谁使用系 统谁就是主体。

### 2.3.2 认证

英文单词：authentication

	权限管理系统确认一个主体的身份，允许主体进入系统。简单说就是“主体”证 明自己是谁。

	笼统的认为就是以前所做的登录操作。

### 2.3.3 授权

英文单词：authorization

	将操作系统的“权力”“授予”“主体”，这样主体就具备了操作系统中特定功 能的能力。

所以简单来说，授权就是给用户分配权限。

## SpringSecurity 基本原理

SpringSecurity 本质是一个过滤器链： 

从启动是可以获取到过滤器链：

```java
org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFil
ter
org.springframework.security.web.context.SecurityContextPersistenceFilter 
org.springframework.security.web.header.HeaderWriterFilter
org.springframework.security.web.csrf.CsrfFilter
org.springframework.security.web.authentication.logout.LogoutFilter 
org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter 
org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter 
org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter
org.springframework.security.web.savedrequest.RequestCacheAwareFilter
org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
org.springframework.security.web.authentication.AnonymousAuthenticationFilter 
org.springframework.security.web.session.SessionManagementFilter 
org.springframework.security.web.access.ExceptionTranslationFilter 
org.springframework.security.web.access.intercept.FilterSecurityInterceptor
```

代码底层流程：重点看三个过滤器： 

	FilterSecurityInterceptor：是一个方法级的权限过滤器, 基本位于过滤链的最底部。

​![image](assets/image-20230528163222-5pqp3dm.png)​

super.beforeInvocation(fi) 表示查看之前的 filter 是否通过。 fi.getChain().doFilter(fi.getRequest(), fi.getResponse());表示真正的调用后台的服务。

‍

ExceptionTranslationFilter：**是个异常过滤器，用来处理在认证授权过程中抛出的异常**

​![image](assets/image-20230528163300-2ymo8bs.png)​

UsernamePasswordAuthenticationFilter ：

	对/login 的 POST 请求做拦截，校验表单中用户 名，密码。

​![image](assets/image-20230528163321-hud17bo.png)​

## 2.6 UserDetailsService 接口讲解

UserDetailsService:查询数据库用户名和密码的过程

* 创建实现类继承UsernamePasswordAuthenticationFilter,重写三个方法
* 创建类实现UserDetailsService，编写查询过程，返回User对象(安全框架提供的User对象)

​![image](assets/image-20230528185503-33l7l12.png)​

	当什么也没有配置的时候，账号和密码是由 Spring Security 定义生成的。而在实际项目中 账号和密码都是从数据库中查询出来的。 所以我们要通过自定义逻辑控制认证逻辑。

	如果需要自定义逻辑时，只需要实现 UserDetailsService 接口即可。接口定义如下：

​![image](assets/image-20230528163354-icbus3c.png)​

* 返回值 UserDetails

  这个类是系统默认的用户“主体

```java
// 表示获取登录用户所有权限
Collection<? extends GrantedAuthority> getAuthorities();
// 表示获取密码
String getPassword();
// 表示获取用户名
String getUsername();
// 表示判断账户是否过期
boolean isAccountNonExpired();
// 表示判断账户是否被锁定
boolean isAccountNonLocked();
// 表示凭证{密码}是否过期
boolean isCredentialsNonExpired();
// 表示当前用户是否可用
boolean isEnabled();

```

以下是 UserDetails 实现类

​![image](assets/image-20230528163437-y7ej5rj.png)​

以后我们只需要使用 User 这个实体类即可！

​![image](assets/image-20230528163450-ojj7rqz.png)​

* 方法参数 username

  表示用户名。此值是客户端表单传递过来的数据。默认情况下必须叫 username，否则无 法接收。

## 2.7 PasswordEncoder 接口讲解

```java
// 表示把参数按照特定的解析规则进行解析
String encode(CharSequence rawPassword);
// 表示验证从存储中获取的编码密码与编码后提交的原始密码是否匹配。如果密码匹配，则返回 true；如果不匹配，则返回 false。第一个参数表示需要被解析的密码。第二个参数表示存储的密码。
boolean matches(CharSequence rawPassword, String encodedPassword);
// 表示如果解析的密码能够再次进行解析且达到更安全的结果则返回 true，否则返回false。默认返回 false。
default boolean upgradeEncoding(String encodedPassword) {
return false;
}

```

接口实现类

​![image](assets/image-20230528163627-m3wb5ua.png)​

	BCryptPasswordEncoder 是 Spring Security 官方推荐的密码解析器，平时多使用这个解析 器。

	BCryptPasswordEncoder 是对 bcrypt 强散列方法的具体实现。是基于 Hash 算法实现的单 向加密。可以通过 strength 控制加密强度，默认 10.

* 查用方法演示

  ```java
  @Test
  public void test01(){
  // 创建密码解析器
  BCryptPasswordEncoder bCryptPasswordEncoder = new 
  BCryptPasswordEncoder();
  // 对密码进行加密
  String atguigu = bCryptPasswordEncoder.encode("atguigu");
  // 打印加密之后的数据
  System.out.println("加密之后数据：\t"+atguigu);
  //判断原字符加密后和加密之前是否匹配
  boolean result = bCryptPasswordEncoder.matches("atguigu", atguigu);
  // 打印比较结果
  System.out.println("比较结果：\t"+result);
  }
  ```

## 2.8实现自定义登录

### 2.8.1连接、查询数据库

1. ​`bean(UserBean)`

    ```java
    package com.lkjedu.boot.beans;

    import com.baomidou.mybatisplus.annotation.TableField;
    import com.baomidou.mybatisplus.annotation.TableId;
    import com.baomidou.mybatisplus.annotation.TableName;
    import lombok.Data;

    @Data
    @TableName("t_user")
    public class UserBean {
        @TableId
        private Integer id;
        @TableField("userName")
        private String userName;
        @TableField("password")
        private String password;
        @TableField("trueName")
        private String trueName;
    }

    ```
2. ​`Mapper(UserMapper)`​

    ```java
    package com.lkjedu.boot.mapper;

    import com.baomidou.mybatisplus.core.mapper.BaseMapper;
    import com.lkjedu.boot.beans.UserBean;

    import java.util.List;

    public interface UserMapper extends BaseMapper<UserBean> {
        List<UserBean> selectAll();
    }

    ```
3. ​`测试是否连接成功`​

    ```java
    package com.lkjedu.boot;

    import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
    import com.lkjedu.boot.beans.UserBean;
    import com.lkjedu.boot.mapper.UserMapper;
    import org.junit.jupiter.api.Test;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.boot.test.context.SpringBootTest;

    /**
     * Unit test for simple App.
     */
    @SpringBootTest
    public class AppTest {
        /**
         * Rigorous Test :-)
         */
        @Autowired
        private UserMapper userMapper;
        @Test
        public void shouldAnswerWithTrue() {
            QueryWrapper<UserBean> wrapper = new QueryWrapper<>();
            QueryWrapper<UserBean> userName = wrapper.eq("userName", "0000");
            UserBean userBean = userMapper.selectOne(userName);

            if (userBean == null){
                System.out.println("是Null");
            }
            System.out.println(userBean);
        }
    }

    ```

### 2.8.2实现自定义逻辑(UserDetailService)

1. ​`UserDetailServiceImpl`​​

    ```java
    package com.lkjedu.boot.service.impl;

    import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
    import com.lkjedu.boot.beans.UserBean;
    import com.lkjedu.boot.domain.LoginUser;
    import com.lkjedu.boot.mapper.UserMapper;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.core.userdetails.UserDetailsService;
    import org.springframework.security.core.userdetails.UsernameNotFoundException;
    import org.springframework.stereotype.Service;

    @Service
    public class UserDetailServiceImpl implements UserDetailsService {
        @Autowired
        private UserMapper userMapper;
        @Override
        public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
            //查询用户信息
            QueryWrapper<UserBean> wrapper = new QueryWrapper<>();
            QueryWrapper<UserBean> userName = wrapper.eq("userName", s);
            UserBean userBean = userMapper.selectOne(userName);
            if (userBean == null){
                throw new RuntimeException("用户名或者密码错误~~~~");
            }
            //把数据封装成UserDetails返回出去
            return new LoginUser(userBean);
            //TODO 查询对应的权限信息
        }
    }

    ```
2. ​`LoginUser`​​

    ```java
    package com.lkjedu.boot.domain;

    import com.lkjedu.boot.beans.UserBean;
    import lombok.AllArgsConstructor;
    import lombok.Data;
    import lombok.NoArgsConstructor;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.userdetails.UserDetails;
    import java.util.Collection;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public class LoginUser implements UserDetails {
        private UserBean userBean;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return null;
        }

        @Override
        public String getPassword() {
            return userBean.getPassword();
        }

        @Override
        public String getUsername() {
            return userBean.getUserName();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

    ```
3. <div>
    	<style>
      .custom-span {
        color: red;
        font-weight: bold;
        text-shadow: 0 0 5px #ff0000;
      }
    </style>
    <span class="custom-span">注意：loadUserByUsername返回参数也可以直接返回Security里面User类可以以。因为我们自定义的LoginUser只是实现了UserDetails接口而Security中的User类是已经实现了[UserDetails, CredentialsContainer]是更加全面</span>
    </div>

### 2.8.3`SecurityConfig`​​Security配置类

1. 这里我们实现SpringSecurity的定义的登录页面和密码加密
2. ​`SecurityConfig`​

    ```java
    package com.lkjedu.boot.config;

    import com.lkjedu.boot.service.impl.UserDetailServiceImpl;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    @Configuration
    @EnableWebSecurity
    public class SecurityConfig extends WebSecurityConfigurerAdapter {
        @Autowired
        private UserDetailServiceImpl userDetailService;

        /*
        AuthenticationManagerBuilder，指定了自定义的UserDetailsService实现类来获取用户详细信息，
        并使用BCryptPasswordEncoder作为密码编码器进行密码加密。
         */
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailService).passwordEncoder(bCryptPasswordEncoder());
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            //设置表达提交规则
            http.formLogin()
                    .loginProcessingUrl("/login")//当发现表单的URL时认为是登录，必须和表单提交的地址一样，去执行UserDetailServiceImpl
                    .loginPage("/static/main.html")//自定义登录页面
                    .successForwardUrl("/toIndex")//登录成功之后跳转的页面接口
                    .failureForwardUrl("/toError");//登录失败后跳转页面
            //请求授权规则
            http.authorizeRequests()
                    .antMatchers("/static/error.html").permitAll()//方向我们的error
                    .antMatchers("/static/main.html").permitAll()//放行某个接口这里mian.html不需要被认证
                    .anyRequest().authenticated();//任何请求都需要拦截
            //关闭csrf()
            http.csrf().disable();
        }

        @Bean
        public BCryptPasswordEncoder bCryptPasswordEncoder(){
           return new BCryptPasswordEncoder();
        }
    }
    ```
3. ​`LoginController`​​

    ```java
    package com.lkjedu.boot.controller;

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
    }
    ```

    1. <div>
        <style>
          .custom-span {
            color: red;
            font-weight: bold;
            text-shadow: 0 0 5px #ff0000;
          }
        </style>
        <span class="custom-span">注意：这里根据我们Debug发现表单提交跟没走这个方法，而是走我们的SecurityConfig【Security的配置类】这类的http.formLogin()，所以这个我们也可是注释掉</span>
        </div>
4. ​`main.html`​​

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Title</title>
    </head>
    <body>
    <form action="/login" method="post">
        <!--注意：这里的name必须使用username不然SpringSecurity看不到-->
        userName:<input type="text" name="username"><br>
        password:<input type="password" name="password"><br>
        submit:<input type="submit">
    </form>
    </body>
    </html>
    ```

    1. ‍
    2. 的
5. <div>
    <style>
      .custom-span {
        color: red;
        font-weight: bold;
        text-shadow: 0 0 5px #ff0000;
      }
    </style>
    <span class="custom-span">特别注意：我这里一开始使用@PostMapping报错了[Request method 'GET' not supported]原因：异常提示的很明确，请求不支持GET方式访问，出现这种问题一般都是由于限制请求接口为POST，然后使用GET形式访问造成的。</span><br>
    <h4>
    <span class="custom-span">解决方案：碰到这种问题有的小伙伴可能很懵逼，除萌新外大部分人都了解，既然限制了接口的访问类型，那肯定会用自己设定的访问类型去访问，比如你一个POST接口肯定不会用GET形式方式，但是有时候明明用POST形式访问了却仍然给你出来这个异常，这种问题一般都是由调用的jar包重定向后引起的。</span>
    <h4>
    <span>具体请看：</span>
    <a href="https://blog.csdn.net/qq_45489797/article/details/112056105">这篇文章</a>
    </div>
6. 自定义登录表单的`name属性`​

    ```java
            http.formLogin()
                    .usernameParameter("UserName")
                    .passwordParameter("MyPassword")
    ```

### 2.8.4自定义成功后跳转页面

因为我们现在大多数项目都是前后端分离的基本上不会用Controller去做页面跳转，都是我们的在外部的跳转。所以我们的`http.formLogin().successForwardUrl()`​方法大多数情况下是不好使的。

1. successForwardUrl()方法的底层逻辑

    1. 我通过源码发现它其实通过​`this.successHandler(new ForwardAuthenticationSuccessHandler(forwardUrl));`​
    2. ​`ForwardAuthenticationSuccessHandler`​

        ```java

        public class ForwardAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
            private final String forwardUrl;

            public ForwardAuthenticationSuccessHandler(String forwardUrl) {
                Assert.isTrue(UrlUtils.isValidRedirectUrl(forwardUrl), () -> {
                    return "'" + forwardUrl + "' is not a valid forward URL";
                });
                this.forwardUrl = forwardUrl;
            }

            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                request.getRequestDispatcher(this.forwardUrl).forward(request, response);
            }
        }
        ```
    3. ​`AuthenticationSuccessHandler`​

        ```java
            void onAuthenticationSuccess(HttpServletRequest var1, HttpServletResponse var2, Authentication var3) throws IOException, ServletException;

        ```
    4. ​`Authentication`​
2. 通过源码发现其实底层也是用的转发机制，所以我们想跳转到站外的话就得实现​`AuthenticationSuccessHandler`​
3. ​`MyAuthenticationSuccessHandler`​

    ```java
    package com.lkjedu.boot.handler;

    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.userdetails.User;
    import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

    import javax.servlet.FilterChain;
    import javax.servlet.ServletException;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.io.IOException;

    public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
        private String url;

        public MyAuthenticationSuccessHandler(String url) {
            this.url = url;
        }

        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
            response.sendRedirect(url);
            //getPrincipal() 这个方法其实就是获取我们的User（SpringSecurity里面的User）
            User user = (User) authentication.getPrincipal();
            String username = user.getUsername();
            String password = user.getPassword();
            System.out.println(username + password);
        }
    }

    ```

    1. authentication.getPrincipal():这个方法其实就是获取我们的User（SpringSecurity里面的User）

### 2.8.5自定义登录失败跳转页面

1. 因为我们现在大多数项目都是前后端分离的基本上不会用Controller去做页面跳转，都是我们的在外部的跳转。所以我们的`http.formLogin().failureForwardUrl()`​方法大多数情况下是不好使的。

    1. ​`failureForwardUrl()`​底层逻辑：

        1. 我通过源码发现它其实通过：​`this.failureHandler(new ForwardAuthenticationFailureHandler(forwardUrl));`​
        2. ​`ForwardAuthenticationFailureHandler(forwardUrl)`​

            ```java
                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                    request.setAttribute("SPRING_SECURITY_LAST_EXCEPTION", exception);
                    request.getRequestDispatcher(this.forwardUrl).forward(request, response);
                }
            ```
    2. 通过源码发现其实底层也是用的转发机制，所以我们想跳转到站外的话就得实现​`AuthenticationFailureHandler`​
    3. ​`MyAuthenticationFailureHandler`​

        ```java
        package com.lkjedu.boot.handler;

        import org.springframework.security.core.AuthenticationException;
        import org.springframework.security.web.authentication.AuthenticationFailureHandler;

        import javax.servlet.ServletException;
        import javax.servlet.http.HttpServletRequest;
        import javax.servlet.http.HttpServletResponse;
        import java.io.IOException;

        public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
            private String failUrl;

            public MyAuthenticationFailureHandler(String failUrl) {
                this.failUrl = failUrl;
            }


            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                request.setAttribute("SPRING_SECURITY_LAST_EXCEPTION", exception);
                response.sendRedirect(failUrl);
            }
        }

        ```

### 退出登录

1. 实现退出非常简单，只要在页面中添加 /logout 的超链接即可。

    ```html
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Title</title>
    </head>
    <body>
    <h4>Hello SpringSecurity</h4>
    跳转页面<a href="/static/VIP.html">1vip</a>
    跳转页面<a href="/toVIP">2vip</a><br>
    <a href="/logout">LogOut</a>
    </body>
    </html>
    ```

    ​![image](assets/image-20230630111848-4sjscbz.png)

    ​
2. http.logout()

    用户只需要向 Spring Security 项目中发送 /logout 退出请求即可。

    ```java
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            //退出登录
            http.logout()
    //              .logoutUrl("设置推出登录的URL")
                    .logoutSuccessUrl("/static/main.html");//指定推出成功后登录页面
    //              .logoutSuccessHandler()//这个也可以自定义我们自己的推出登录逻辑
        }
    ```

‍

## 2.9.1http.formLogin()详细解释

​`http.formLogin()`​是Spring Security中的一个配置方法，用于启用基于表单的登录认证功能。它负责配置和处理用户的登录请求，并提供了默认的登录页面、登录请求路径和认证失败处理等功能。

<div>
<span>具体而言，http.formLogin()方法的作用包括：</span>
</div>

1. 启用登录表单：该方法会自动创建一个登录表单，让用户输入用户名和密码进行身份验证。
2. 配置登录页面：默认情况下，`http.formLogin()`​会生成一个简单的登录页面，可以在该方法中使用`.loginPage("/login")`​来指定自定义的登录页面路径。
3. 配置登录请求路径：默认情况下，登录表单的提交地址为`/login`​，可以使用`.loginProcessingUrl("/login")`​来指定自定义的登录请求路径。
4. 配置登录成功跳转：登录成功后，默认会跳转到之前被拦截的路径，你可以使用`.defaultSuccessUrl("/home")`​来指定登录成功后的跳转路径。
5. 配置认证失败处理：如果身份验证失败（例如用户名或密码错误），默认会重定向到登录页面并显示错误消息。你可以使用`.failureUrl("/login?error=true")`​来指定认证失败后的跳转路径。
6. 其他相关配置：你可以通过该方法的其他配置选项来自定义登录表单的各种行为和样式，如指定登录表单中的用户名字段名、密码字段名、记住我选项等。

	总之，`http.formLogin()`​方法的作用是启用基于表单的登录认证功能，并提供了一些常用的配置选项，使得开发人员可以轻松进行登录页面的定制和处理。通过这个方法，你可以快速设置一个简单但有效的登录认证流程，以保护你的应用程序的安全性。

## 2.10http.authorizeRequests()详细解释

​`http.authorizeRequests()`​是Spring Security中的一个配置方法，它的作用是为不同的URL路径指定访问的权限要求。

通过调用`http.authorizeRequests()`​方法，你可以为应用程序中的各种URL路径设置不同的权限规则。这些规则将决定用户是否能够访问或执行特定的URL。

<div>
<span>具体而言，http.authorizeRequests()方法允许你：</sapn>
</div>

1. 使用`.antMatchers()`​方法匹配URL模式：你可以使用Ant风格的URL模式来指定要匹配的URL路径。例如，你可以使用`.antMatchers("/public")`​来匹配路径为"/public"的URL。
2. 为匹配的URL指定访问权限：你可以使用诸如`.permitAll()`​、`.hasRole("ROLE_NAME")`​、`.hasAnyRole("ROLE1", "ROLE2")`​等方法来指定访问该URL所需的权限。

    * ​`.permitAll()`​表示该URL是公共资源，任何人都可以访问，无需进行身份验证。
    * ​`.hasRole("ROLE_NAME")`​表示需要具有指定角色才能访问该URL。
    * ​`.hasAnyRole("ROLE1", "ROLE2")`​表示需要具有指定角色中的任意一个才能访问该URL。
3. 使用`.anyRequest()`​方法进行默认的权限设置：你可以使用`.anyRequest().authenticated()`​来指定其他所有请求（未在前面的规则中匹配到的请求）需要进行身份验证。
4. 总之，`http.authorizeRequests()`​方法允许你基于URL路径来配置访问权限，从而保护应用程序的资源和功能。通过定义适当的权限规则，你可以确保只有经过授权的用户才能访问受限资源，提高应用程序的安全性。

### 2.10.1anyRequest()

在Spring Security中，`anyRequest()`​是一种配置方法，用于指定所有请求的权限要求。

通过调用`anyRequest()`​方法，你可以为所有未经过前面指定的URL匹配规则的请求设置默认的访问权限。这意味着如果一个请求没有匹配到显式的访问权限规则，那么默认规则将适用于该请求。

1. 具体来说，`anyRequest()`​方法常与其他方法链式调用。以下是使用`anyRequest()`​方法的示例：

    ```java
    http.authorizeRequests()
        .antMatchers("/public").permitAll()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated();
    ```
2. 在上述示例中，我们首先通过`.antMatchers()`​方法为某些特定URL路径设置了访问权限规则。然后，在使用`.anyRequest()`​方法之前的规则都不适用于请求时，就会应用`.anyRequest()`​的规则。
3. 在这个示例中，`.authenticated()`​方法被使用，表示除了前面指定的"/public"和"/admin/**"的URL路径之外，所有其他请求都需要进行身份验证。也就是说，这些请求必须是已经登录的用户才能访问。
4. ​`anyRequest()`​方法的作用是定义了系统上所有未明确配置的请求所需的访问权限要求。它提供了一种方便的方式来为系统中的所有请求（即不匹配前面规则的请求）设置默认的权限规则。通过使用`anyRequest().authenticated()`​，你可以确保只有经过身份验证的用户才能访问未在其他规则中明确指定的资源。

    需要注意的是，`anyRequest()`​方法应该放置在权限规则声明的最后，以防止其它具体规则被忽略。

### 2.10.2antMatchers()

在Spring Security中，`antMatchers()`​是一种用于匹配URL模式的配置方法。

通过调用`antMatchers()`​方法，你可以指定URL路径的模式，并为这些路径设置访问权限规则。这允许你对应用程序中的特定URL路径进行细粒度的访问控制。

具体来说，`antMatchers()`​方法根据Ant风格的URL模式来匹配URL路径。Ant风格的URL模式支持通配符和占位符，例如：

* ​`?`​ 表示单个字符的通配符。
* ​`*`​ 表示任意数量字符的通配符。
* ​`{}`​ 用于指定多个选项中的一个。
* ​`/`​ 分割URL路径的分隔符。

以下是使用`antMatchers()`​方法的示例：

```java
http.authorizeRequests()
    .antMatchers("/public").permitAll()
    .antMatchers("/admin/**").hasRole("ADMIN");

```

在上述示例中，我们使用`.antMatchers()`​方法为两个不同的URL路径设置了访问权限规则。

* ​`"/public"`​ 表示精确匹配路径为 "/public" 的URL。我们使用 `.permitAll()`​ 方法指定了该路径是公共资源，即任何人都可以访问它，无需进行身份验证。
* ​`"/admin/**"`​ 表示匹配以 "/admin/" 开头的所有URL路径。我们使用 `.hasRole("ADMIN")`​ 方法指定访问该路径需要具有 "ADMIN" 角色的用户。

通过使用`antMatchers()`​方法，你可以根据URL路径的模式设置访问权限规则。这使你能够对不同的URL路径进行细粒度的访问控制，从而保护应用程序中的资源和功能。

‍

# `ExpressionUrlAuthorizationConfigurer`​

是Spring Security中的一个全局的配置类，用于定义基于表达式的访问控制规则。

该类提供了一种灵活、强大的方式来根据表达式对URL路径进行细粒度的访问控制。通过使用`ExpressionUrlAuthorizationConfigurer`​，你可以根据特定的条件和逻辑来定义访问权限规则，而不仅仅是简单地指定角色或权限。

## 访问控制规则

* ​`permitAll`​：表示允许所有用户访问该资源，无需进行身份验证。
* ​`denyAll`​：表示拒绝所有用户访问该资源。
* ​`anonymous`​：表示允许匿名用户访问该资源，即未经身份验证的用户。
* ​`authenticated`​：表示允许已经身份验证的用户访问该资源。
* ​`fullyAuthenticated`​：表示只允许完全经过身份验证的用户（非记住我身份验证）访问该资源。
* ​`rememberMe`​：表示只允许通过"Remember Me"功能进行身份验证的用户访问该资源。

这些权限表达式可以在Spring Security的配置中使用，以定义对URL路径的访问权限规则。例如：

```java
http.authorizeRequests()
    .antMatchers("/public").access(permitAll)
    .antMatchers("/admin/**").access(authenticated)
    .anyRequest().authenticated();

```

在上述示例中，我们使用了不同的权限表达式来配置访问控制规则。`access(permitAll)`​表示访问 "/public" 资源时允许所有用户，而 `access(authenticated)`​ 表示访问以 "/admin/" 开头的资源时需要已经身份验证的用户。

通过使用这些权限表达式，你可以根据不同的访问要求和安全策略，定义灵活的访问控制规则，以保护应用程序中的资源和功能。

## 访问控制url匹配

在前面讲解了认证中所有常用配置，主要是对 **http.formLogin()** 进行操作。而在配置类中 **http.authorizeRequests() ​**主要是对url进行控制，也就是我们所说的授权（访问控制）。 

http.authorizeRequests() 也支持连缀写法，总体公式为：

*  url 匹配规则.权限控制方法

	通过上面的公式可以有很多 url 匹配规则和很多权限控制方法。这些内容进行各种组合就形成了Spring Security中 的授权。在所有匹配规则中取所有规则的交集。配置顺序影响了之后授权效果，越是具体的应该放在前面，越是笼统的应该 放到后面。 

	anyRequest() 在之前认证过程中我们就已经使用过 anyRequest()，表示匹配所有的请求。一般情况下此方法都会使用，设置全 部内容都需要进行认证。 .anyRequest().authenticated();

## _anyRequest详细解释

	在之前认证过程中我们就已经使用过 anyRequest()，表示匹配所有的请求。一般情况下此方法都会使用，设置全 部内容都需要进行认证。

```java
.anyRequest().authenticated();  
```

## antMatcher()

1. 方法定义如下

    ```java
    public C antMatchers(String... antPatterns)  
    ```

    参数是不定向参数，每个参数是一个 ant 表达式，用于匹配 URL规则。

    * 规则如下：

      * ​`?`​： 匹配一个字符
      * ​`*`​:匹配 0 个或多个字符
      * ​`**`​ ：匹配 0 个或多个目录
2. 在实际项目中经常需要放行所有静态资源，下面演示放行 js 文件夹下所有脚本文件。

    ```java
    .antMatchers("/js/**","/css/**").permitAll()  
    ```
3. 还有一种配置方式是只要是.js 文件都放行

    ```java
    .antMatchers("/**/*.js").permitAll()
    ```

## regexMatchers()

1. 介绍

    使用正则表达式进行匹配。和 antMatchers() 主要的区别就是参数， antMatchers() 参数是 ant 表达式， regexMatchers() 参数是正则表达式。

    1. 演示所有以.js 结尾的文件都被放行。

        ```java
        .regexMatchers( ".+[.]js").permitAll()
        ```
2. 两个参数时使用方式

    无论是 antMatchers() 还是 regexMatchers() 都具有两个参数的方法，其中第一个参数都是 HttpMethod ，表示请求方式，当设置了 HttpMethod 后表示只有设定的特定的请求方式才执行对应的权限设置。

    1. 枚举类型 HttpMethod 内置属性如下：

        ```java
        public enum HttpMethod(){
        	GET,
        	HEAD,
        	POST,
        	PUT,
        	PATCH,
        	DELETE,
        	OPTTONS,
        	TRACE
        }
        ```

## mvcMatchers()

mvcMatchers()适用于配置了 servletPath 的情况。

servletPath 就是所有的 URL 的统一前缀。在 SpringBoot 整合SpringMVC 的项目中可以在application.properties 中添加下面内容设置 ServletPath

```java
spring.mvc.servlet.path=/xxxx
```

在Spring Security 的配置类中配置 .servletPath() 是 mvcMatchers()返回值特有的方法，antMatchers()和 regexMatchers()没有这个方法。在 servletPath() 中配置了 servletPath 后，mvcMatchers()直接写 SpringMVC 中@RequestMapping()中设置的路径即可。

```java
.mvcMatchers("/demo").servletPath("/xxxx").permitAll()
```

如果不习惯使用 mvcMatchers()也可以使用 antMatchers()，下面代码和上面代码是等效

```java
.antMatchers("/xxxx/demo").permitAll()
```

## 内置访问控制方法

Spring Security 匹配了 URL 后调用了 permitAll() 表示不需要认证，随意访问。在 Spring Security 中提供了多种内置控制。

### permitAll()

permitAll()表示所匹配的 URL 任何人都允许访问。

```javav
		/**
		 * Specify that URLs are allowed by anyone.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry permitAll() {
			return access(permitAll);
		}
```

### authenticated()

authenticated()表示所匹配的 URL 都需要被认证才能访问。

```java
		/**
		 * Specify that URLs are allowed by any authenticated user.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry authenticated() {
			return access(authenticated);
		}
```

### anonymous()

anonymous()表示可以匿名访问匹配的URL。和permitAll()效果类似，只是设置为 anonymous()的 url 会执行 filter链中

```java
		/**
		 * Specify that URLs are allowed by anonymous users.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry anonymous() {
			return access(anonymous);
		}
```

### denyAll()

denyAll()表示所匹配的 URL 都不允许被访问。

```java
		/**
		 * Specify that URLs are not allowed by anyone.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 */
		public ExpressionInterceptUrlRegistry denyAll() {
			return access(denyAll);
		}
```

### rememberMe()

被“remember me”的用户允许访问

```java
/**
		 * Specify that URLs are allowed by users that have been remembered.
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public ExpressionInterceptUrlRegistry rememberMe() {
			return access(rememberMe);
		}
```

	Spring Security 中 Remember Me 为“记住我”功能，用户只需要在登录时添加 remember-me复选框，取值为 true。Spring Security 会自动把用户信息存储到数据源中，以后就可以不登录进行访问

1. 添加依赖

    Spring Security 实 现 Remember Me 功 能 时 底 层 实 现 依 赖Spring-JDBC，所以需要导入 Spring-JDBC。以后 多使用 MyBatis 框架而很少直接导入 spring-jdbc，所以此处导入 mybatis 启动器同时还需要添加 MySQL 驱动

    ```xml
    <!-- mybatis 依赖 -->
    <dependency>
       <groupId>org.mybatis.spring.boot</groupId>
       <artifactId>mybatis-spring-boot-starter</artifactId>
       <version>2.1.1</version>
    </dependency>
    <!-- mysql 数据库依赖 -->
    <dependency>
       <groupId>mysql</groupId>
       <artifactId>mysql-connector-java</artifactId>
       <version>8.0.18</version>
    </dependency>
    ```
2. 配置数据源

    在 application.properties 中配置数据源。请确保数据库中已经存在shop数据库

    ```properties
    spring.datasource.driver-class-name= com.mysql.cj.jdbc.Driver
    spring.datasource.url= jdbc:mysql://localhost:3306/security?
    useUnicode=true&characterEncoding=UTF-8&serverTimezone=Asia/Shanghai
    spring.datasource.username= root
    spring.datasource.password= 123456
    ```
3. 开启`rememberMe()`​[记住我]功能

    ```java
      
        @Autowired
        private DataSource dataSource;

        @Autowired
        private PersistentTokenRepository persistentTokenRepository;

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            //实现记住我功能
            //注意：我们rememberMe()的默认失效时间其实是两周时间
            http.rememberMe()
                    .tokenValiditySeconds(60)//设置失效时间，单位秒
    //                .rememberMeParameter("设置我们的登录标单复选框的name属性值")
                    .userDetailsService(userDetailService)//自定义登录逻辑
                    .tokenRepository(persistentTokenRepository);//持久层对象
        }
    ```
4. 编写配置

    ​`RememberMeConfig.java`​

    ```java
        @Bean
        public PersistentTokenRepository persistentTokenRepository(){
            JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
            //注入数据源
            repository.setDataSource(dataSource);
            //自动创建表，第一次启动时需要。
    //        repository.setCreateTableOnStartup(true);
            return  repository;
        }
    ```

### fullyAuthenticated()

如果用户不是被 remember me 的，才可以访问。

```java
		/**
		 * Specify that URLs are allowed by users who have authenticated and were not
		 * "remembered".
		 * @return the {@link ExpressionUrlAuthorizationConfigurer} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public ExpressionInterceptUrlRegistry fullyAuthenticated() {
			return access(fullyAuthenticated);
		}
```

## 角色权限判断

	除了之前讲解的内置权限控制。Spring Security 中还支持很多其他权限控制。这些方法一般都用于用户已经被认 证后，判断用户是否具有特定的要求

### hasAuthority(String)

判断用户是否具有特定的权限，用户的权限是在自定义登录逻辑中创建 User 对象时指定的。下图中 admin和 normal 就是用户的权限。admin和normal 严格区分大小写。

```java
.antMatchers("/static/VIP.html").hasAnyAuthority("admin")//权限认证
```

在配置类中通过 hasAuthority(“admin”)设置具有 admin 权限时才能访问。

### hasAnyAuthority(String ...)

如果用户具备给定权限中某一个，就允许访问。

下面代码中由于大小写和用户的权限不相同，所以用户无权访问

```java
.antMatchers("/main1.html").hasAnyAuthority("adMin","admiN")
```

### hasRole(String)

如果用户具备给定角色就允许访问。否则出现 403。

 参数取值来源于自定义登录逻辑 UserDetailsService 实现类中创建 User 对象时给 User 赋予的授权。

	 在给用户赋予角色时角色需要以： ROLE_开头 ，后面添加角色名称。例如：ROLE_abc 其中 abc 是角色名，ROLE_ 是固定的字符开头。

使用 hasRole()时参数也只写 abc 即可。否则启动报错

1. 给用户赋予角色：

    ```java
    ArrayList<String> authenticationList = new ArrayList<>();
            authenticationList.add("admin");
            authenticationList.add("ROLE_aaa");
            return new LoginUser(userBean,authenticationList);
    ```
2. 判断用户角色

    ```java
    .antMatchers("/static/VIP.html").hasRole("aaa")
    ```

## 基于表达式的访问控制

### access()方法使用

之前学习的登录用户权限判断实际上底层实现都是调用access(表达式)

​![image](assets/image-20230629150334-a7di6mb.png)

可以通过 access() 实现和之前学习的权限控制完成相同的功能。​

以 hasRole 和 和 permitAll 举例

​![image](assets/image-20230629150355-mpl5pfj.png)​

### 使用自定义方法

虽然这里面已经包含了很多的表达式(方法)但是在实际项目中很有可能出现需要自己自定义逻辑的情况。 判断登录用户是否具有访问当前 URL 权限。

1. 新建接口及实现类

    1. ​`MyService.java`​

        ```java
        package com.xxxx.springsecuritydemo.service;
        import org.springframework.security.core.Authentication;
        import javax.servlet.http.HttpServletRequest;
        public interface MyService {
           boolean hasPermission(HttpServletRequest request, Authentication authentication);
        }

        ```
    2. ​`MyServiceImpl.java`

        ```java
        package com.xxxx.springsecuritydemo.service.impl;
        import com.xxxx.springsecuritydemo.service.MyService;
        import org.springframework.security.core.Authentication;
        import org.springframework.security.core.GrantedAuthority;
        import org.springframework.security.core.authority.SimpleGrantedAuthority;
        import org.springframework.security.core.userdetails.UserDetails;
        import org.springframework.stereotype.Component;
        import javax.servlet.http.HttpServletRequest;
        import java.util.Collection;
        /**
        * @author zhoubin
        * @since 1.0.0
        */
        @Component
        public class MyServiceImpl implements MyService {
           @Override
           public boolean hasPermission(HttpServletRequest request, Authentication authentication) 
        {
              Object obj = authentication.getPrincipal();
              if (obj instanceof UserDetails){
                 UserDetails userDetails = (UserDetails) obj;
                 Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
                 return authorities.contains(new SimpleGrantedAuthority(request.getRequestURI()));
             }
              return false;
          	}
        }
        ```
2. 修改配置类

    1. 在 access 中通过@bean的id名.方法(参数)的形式进行调用配置类中修改如下：

        ```java
        //url拦截
        http.authorizeRequests()
              //login.html不需要被认证
              // .antMatchers("/login.html").permitAll()
             .antMatchers("/login.html").access("permitAll")
              // .antMatchers("/main.html").hasRole("abc")
             .antMatchers("/main.html").access("hasRole('abc')")
             .anyRequest().access("@myServiceImpl.hasPermission(request,authentication)")
        ```

# Thymeleaf中SpringSecurity的使用

	Spring Security 可以在一些视图技术中进行控制显示效果。例如： JSP 或 Thymeleaf 。在非前后端分离且使用 Spring Boot 的项目中多使用 Thymeleaf 作为视图展示技术。

	Thymeleaf 对 Spring Security 的 支 持 都 放 在 `thymeleaf-extras-springsecurityX`​ 中，目前最新版本为 5。所 以需要在项目中添加此 jar 包的依赖和 thymeleaf 的依赖。

1. 添加依赖

    ```xml
    <!--thymeleaf springsecurity5 依赖-->
    <dependency>
       <groupId>org.thymeleaf.extras</groupId>
       <artifactId>thymeleaf-extras-springsecurity5</artifactId>
    </dependency>
    <!--thymeleaf依赖-->
    <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
    ```
2. 在 html 页面中引入 thymeleaf 命名空间和 security 命名空间

    ```html
    <html xmlns="http://www.w3.org/1999/xhtml"
          xmlns:th="http://www.thymeleaf.org"
          xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5">
    ```

## 获取属性

可以在html页面中通过 sec:authentication="" 获取

​`UsernamePasswordAuthenticationToken`​ 中所有 getXXX 的内容，包含父类中的 getXXX 的内容。

1. 根据源码得出下面属性：

    * name ：登录账号名称
    * principal ：登录主体，在自定义登录逻辑中是 UserDetails
    * credentials ：凭证
    * authorities ：权限和角色
    * details ：实际上是 WebAuthenticationDetails 的实例。可以获取 remoteAddress (客户端 ip)和
    * sessionId (当前 sessionId)
2. 新建demo.html

    在项目 resources 中新建 templates 文件夹，在 templates 中新建demo.html 页面

    ```html
    <!DOCTYPE html>
    <html xmlns="http://www.w3.org/1999/xhtml"
          xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity5">
    <head>
        <meta charset="UTF-8">
    智者乐水 仁者乐山 程序员 乐字节 2 如果需要更多优质的Java、Python、架构、大数据等IT资料请加微信：lezijie007
    编写Controller
    thymeleaf 页面需要控制转发，在控制器类中编写下面方法
        <title>Title</title>
    </head>
    <body>
       登录账号:<span sec:authentication="name"></span><br/>
       登录账号:<span sec:authentication="principal.username"></span><br/>
       凭证：<span sec:authentication="credentials"></span><br/>
       权限和角色：<span sec:authentication="authorities"></span><br/>
       客户端地址：<span sec:authentication="details.remoteAddress"></span><br/>
       sessionId：<span sec:authentication="details.sessionId"></span><br/>
    </body>
    </html>
    ```
3. 编写Controller

    thymeleaf 页面需要控制转发，在控制器类中编写下面方法

    ```java
    @RequestMapping("/demo")
    public String demo(){
       return "demo";
    }
    ```

## 权限判断

设置用户角色和权限

1. 设定用户具有 admin，/insert，/delete 权限 ROLE_abc 角色。

    ```java
    return new User(username,password, 
    AuthorityUtils.commaSeparatedStringToAuthorityList("admin,ROLE_abc,/insert,/delete"));
    ```
2. 控制页面显示效果

    ```html
    通过权限判断：
    <button sec:authorize="hasAuthority('/insert')">新增</button>
    <button sec:authorize="hasAuthority('/delete')">删除</button>
    <button sec:authorize="hasAuthority('/update')">修改</button>
    <button sec:authorize="hasAuthority('/select')">查看</button>
    <br/>
    通过角色判断：
    <button sec:authorize="hasRole('abc')">新增</button>
    <button sec:authorize="hasRole('abc')">删除</button>
    <button sec:authorize="hasRole('abc')">修改</button>
    <button sec:authorize="hasRole('abc')">查看</button>
    ```

## 2.11 SpringBoot 对 Security 的自动配置

[Spring Security Reference](https://docs.spring.io/spring-security/site/docs/5.3.4.RELEASE/reference/html5/#servlet-hello)

# 3.SpringSecurity Web 权限方案

## 3.1 设置登录系统的账号、密码

1. 方式一：在 application.properties

    ```properties
    spring.security.user.name=atguigu
    spring.security.user.password=atguigu
    ```
2. 编写类实现`WebSecurityConfigurerAdapter核心配置`​接口

    1. ```java
        import org.springframework.context.annotation.Bean;
        import org.springframework.context.annotation.Configuration;
        import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
        import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
        import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
        import org.springframework.security.crypto.password.PasswordEncoder;

        @Configuration
        public class SecurityConfig extends WebSecurityConfigurerAdapter {
            @Override
            protected void configure(AuthenticationManagerBuilder auth) throws Exception {
                BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
                String password = passwordEncoder.encode("123");
                auth.inMemoryAuthentication().withUser("zhangsan")
                        .password(password)
                        .roles("admin");
            }
            @Bean
            PasswordEncoder passwordEncoder(){
                return new BCryptPasswordEncoder();
            }
        }
        ```

## 3.2 实现数据库认证来完成用户登录

完成自定义登录:

* 编写自定义实现`UserDetailsService`​接口(​`MyUserDetailsService`​)

  ```java
  import org.springframework.security.core.GrantedAuthority;
  import org.springframework.security.core.authority.AuthorityUtils;
  import org.springframework.security.core.userdetails.User;
  import org.springframework.security.core.userdetails.UserDetails;
  import org.springframework.security.core.userdetails.UserDetailsService;
  import org.springframework.security.core.userdetails.UsernameNotFoundException;
  import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
  import org.springframework.stereotype.Service;

  import java.util.List;

  @Service()
  public class MyUserDetailsService implements UserDetailsService {

      @Override
      public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
          //用户密码加密
          BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
          String password = passwordEncoder.encode("123");

          //添加用户角色
          List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");

          User user = new User("lisi",password, auths);
          return user;
      }
  }
  ```
* 自定义SpringSecurity配置类(`SecurityConfig`​)实现`WebSecurityConfigurerAdapter`​接口重写configure方法，参数`AuthenticationManagerBuilder`​(​`身份验证管理器生成器`​)

  ```java
  import org.springframework.beans.factory.annotation.Autowired;
  import org.springframework.context.annotation.Bean;
  import org.springframework.context.annotation.Configuration;
  import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
  import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
  import org.springframework.security.core.userdetails.UserDetailsService;
  import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
  import org.springframework.security.crypto.password.PasswordEncoder;

  @Configuration
  public class SecurityConfig extends WebSecurityConfigurerAdapter {
      //把刚刚我们写的 MyUserDetailsService 自动注入进来
      @Autowired
      private UserDetailsService myUserDetailsService;
      @Override
      protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          auth.userDetailsService(myUserDetailsService);
      }
      @Bean
      PasswordEncoder passwordEncoder(){
          return new BCryptPasswordEncoder();
      }
  }
  ```

### 3.2.1 准备 sql

```sql
create table users(
 id bigint primary key auto_increment,
username varchar(20) unique not null,
password varchar(100)
);
-- 密码 atguigu
insert into users values(1,'张
san','$2a$10$2R/M6iU3mCZt3ByG7kwYTeeW0w7/UqdeXrb27zkBIizBvAven0/na');
-- 密码 atguigu
insert into users values(2,'李
si','$2a$10$2R/M6iU3mCZt3ByG7kwYTeeW0w7/UqdeXrb27zkBIizBvAven0/na');
create table role(
id bigint primary key auto_increment,
name varchar(20)
);
insert into role values(1,'管理员');
insert into role values(2,'普通用户');
create table role_user(
uid bigint,
rid bigint
);
insert into role_user values(1,1);
insert into role_user values(2,2);
create table menu(
id bigint primary key auto_increment,
name varchar(20),
url varchar(100),
parentid bigint,
permission varchar(20)
);
insert into menu values(1,'系统管理','',0,'menu:system');
insert into menu values(2,'用户管理','',0,'menu:user');
create table role_menu(
mid bigint,
rid bigint
);
insert into role_menu values(1,1);
insert into role_menu values(2,1);
insert into role_menu values(2,2);

```

### 3.2.2 添加依赖

```xml
<dependencies>
	 <dependency>
		 <groupId>org.springframework.boot</groupId>
		 <artifactId>spring-boot-starter-web</artifactId>
	 </dependency>
	 <dependency>
		 <groupId>org.springframework.boot</groupId>
		 <artifactId>spring-boot-starter-security</artifactId>
	 </dependency>
	 <dependency>
	 	<groupId>org.springframework.boot</groupId>
		 <artifactId>spring-boot-starter-test</artifactId>
		 <scope>test</scope>
	 </dependency>
	 <!--mybatis-plus-->
	 <dependency>
		 <groupId>com.baomidou</groupId>
		 <artifactId>mybatis-plus-boot-starter</artifactId>
		 <version>3.0.5</version>
	 </dependency>
	 <!--mysql-->
	 <dependency>
		 <groupId>mysql</groupId>
		 <artifactId>mysql-connector-java</artifactId>
	 </dependency>
	 <!--lombok 用来简化实体类-->
	 <dependency>
		 <groupId>org.projectlombok</groupId>
		 <artifactId>lombok</artifactId>
	 </dependency>
</dependencies>
```

### 3.2.3 制作实体类

```java

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.Data;

@Data
@TableName("t_user")
public class UserBean {
    private Integer id;
    private String userName;
    private String password;
    private String trueName;
}
```

### 3.2.4 整合 MybatisPlus 制作 mapper

​`Mapper类`​

```java
@Repository
public interface UsersMapper extends BaseMapper<Users> {
}
```

​`application.properties`

```properties
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql:///lkj?characeter=utf-8
    username: root
    password: 123456
mybatis-plus:
  configuration:
    map-underscore-to-camel-case: true # 开启驼峰命名转换
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl # 开启驼峰命名转换
  mapper-locations: classpath:/mappers/*.xml
```

### 3.2.5 制作登录实现类

```java
import com.lkjedu.boot.beans.UserBean;
import com.lkjedu.boot.mappers.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service()
public class MyUserDetailsService implements UserDetailsService {
    @Resource
    private UserMapper userMapper;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserBean byId = userMapper.findById(username);
        if (byId != null){
            //用户密码加密
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            String password = passwordEncoder.encode(byId.getPassword());

            //添加用户角色
            List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("admin");

            User user = new User(byId.getUserName(), password, auths);
            return user;
        }
        throw new UsernameNotFoundException("用户名或者密码错误~");
    }
}
```

### 3.2.6 测试访问

​![image](assets/image-20230528164825-ioyxtu8.png)​

输入用户名，密码

## 3.3 未认证请求跳转到登录页

* 自定义SpringSecurity配置类(`SecurityConfig`​)实现`WebSecurityConfigurerAdapter`​接口重写configure方法，参数`HttpSecurity ​`​

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() //自定义自己的登录页面
                .loginPage("/login.html")//登录页面设置
                .loginProcessingUrl("/user/login")//登录访问路径
                .defaultSuccessUrl("/test/successUrl").permitAll()//登录成功后跳转路径
                .and().authorizeRequests()
                .antMatchers("/","/user/login").permitAll()//设置那些路径不需要认证，直接访问
                .anyRequest().authenticated()
                .and().csrf().disable();//关闭csrf防护
    }
```

​![image](assets/image-20230528225649-l9iyf90.png)​

### 3.3.1 引入前端模板依赖

```xml
<dependency>
<groupId>org.springframework.boot</groupId>
<artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>

```

### 3.3.2 引入登录页面

将准备好的登录页面导入项目中

### 3.3.3 编写控制器

```java
@Controller
public class IndexController {
@GetMapping("index")
public String index(){
return "login";
 }
@GetMapping("findAll")
@ResponseBody
public String findAll(){
return "findAll";
 }
}

```

### 3.3.4 编写配置类放行登录页面以及静态资源

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
// 注入 PasswordEncoder 类到 spring 容器中
@Bean
public PasswordEncoder passwordEncoder(){
return new BCryptPasswordEncoder();
 }
@Override
protected void configure(HttpSecurity http) throws Exception {
 http.authorizeRequests()
 .antMatchers("/layui/**","/index") //表示配置请求路径
.permitAll() // 指定 URL 无需保护。
.anyRequest() // 其他请求
.authenticated(); //需要认证
}
}

```

### 3.3.5 测试

访问 localhost:8090/index

​![image](assets/image-20230528165036-41t2r1m.png)​

访问 localhost:8090/findAll 会提示 403 错误 表示没有这个权限。

​![image](assets/image-20230528165053-a61f6ds.png)​

### 3.3.6 设置未授权的请求跳转到登录页

​`配置类`​

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
// 配置认证
http.formLogin()
 .loginPage("/index") // 配置哪个 url 为登录页面
.loginProcessingUrl("/login") // 设置哪个是登录的 url。
.successForwardUrl("/success") // 登录成功之后跳转到哪个 url
.failureForwardUrl("/fail");// 登录失败之后跳转到哪个 url
http.authorizeRequests()
 .antMatchers("/layui/**","/index") //表示配置请求路径
.permitAll() // 指定 URL 无需保护。
.anyRequest() // 其他请求
.authenticated(); //需要认证
// 关闭 csrf
http.csrf().disable();
}

```

​`控制器`​

```java
@PostMapping("/success")
public String success(){
return "success";
}
@PostMapping("/fail")
public String fail(){
return "fail";
}
```

​`前端页面`​

```html
<form action="/login"method="post">
用户名:<input type="text"name="username"/><br/>
密码：<input type="password"name="password"/><br/>
<input type="submit"value="提交"/>
</form>
```

**注意：页面提交方式必须为 post 请求，所以上面的页面不能使用，用户名，密码必须为 username,password**

**原因： 在执行登录的时候会走一个过滤器 UsernamePasswordAuthenticationFilter**

​![image](assets/image-20230528165325-rjt31s1.png)​

如果修改配置可以调用 usernameParameter()和 passwordParameter()方法。

```html
<form action="/login"method="post">
用户名:<input type="text"name="loginAcct"/><br/>
密码：<input type="password"name="userPswd"/><br/>
<input type="submit"value="提交"/>
</form>
```

​![image](assets/image-20230528165359-cfqk2c1.png)​

## 3.4 基于角色或权限进行访问控制

### 3.4.1 hasAuthority 方法

如果当前的主体具有指定的权限，则返回 true,否则返回 false

* 修改配置

  ​![image](assets/image-20230528165455-51x92j7.png)​
* 添加一个控制器

  ```java
  @GetMapping("/find")
  @ResponseBody
  public String find(){
  return "find";
  }

  ```
* 给用户登录主体赋予权限

  ​![image](assets/image-20230528165525-3sek7qp.png)​
* 测试：

  ​![image](assets/image-20230528165543-3s3ffj9.png)​

### 3.4.2 hasAnyAuthority 方法

	如果当前的主体有任何提供的角色（给定的作为一个逗号分隔的字符串列表）的话，返回 true

访问 http://localhost:8090/find

​![image](assets/image-20230528165618-nuzm6c1.png)​

### 3.4.3 hasRole 方法

如果用户具备给定角色就允许访问,否则出现 403。

 如果当前主体具有指定的角色，则返回 true。

底层源码：

​![image](assets/image-20230528165648-ryijsau.png)​

给用户添加角色：

​![image](assets/image-20230528165708-qsk4vm8.png)​

修改配置文件：

	 注意配置文件中不需要添加”ROLE_“，因为上述的底层代码会自动添加与之进行匹配。

​![image](assets/image-20230528165732-q6t4uwn.png)​

### 3.4.4 hasAnyRole

表示用户具备任何一个条件都可以访问。 

给用户添加角色：

​![image](assets/image-20230528165801-x0pqda0.png)​

修改配置文件：

​![image](assets/image-20230528165813-p2xp0bb.png)​

## 3.5 基于数据库实现权限认证

### 3.5.1 添加实体类

​`Menu`​

```java
@Data
public class Menu {
private Long id;
private String name;
private String url;
private Long parentId;
private String permission;
}

```

​`Role`​

```java
@Data
public class Role {
private Long id;
private String name;
}
```

### 3.5.2 编写接口与实现类

​`UserInfoMapper`​

```java
/**
* 根据用户 Id 查询用户角色
* @param userId
* @return
*/
List<Role> selectRoleByUserId(Long userId);
/**
* 根据用户 Id 查询菜单
* @param userId
* @return
*/
List<Menu> selectMenuByUserId(Long userId);
```

上述接口需要进行多表管理查询： 

需要在 resource/mapper 目录下自定义 UserInfoMapper.xml

​`UserInfoMapper.xml`​

```xml
<?xml version="1.0"encoding="utf-8"?>
<!DOCTYPEmapperPUBLIC"-//mybatis.org//DTD Mapper 
3.0//EN""http://mybatis.org/dtd/mybatis-3-mapper.dtd">
<mapper namespace="com.atguigu.mapper.UserInfoMapper">
<!--根据用户 Id 查询角色信息-->
<select id="selectRoleByUserId"resultType="com.atguigu.bean.Role">
 SELECT r.id,r.name FROM role r INNER JOIN role_user ru ON 
ru.rid=r.id where ru.uid=#{0}
</select>
<!--根据用户 Id 查询权限信息-->
<select id="selectMenuByUserId"resultType="com.atguigu.bean.Menu">
 SELECT m.id,m.name,m.url,m.parentid,m.permission FROM menu m
 INNER JOIN role_menu rm ON m.id=rm.mid
INNER JOIN role r ON r.id=rm.rid
INNER JOIN role_user ru ON r.id=ru.rid
WHERE ru.uid=#{0}
</select>
</mapper>

```

​`UsersServiceImpl`​

​![image](assets/image-20230528170143-vw95tlp.png)​

### 3.5.3 在配置文件中添加映射

在配置文件中 application.yml 添加

```xml
mybatis:
mapper-locations: classpath:mapper/*.xml

```

### 3.5.4 修改访问配置类

​![image](assets/image-20230528170232-yzr3ma2.png)​

### 3.5.5 使用管理员与非管理员进行测试

如果非管理员测试会提示 403 没有权限

​![image](assets/image-20230528170254-cnu1x4w.png)​

## 3.6 自定义 403 页面

### 3.6.1 修改访问配置类

```java
http.exceptionHandling().accessDeniedPage("/unauth");
```

### 3.6.2 添加对应控制器

```java
@GetMapping("/unauth")
public String accessDenyPage(){
return "unauth";
}

```

​`html`​

```html
unauth.html
<body>
<h1>对不起，您没有访问权限！</h1>
</body>
```

### 3.6.3 测试

​![image](assets/image-20230528170430-ei5da58.png)​

## 3.7 基于的注解使用

	在Spring Security中提供了一些访问控制的注解。这些注解都是默认是都不可用的，需要通过@EnableGlobalMethodsecurity进行开启后使用。制器方法上的，控制接口URL是否允许被访问。如果设置的条件允许，程序正常执行。如果不允许会报500

	org.springframework.security.access.AccessDeniedException:不允许访问这些注解可以写到Service接口或方法上上也可以写到Controller或 Controller的方法上。通常情况下都是写在控

### 3.7.1 @Secured

判断是否具有角色，另外需要注意的是这里匹配的字符串需要添加前缀“ROLE_“。 

使用注解先要开启注解功能！

```java
@EnableGlobalMethodSecurity(securedEnabled=true)
@SpringBootApplication
@EnableGlobalMethodSecurity(securedEnabled=true)
public class DemosecurityApplication {
public static void main(String[] args) {
 SpringApplication.run(DemosecurityApplication.class, args);
 }
}

```

​`在控制器方法上添加注解`​

注意：我们在配置类中是不允许家`ROLE_`​的但是我们的注解是必须加上`ROLE_`​

```java
// 测试注解：
@RequestMapping("testSecured")
@ResponseBody
@Secured({"ROLE_normal","ROLE_admin"})
public String helloUser() {
return "hello,user";
}
@Secured({"ROLE_normal","ROLE_管理员"})

```

登录之后直接访问：http://localhost:8090/testSecured 控制器 将上述的角色改为 @Secured({"ROLE_normal","ROLE_管理员"})即可访问

​![image](assets/image-20230528170617-hh56q02.png)​

### 3.7.2 @PreAuthorize

@PreAuthorize是方法或者类级别的注解

​`**功能：表示方法执行前判断权限，大多数情况下大家都是使用这个注解，注解的参数和acces()方法取值相同，都是权限表达方式,且这个注解也不能使用ROLE_开头**`​

​`先开启注解功能：`​​

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@PreAuthorize：注解适合进入方法前的权限验证， @PreAuthorize 可以将登录用
户的 roles/permissions 参数传到方法中。
@RequestMapping("/preAuthorize")
@ResponseBody
//@PreAuthorize("hasRole('ROLE_管理员')")
@PreAuthorize("hasAnyAuthority('menu:system')")
public String preAuthorize(){
 System.out.println("preAuthorize");
return "preAuthorize";
}

```

使用李四登录测试：

### 3.7.3 @PostAuthorize

​`先开启注解功能：`​

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@PostAuthorize 注解使用并不多，在方法执行后再进行权限验证，适合验证带有返回值
的权限.
@RequestMapping("/testPostAuthorize")
@ResponseBody
@PostAuthorize("hasAnyAuthority('menu:system')")
public String preAuthorize(){
 System.out.println("test--PostAuthorize");
return "PostAuthorize";
}

```

使用李四登录测试：

### 3.7.4 @PostFilter

​`先开启注解功能：`​

```java
@EnableGlobalMethodSecurity(prePostEnabled = true)
@PostAuthorize 注解使用并不多，在方法执行后再进行权限验证，适合验证带有返回值
的权限.
@RequestMapping("/testPostAuthorize")
@ResponseBody
@PostAuthorize("hasAnyAuthority('menu:system')")
public String preAuthorize(){
 System.out.println("test--PostAuthorize");
return "PostAuthorize";
}
```

使用李四登录测试：

### 3.7.5 @PreFilter

@PreFilter: 进入控制器之前对数据进行过滤

```java
@RequestMapping("getTestPreFilter")
@PreAuthorize("hasRole('ROLE_管理员')")
@PreFilter(value = "filterObject.id%2==0")
@ResponseBody
public List<UserInfo> getTestPreFilter(@RequestBody List<UserInfo> 
list){
 list.forEach(t-> {
 System.out.println(t.getId()+"\t"+t.getUsername());
 });
return list;
}
```

先登录，然后使用 postman 进行测试

​![image](assets/image-20230528170931-39544yk.png)​

​![image](assets/image-20230528170938-5cp0y1h.png)​

测试的Json数据：

```json
[
{
"id": "1",
"username": "admin",
"password": "666"
},
{
"id": "2",
"username": "admins",
"password": "888"
},
{
"id": "3",
"username": "admins11",
"password": "11888"
},
{
"id": "4",
"username": "admins22",
"password": "22888"
}]
```

### 3.7.6 权限表达式

https://docs.spring.io/springsecurity/site/docs/5.3.4.RELEASE/reference/html5/#el-access

## 3.8 基于数据库的记住我

### 3.8.1 创建表

```sql
CREATE TABLE `persistent_logins` (
 `username` varchar(64) NOT NULL,
 `series` varchar(64) NOT NULL,
 `token` varchar(64) NOT NULL,
 `last_used` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE 
CURRENT_TIMESTAMP,
 PRIMARY KEY (`series`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

### 3.8.2 添加数据库的配置文件

```yaml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    url: jdbc:mysql:///lkj?characeter=utf-8
    username: root
    password: 123456
mybatis-plus:
  configuration:
    map-underscore-to-camel-case: true # 开启驼峰命名转换
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl # 开启驼峰命名转换
  mapper-locations: classpath:/mappers/*.xml
```

### 3.8.3 编写配置类

```java
@Configuration
public class BrowserSecurityConfig {
@Autowired
private DataSource dataSource;
@Bean
public PersistentTokenRepository persistentTokenRepository(){
 JdbcTokenRepositoryImpl jdbcTokenRepository = new 
JdbcTokenRepositoryImpl();
// 赋值数据源
jdbcTokenRepository.setDataSource(dataSource);
// 自动创建表,第一次执行会创建，以后要执行就要删除掉！
jdbcTokenRepository.setCreateTableOnStartup(true);
return jdbcTokenRepository;
 }
}
```

### 3.8.4 修改安全配置类

```java
@Autowired
private UsersServiceImpl usersService;
@Autowired
private PersistentTokenRepository tokenRepository;
// 开启记住我功能
http.rememberMe()
 .tokenRepository(tokenRepository)
 .userDetailsService(usersService);

```

### 3.8.5 页面添加记住我复选框

```html
记住我：<input type="checkbox"name="remember-me"title="记住密码"/><br/>
```

此处：name 属性值必须位 remember-me.不能改为其他值

### 3.8.6 使用张三进行登录测试

登录成功之后，关闭浏览器再次访问 http://localhost:8090/find，发现依然可以使用！

​![image](assets/image-20230528171337-p0mg4sl.png)​

### 3.8.7 设置有效期

	默认 2 周时间。但是可以通过设置状态有效时间，即使项目重新启动下次也可以正常登 录。

在配置文件中设置

​![image](assets/image-20230528171359-cl4lp6x.png)​

## 3.9 用户注销

### 3.9.1 在登录页面添加一个退出连接

​`success.html`​

```html
<body>
登录成功<br>
<a href="/logout">退出</a>
</body>
```

### 3.9.2 在配置类中添加退出映射地址

```java
http.logout().logoutUrl("/logout").logoutSuccessUrl("/index").permitAll();

```

### 3.9.3 测试

退出之后，是无法访问需要登录时才能访问的控制器！

## 3.10 CSR

### 3.10.1 CSRF 理解

	跨站请求伪造（英语：Cross-site request forgery），也被称为 one-click  attack 或者 session riding，通常缩写为 CSRF 或者 XSRF， 是一种挟制用户在当前已 登录的 Web 应用程序上执行非本意的操作的攻击方法。跟跨网站脚本（XSS）相比，XSS 利用的是用户对指定网站的信任，CSRF 利用的是网站对用户网页浏览器的信任。

	跨站请求攻击，简单地说，是攻击者通过一些技术手段欺骗用户的浏览器去访问一个 自己曾经认证过的网站并运行一些操作（如发邮件，发消息，甚至财产操作如转账和购买 商品）。由于浏览器曾经认证过，所以被访问的网站会认为是真正的用户操作而去运行。 这利用了 web 中用户身份验证的一个漏洞：简单的身份验证只能保证请求发自某个用户的 浏览器，却不能保证请求本身是用户自愿发出的。

	从 Spring Security 4.0 开始，默认情况下会启用 CSRF 保护，以防止 CSRF 攻击应用 程序，Spring Security CSRF 会针对 PATCH，POST，PUT 和 DELETE 方法进行防护。

### 3.10.2 案例

在登录页面添加一个隐藏域：

```html
<input 
type="hidden"th:if="${_csrf}!=null"th:value="${_csrf.token}"name="_csrf
"/>
```

关闭安全配置的类中的 csrf

```java
// http.csrf().disable();

```

### 3.10.3 Spring Security 实现 CSRF 的原理：

1. 生成 csrfToken 保存到 HttpSession 或者 Cookie 中。

    ​![image](assets/image-20230528171707-4qhwus3.png)​

    当前接口实现类：HttpSessionCsrfTokenRepository，CookieCsrfTokenRepository

    ​​![image](assets/image-20230528171928-3s7e377.png)​​
2. ​请求到来时，从请求中提取 csrfToken，和保存的 csrfToken 做比较，进而判断当 前请求是否合法。主要通过 CsrfFilter 过滤器来完成。

    ​![image](assets/image-20230528172052-woeuvz0.png)​

# Oauth2认证

## Oauth简介

	第三方认证技术方案最主要是解决认证协议的通用标准问题，因为要实现跨系统认证，各系统之间要遵循一定的接 口协议。

	OAUTH协议为用户资源的授权提供了一个安全的、开放而又简易的标准。同时，任何第三方都可以使用OAUTH认 证服务，任何服务提供商都可以实现自身的OAUTH认证服务，因而OAUTH是开放的。业界提供了OAUTH的多种实 现如PHP、JavaScript，Java，Ruby等各种语言开发包，大大节约了程序员的时间，因而OAUTH是简易的。互联网很 多服务如Open API，很多大公司如Google，Yahoo，Microsoft等都提供了OAUTH认证服务，这些都足以说明 OAUTH标准逐渐成为开放资源授权的标准。Oauth协议目前发展到2.0版本，1.0版本过于复杂，2.0版本已得到广泛应用。 

参考：[https://baike.baidu.com/item/oAuth/7153134?fr=aladdin Oauth](https://baike.baidu.com/item/oAuth/7153134?fr=aladdin Oauth) 

协议：[https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749) 

下边分析一个Oauth2认证的例子

网站使用微信认证的过程： 1. 用户进入网站的登录页面，点击微信的图标以微信账号登录系统，用户是自己在微信里信息的资源拥有者。

​![image](assets/image-20230630114339-1r55ppu.png)

1. 用户进入网站的登录页面，点击微信的图标以微信账号登录系统，用户是自己在微信里信息的资源拥有者。

    ​![image](assets/image-20230630114419-ghcbgf3.png)​

    点击“微信”出现一个二维码，此时用户扫描二维码，开始给网站授权。

    ​![image](assets/image-20230630114441-p85bded.png)​
2. 资源拥有者同意给客户端授权

    资源拥有者扫描二维码表示资源拥有者同意给客户端授权，微信会对资源拥有者的身份进行验证，验证通过后，微 信会询问用户是否给授权网站访问自己的微信数据，用户点击“确认登录”表示同意授权，微信认证服务器会颁发一个 授权码，并重定向到网站
3. 客户端获取到授权码，请求认证服务器申请令牌

    此过程用户看不到，客户端应用程序请求认证服务器，请求携带授权码。
4. 认证服务器向客户端响应令牌

    认证服务器验证了客户端请求的授权码，如果合法则给客户端颁发令牌，令牌是客户端访问资源的通行证。此交互 过程用户看不到，当客户端拿到令牌后，用户在网站看到已经登录成功。
5. 客户端请求资源服务器的资源

    客户端携带令牌访问资源服务器的资源。网站携带令牌请求访问微信服务器获取用户的基本信息。
6. 资源服务器返回受保护资源

    资源服务器校验令牌的合法性，如果合法则向用户响应资源信息内容。

    ​`注意:`​资源服务器和认证服务器可以是一个服务也可以分开的服务，如果是分开的服务资源服务器通常要请求认证服 务器来校验令牌的合法性。
7. Oauth2.0认证流程如下：

    引自Oauth2.0协议rfc6749: [https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749)

    ​![image](assets/image-20230630114733-sfe02br.png)​

### 角色

1. 本身不存储资源，需要通过资源拥有者的授权去请求资源服务器的资源，比如：Android客户端、Web客户端（浏览器端）、微信客户端等。
2. 资源拥有者

    通常为用户，也可以是应用程序，即该资源的拥有者。
3. 授权服务器（也称认证服务器）

    用来对资源拥有的身份进行认证、对访问资源进行授权。客户端要想访问资源需要通过认证服务器由资源拥有者授权 后方可访问。
4. 资源服务器

    存储资源的服务器，比如，网站用户管理服务器存储了网站用户信息，网站相册服务器存储了用户的相册信息，微信 的资源服务存储了微信的用户信息等。客户端最终访问资源服务器获取资源信息。

### 常用术语

* 客户凭证(client Credentials) ：客户端的clientId和密码用于认证客户
* 令牌(tokens) ：授权服务器在接收到客户请求后，颁发的访问令牌 

  * 令牌类型

    * 授权码 ：仅用于授权码授权类型，用于交换获取访问令牌和刷新令牌
    * 访问令牌 ：用于代表一个用户或服务直接去访问受保护的资源
    * 刷新令牌 ：用于去授权服务器获取一个刷新访问令牌
    * BearerToken ：不管谁拿到Token都可以访问资源，类似现金
    * Proof of Possession(PoP) Token ：可以校验client是否对Token有明确的拥有权
* 作用域(scopes) ：客户请求访问令牌时，由资源拥有者额外指定的细分权限(permission)
* 特点

  * 优点：

    * 更安全，客户端不接触用户密码，服务器端更易集中保护
    * 广泛传播并被持续采用
    * 短寿命和封装的token
    * 资源服务器和授权服务器解耦
    * 集中式授权，简化客户端
    * HTTP/JSON友好，易于请求和传递token
    * HTTP/JSON友好，易于请求和传递token
    * 客户可以具有不同的信任级别
  * 缺点：

    * 协议框架太宽泛，造成各种实现的兼容性和互操作性差
    * 不是一个认证协议，本身并不能告诉你任何用户信息。

## 授权模式（四种授权方式）

### 授权模式（Authorization Code）

​![image](assets/image-20230630145400-qvr8zjr.png)

### 简化授权模式（Implicit）

​![image](assets/image-20230630145618-oqhmyii.png)

### 密码模式（Resource Owner PasswordCredentials）

​![image](assets/image-20230630145819-m4jmkgz.png)​

### 客户端模式（Client Credentials）

​![image](assets/image-20230630145913-zjneghe.png)​

### 刷新令牌

​![image](assets/image-20230630150011-n81ekm3.png)​

## SpringSecurity Oauth2

### 授权服务器

​![image](assets/image-20230630150220-p9oxvfr.png)

* Authorize Endpoint ：授权端点，进行授权
* Token Endpoint ：令牌端点，经过授权拿到对应的Token
* Introspection Endpoint ：校验端点，校验Token的合法性
* Revocation Endpoint ：撤销端点，撤销授权

## SpringSecurity Oauth2架构

​![image](assets/image-20230630150430-cs7o37m.png)​

1. 流程： 

    1.  用户访问,此时没有Token。Oauth2RestTemplate会报错，这个报错信息会被Oauth2ClientContextFilter捕获 并重定向到认证服务器
    2. 认证服务器通过Authorization Endpoint进行授权，并通过AuthorizationServerTokenServices生成授权码并返 回给客户端
    3. 客户端拿到授权码去认证服务器通过Token Endpoint调用AuthorizationServerTokenServices生成Token并返 回给客户端
    4. 客户端拿到Token去资源服务器访问资源，一般会通过Oauth2AuthenticationManager调用 ResourceServerTokenServices进行校验。校验通过可以获取资源。

# JWT

## 什么是JWT？

	JSON Web Token（JWT）是一个开放的行业标准（RFC 7519），它定义了一种简介的、自包含的协议格式，用于  
在通信双方传递json对象，传递的信息经过数字签名可以被验证和信任。JWT可以使用HMAC算法或使用RSA的公钥/  
私钥对来签名，防止被篡改

官网：[https://jwt.io/](https://jwt.io/)

标准： [https://tools.ietf.org/html/rfc7519](https://tools.ietf.org/html/rfc7519)

1. JWT令牌的优点：

    1. jwt基于json，非常方便解析。
    2. 可以在令牌中自定义丰富的内容，易扩展。
    3. 通过非对称加密算法及数字签名技术，JWT防止篡改，安全性高。
    4. 资源服务使用JWT可不依赖认证服务即可完成授权。
2. 缺点：

    1. JWT令牌较长，占存储空间比较大。

## JWT组成

一个JWT实际上就是一个字符串，它由三部分组成，头部、载荷与签名

### 头部(Header)

头部用于描述关于该JWT的最基本的信息，例如其类型（即JWT）以及签名所用的算法（如HMAC SHA256或RSA）  
等。这也可以被表示成一个JSON对象。

```json
{
"alg": "HS256",
"typ": "JWT"
}
```

* typ ：是类型。
* alg ：签名的算法，这里使用的算法是HS256算法

我们对头部的json字符串进行BASE64编码（网上有很多在线编码的网站），编码后的字符串如下：

```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

​`Base64`​ 是一种基于64个可打印字符来表示二进制数据的表示方法。由于2的6次方等于64，所以每6个比特为一个  
单元，对应某个可打印字符。三个字节有24个比特，对应于4个Base64单元，即3个字节需要用4个可打印字符来表  
示。JDK 中提供了非常方便的 `BASE64Encoder`​ 和 `BASE64Decoder`​ ，用它们可以非常方便的完成基于 BASE64 的编  
码和解码。

### 负载(Payload)

1. 第二部分是负载，就是存放有效信息的地方。这个名字像是特指飞机上承载的货品，这些有效信息包含三个部分：

    1. 标准中注册的声明（建议但不强制使用）

        ```json
        iss: jwt签发者
        sub: jwt所面向的用户
        aud: 接收jwt的一方
        exp: jwt的过期时间，这个过期时间必须要大于签发时间
        nbf: 定义在什么时间之前，该jwt都是不可用的.
        iat: jwt的签发时间
        jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
        ```
    2. 公共的声明

        公共的声明可以添加任何的信息，一般添加用户的相关信息或其他业务需要的必要信息.但不建议添加敏感信息，  
        因为该部分在客户端可解密
    3. 私有的声明

        私有声明是提供者和消费者所共同定义的声明，一般不建议存放敏感信息，因为base64是对称解密的，意味着该  
        部分信息可以归类为明文信息。

        这个指的就是自定义的claim。比如下面那个举例中的name都属于自定的claim。这些claim跟JWT标准规定的  
        claim区别在于：JWT规定的claim，JWT的接收方在拿到JWT之后，都知道怎么对这些标准的claim进行验证(还不知道是否能够验证)；而private claims不会验证，除非明确告诉接收方要对这些claim进行验证以及规则才行。

        ```json
        {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1516239022
        }
        ```

        其中 sub 是标准的声明， name 是自定义的声明（公共的或私有的)

        然后将其进行base64编码，得到Jwt的第二部分：

        ```json
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbWVzIiwiYWRtaW4iOnRydWV9
        ```

        提示：声明中不要放一些敏感信息。
    4. 签证、签名（signature）

        1. jwt的第三部分是一个签证信息，这个签证信息由三部分组成：

            1. header (base64后的)
            2. payload (base64后的)
            3. secret（盐，一定要保密）
        2. 这个部分需要base64加密后的header和base64加密后的payload使用.连接组成的字符串，然后通过header中声明的加密方式进行加盐secret组合加密，然后就构成了jwt的第三部分：

            ```json
            8HI-Lod0ncfVDnbKIPJJqLH998duF9DSDGkx3gRPNVI
            ```

        1. 将这三部分用.连接成一个完整的字符串,构成了最终的jwt:

            ```json
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaW
            F0IjoxNTE2MjM5MDIyfQ.8HI-Lod0ncfVDnbKIPJJqLH998duF9DSDGkx3gRPNVI
            ```
        2. 注意： secret 是保存在服务器端的， jwt 的签发生成也是在服务器端的， secret 就是用来进行 jwt 的签发和 jwt  
            的验证，所以，它就是你服务端的私钥，在任何场景都不应该流露出去。一旦客户端得知这个 secret , 那就意味着客户端是可以自我签发 jwt 了。

### 创建一个JWTDemo

1. 引入依赖

    ```xml
            <!--JWT依赖-->
            <dependency>
                <groupId>io.jsonwebtoken</groupId>
                <artifactId>jjwt</artifactId>
                <version>0.9.0</version>
            </dependency>
    ```
2. ​`TestJwtDemo01`​

    ```java
    package com.lkjedu.boot;

    import static org.junit.Assert.assertTrue;

    import io.jsonwebtoken.JwtBuilder;
    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.SignatureAlgorithm;
    import io.jsonwebtoken.impl.Base64Codec;
    import org.junit.Test;

    import java.util.Date;

    /**
     * Unit test for simple App.
     */
    public class AppTest {
        /**
         * Rigorous Test :-)
         */
        @Test
        public void testJwtDemo01() {
            //创建一个JwtBuilder对象
            JwtBuilder jwtBuilder = Jwts.builder()
            //声明的标识{"jti":"888"}
                    .setId("888")
            //主体，用户{"sub":"Rose"}
                    .setSubject("Rose")
            //创建日期{"ita":"xxxxxx"}
                    .setIssuedAt(new Date())
            //签名手段，参数1：算法，参数2：盐
                    .signWith(SignatureAlgorithm.HS256,"xxxx");
            //获取jwt的token
            String token = jwtBuilder.compact();
            System.out.println(token);
            //三部分的base64解密
            System.out.println("--------------------");
            String[] split = token.split("\\.");
            System.out.println(Base64Codec.BASE64.decodeToString(split[0]));
            System.out.println(Base64Codec.BASE64.decodeToString(split[1]));
            //无法解密
            System.out.println(Base64Codec.BASE64.decodeToString(split[2]));
        }
    }
    ```
3. 运行结果

    ​![image](assets/image-20230630170326-dxmhhdi.png)​

### token的验证解析

我们刚才已经创建了token ，在web应用中这个操作是由服务端进行然后发给客户端，客户端在下次向服务端发送  
请求时需要携带这个token（这就好像是拿着一张门票一样），那服务端接到这个token 应该解析出token中的信息  
（例如用户id）,根据这些信息查询数据库返回相应的结果。

```java
    @Test
    public void testParseToken(){
        //token
        String token =
                "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4ODgiLCJzdWIiOiJSb3NlIiwiaWF0IjoxNjg4MTE1NzE2fQ.rx5FGlniHF8HXfaVWJvB-QtIiGYbhvcNJvYAbZe2meY";
        //解析token获取负载中的声明对象
        Claims claims = Jwts.parser()
                .setSigningKey("xxxx")
                .parseClaimsJws(token)
                .getBody();
        //打印声明的属性
        System.out.println("id:"+claims.getId());
        System.out.println("subject:"+claims.getSubject());
        System.out.println("issuedAt:"+claims.getIssuedAt());
    }
```

​![image](assets/image-20230630170550-577rtgb.png)​

### token过期校验

	有很多时候，我们并不希望签发的token是永久生效的（上节的token是永久的），所以我们可以为token添加一个过期时间。原因：从服务器发出的token，服务器自己并不做记录，就存在一个弊端就是，服务端无法主动控制某token的立刻失效。

1. 测试用例：

    ```java
        @Test
        public void testCreatTokenHasExp() {
            //当前系统时间的长整型
            long now = System.currentTimeMillis();
            //过期时间，这里是1分钟后的时间长整型
            long exp = now + 60 * 1000;
            //创建一个JwtBuilder对象
            JwtBuilder jwtBuilder = Jwts.builder()
            //声明的标识{"jti":"888"}
                    .setId("888")
            //主体，用户{"sub":"Rose"}
                    .setSubject("Rose")
            //创建日期{"ita":"xxxxxx"}
                    .setIssuedAt(new Date())
            //签名手段，参数1：算法，参数2：盐
                    .signWith(SignatureAlgorithm.HS256, "xxxx")
            //设置过期时间
                    .setExpiration(new Date(exp));
            //获取jwt的token
            String token = jwtBuilder.compact();
            System.out.println(token);
        }
        @Test
        public void testParseTokenHasExp() {
            //token
            String token = "eyJhbGciOiJIUzI1NiJ9" +
                    ".eyJqdGkiOiI4ODgiLCJzdWIiOiJSb3NlIiwiaWF0IjoxNTc4ODE1MDYyLCJleHAiOjE1Nzg4MTUxMjIsInJvbGVzI joiYWRtaW4iLCJsb2dvIjoic2hzeHQuanBnIn0.hKog0RsZ9_6II_R8kUCp0HLAouUAYXAJVbz3xtLTUh4";
            //解析token获取负载中的声明对象
            Claims claims = Jwts.parser()
                    .setSigningKey("xxxx")
                    .parseClaimsJws(token)
                    .getBody();
            //打印声明的属性
            System.out.println("id:" + claims.getId());
            System.out.println("subject:" + claims.getSubject());
            System.out.println("issuedAt:" + claims.getIssuedAt());
            DateFormat sf =new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            System.out.println("签发时间:"+sf.format(claims.getIssuedAt()));
            System.out.println("过期时间:"+sf.format(claims.getExpiration()));
            System.out.println("当前时间:"+sf.format(new Date()));
        }
    ```
2. 测试：当未过期时可以正常读取，当过期时会引发io.jsonwebtoken.ExpiredJwtException异常。

    ​![image](assets/image-20230630171121-gtbop90.png)​

### 自定义claims

我们刚才的例子只是存储了id和subject两个信息，如果你想存储更多的信息（例如角色）可以定义自定义claims

1. 测试用例：

    ```java
        @Test
        public void testCreatTokenByClaims() {
            //当前系统时间的长整型
            long now = System.currentTimeMillis();
            //过期时间，这里是1分钟后的时间长整型
            long exp = now + 60 * 1000;
            //创建一个JwtBuilder对象
            JwtBuilder jwtBuilder = Jwts.builder()
            //声明的标识{"jti":"888"}
                    .setId("888")
            //主体，用户{"sub":"Rose"}
                    .setSubject("Rose")
            //创建日期{"ita":"xxxxxx"}
                    .setIssuedAt(new Date())
            //签名手段，参数1：算法，参数2：盐
                    .signWith(SignatureAlgorithm.HS256, "xxxx")
            //设置过期时间
                    .setExpiration(new Date(exp))
            //直接传入map
            // .addClaims(map)
                    .claim("roles","admin")
                    .claim("logo","shsxt.jpg");
            //获取jwt的token
            String token = jwtBuilder.compact();
            System.out.println(token);
        }
        @Test
        public void testParseTokenByClaims() {
            //token
            String token = "eyJhbGciOiJIUzI1NiJ9" +
                    ".eyJqdGkiOiI4ODgiLCJzdWIiOiJSb3NlIiwiaWF0IjoxNTc4ODE1MDYyLCJleHAiOjE1Nzg4MTUxMjIsInJvbGVzI joiYWRtaW4iLCJsb2dvIjoic2hzeHQuanBnIn0.hKog0RsZ9_6II_R8kUCp0HLAouUAYXAJVbz3xtLTUh4";
            //解析token获取负载中的声明对象
            Claims claims = Jwts.parser()
                    .setSigningKey("xxxx")
                    .parseClaimsJws(token)
                    .getBody();
            //打印声明的属性
            System.out.println("id:" + claims.getId());
            System.out.println("subject:" + claims.getSubject());
            System.out.println("issuedAt:" + claims.getIssuedAt());
            DateFormat sf =new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");智者乐水 仁者乐山 程序员 乐字节2如果需要更多优质的Java、Python、架构、大数据等IT资料请加微信：lezijie007
            System.out.println("签发时间:"+sf.format(claims.getIssuedAt()));
            System.out.println("过期时间:"+sf.format(claims.getExpiration()));
            System.out.println("当前时间:"+sf.format(new Date()));
            System.out.println("roles:"+claims.get("roles"));
            System.out.println("logo:"+claims.get("logo"));
        }
    ```

# 4.SpringSecurity 微服务权限方案

‍
