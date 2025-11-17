package htlkaindorf.springsecuritydemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class DemoController {

    // -- PUBLIC --
    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from PUBLIC endpoint! No token needed.";
    }

    // -- PRIVATE --
    @GetMapping("/private/hello")
    public String privateHello() {
        return "Hello from PRIVATE endpoint! Valid token needed.";
    }

}
