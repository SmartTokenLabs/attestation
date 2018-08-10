package identity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class HelloWorld {
    public static void main(String[] args) {
        WebFlowConfig greeter = new WebFlowConfig();
        System.out.println(greeter.sayHello());
    }
}
