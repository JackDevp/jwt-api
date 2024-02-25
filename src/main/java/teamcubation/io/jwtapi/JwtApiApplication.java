package teamcubation.io.jwtapi;

import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import teamcubation.io.jwtapi.config.RsaKeyConfigProperties;

@EnableConfigurationProperties(RsaKeyConfigProperties.class)
@SpringBootApplication
public class JwtApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApiApplication.class, args);
    }

    @Bean
    ApplicationRunner runner(PasswordEncoder passwordEncoder){
        return args -> System.out.println(passwordEncoder.encode("password"));
    }

}
