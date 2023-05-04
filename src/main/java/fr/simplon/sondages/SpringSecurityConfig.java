package fr.simplon.sondages;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {

    @Autowired
    private javax.sql.DataSource dataSource;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
        return http
                .csrf().disable() // Pour l'instant on désactive la protection CSRF
                .authorizeHttpRequests()
                .requestMatchers("/connexion", "/inscription").permitAll()
                .requestMatchers(HttpMethod.GET, "/**").permitAll()
                .requestMatchers(HttpMethod.PUT, "/**").permitAll()
                .requestMatchers(HttpMethod.POST, "/votes/*").authenticated()
                .requestMatchers(HttpMethod.GET, "/votes/*").authenticated()
                .requestMatchers(HttpMethod.DELETE, "/*").authenticated()
                .requestMatchers("/admin/**").hasRole("ADMIN") //
                .requestMatchers("/admin/createUser").hasAuthority("CREATE_USER")
                .anyRequest().permitAll()//
                .and().formLogin()
                .and().build();
    }

    @Bean
    public UserDetailsManager users(DataSource dataSource)
    {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
