package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtUserNameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        /**
         * notice: the order of antMatchers is very important so if we change the order if any antMatchers that impact the functionality of pour path security
         * and to try this try to remove the param HttpMethod.GET from ligne 45 or try de move it at line 42
         */
        http
                .csrf().disable() // this is spring security configuration
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // this is jwt configuration
                .and()
                .addFilter(new JwtUserNameAndPasswordAuthenticationFilter(authenticationManager())) // this is jwt configuration (this is our filter)
                .authorizeRequests()
                .antMatchers("index").permitAll() // this is spring security configuration
                .antMatchers("/api/**").hasRole(STUDENT.name())  // this is spring security configuration
                /**
                 * we are replaced this with PreAuthorize annotation
                 *.antMatchers(HttpMethod.DELETE, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
                 *.antMatchers(HttpMethod.POST, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
                 *.antMatchers(HttpMethod.PUT, "/management/api/v1/students/**").hasAuthority(COURSE_WRITE.getPermission())
                 *.antMatchers(HttpMethod.GET, "/management/api/v1/students/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                 */
                .anyRequest()  // this is spring security configuration
                .authenticated(); // this is spring security configuration

                /**
                 *we are replaced this with JWT
                formLogin()
                    .loginPage("/login").permitAll()
                    .defaultSuccessUrl("/courses", true)
                .passwordParameter("password")
                .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21)) // defaults to 2 weeks
                    .key("dali")
                    .rememberMeParameter("remember-me")
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
                    **/
    }

    /** @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails student = User.builder()
                .username("student")
                .password(passwordEncoder.encode("student"))
//                .roles(STUDENT.name())
                .authorities(STUDENT.getGrantedAuthorities())
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("admin"))
//                .roles(ADMIN.name())
                .authorities(ADMIN.getGrantedAuthorities())
                .build();
        UserDetails admintrainee = User.builder()
                .username("admintrainee")
                .password(passwordEncoder.encode("admintrainee"))
//                .roles(ADMINTRAINEE.name())
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(student, admin, admintrainee);
    }**/

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }
}
