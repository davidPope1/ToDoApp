package com.in28minutes.learn_spring_security.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class BasicAuthSecurityConfiguration {
	
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests(
				auth -> {
					auth
					.requestMatchers("/users").hasRole(Roles.USER.getRole())
					.requestMatchers("/admin/**").hasRole(Roles.ADMIN.getRole())
					.anyRequest().authenticated();
				});
		http.sessionManagement(
				session -> 
					session.sessionCreationPolicy(
							SessionCreationPolicy.STATELESS)
				);
//		http.formLogin(withDefaults());
		http.httpBasic(withDefaults());
		
		http.csrf(csrf -> csrf.disable());
		
		http.headers(headersConfigurer -> headersConfigurer
				.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
		
		return http.build();
	}
	
	public enum Roles {
		USER("USER"),
		ADMIN("ADMIN");
		
		private String role;
		
		Roles(String role) {
			this.role = role;
		}
		
		public String getRole() {
			return this.role;
		}
	}
//	
//	@Bean
//	public UserDetailsService userDetailService() {
//		
//		var user = User.withUsername("in28minutes")
//			.password("{noop}dummy")
//			.roles(Roles.USER.getRole())
//			.build();
//		
//		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
//				.roles(Roles.ADMIN.getRole())
//				.build();
//		
//		return new InMemoryUserDetailsManager(user, admin);
//	}
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder()
				.setType(EmbeddedDatabaseType.H2)
				.addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
				.build();
	}
	
	@Bean
	public UserDetailsService userDetailService(DataSource dataSource) {
		
		var user = User.withUsername("in28minutes")
//			.password("{noop}dummy")
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles(Roles.USER.getRole())
			.build();
		
		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles(Roles.ADMIN.getRole(), Roles.USER.getRole())
				.build();
		
		var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
		jdbcUserDetailsManager.createUser(user);
		jdbcUserDetailsManager.createUser(admin);

		return jdbcUserDetailsManager;
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

}
