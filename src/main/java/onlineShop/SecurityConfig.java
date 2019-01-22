package onlineShop;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DataSource dataSource;//利用数据库对密码进行验证
	//验证用户是否有权限访问
	protected void configure(HttpSecurity http) throws Exception {
		http
			.csrf().disable()/*cross-side disable check token*/
			.formLogin()
				.loginPage("/login")
			.and()
			.authorizeRequests()
			.antMatchers("/cart/**").hasAuthority("ROLE_USER")
			.antMatchers("/get*/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
			.antMatchers("/admin*/**").hasAuthority("ROLE_ADMIN")
			.anyRequest().permitAll()
			.and()
			.logout()/*清除login cookie*/	
				.logoutUrl("/logout");
	}
	//验证用户名密码是否匹配
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("linj7356@gmail.com").password("123456").authorities("ROLE_ADMIN");//授权为admin
//.and().withUser("stefanlaioffer@gmail.com").password("123456").authorities("ROLE_ADMIN"); 添加多个admin；
		
		auth
			.jdbcAuthentication()
			.dataSource(dataSource)/*到数据库查找*/
			.usersByUsernameQuery("SELECT emailId, password, enabled FROM users WHERE emailId=? ")/*check email and password exsit in users table*/
			.authoritiesByUsernameQuery("SELECT emailId,authorities FROM authorities WHERE emailId =?");/*check authorities of user*/
	}
}
