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
	private DataSource dataSource;//�������ݿ�����������֤
	//��֤�û��Ƿ���Ȩ�޷���
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
			.logout()/*���login cookie*/	
				.logoutUrl("/logout");
	}
	//��֤�û��������Ƿ�ƥ��
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
			.withUser("linj7356@gmail.com").password("123456").authorities("ROLE_ADMIN");//��ȨΪadmin
//.and().withUser("stefanlaioffer@gmail.com").password("123456").authorities("ROLE_ADMIN"); ��Ӷ��admin��
		
		auth
			.jdbcAuthentication()
			.dataSource(dataSource)/*�����ݿ����*/
			.usersByUsernameQuery("SELECT emailId, password, enabled FROM users WHERE emailId=? ")/*check email and password exsit in users table*/
			.authoritiesByUsernameQuery("SELECT emailId,authorities FROM authorities WHERE emailId =?");/*check authorities of user*/
	}
}
