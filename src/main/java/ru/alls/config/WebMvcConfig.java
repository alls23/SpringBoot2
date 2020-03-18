package ru.alls.config;

import nz.net.ultraq.thymeleaf.LayoutDialect;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.Validator;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import org.springframework.web.servlet.config.annotation.*;
import org.thymeleaf.extras.springsecurity4.dialect.SpringSecurityDialect;

@Configuration
@ComponentScan("ru.alls")
public class WebMvcConfig implements WebMvcConfigurer {
	@Autowired
	private MessageSource messageSource;

	@Override
	public void addViewControllers(ViewControllerRegistry registry)
	{
		registry.addViewController("/").setViewName("index");
		registry.addViewController("/login").setViewName("login");
		//registry.addViewController("/home").setViewName("userhome");
		registry.addViewController("/admin/adminhome").setViewName("adminhome");
		//registry.addViewController("/403").setViewName("403");
	}
	@Bean
	public LayoutDialect layoutDialect() {
		return new LayoutDialect();
	}





	@Override
	public Validator getValidator() {
		LocalValidatorFactoryBean factory = new LocalValidatorFactoryBean();
		factory.setValidationMessageSource(messageSource);
		return factory;
	}

	@Bean
	public SpringSecurityDialect securityDialect() {
		return new SpringSecurityDialect();
	}
}

