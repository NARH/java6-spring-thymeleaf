/*
 * Copyright (c) 2018, NARH https://github.com/NARH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.github.narh;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.format.FormatterRegistry;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.config.annotation.ContentNegotiationConfigurer;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.spring4.SpringTemplateEngine;
import org.thymeleaf.spring4.templateresolver.SpringResourceTemplateResolver;
import org.thymeleaf.spring4.view.ThymeleafViewResolver;
import org.thymeleaf.templatemode.TemplateMode;

/**
 * @author narita
 *
 */
@Configuration
@EnableWebMvc
@ComponentScan
public class SpringWebConfig extends WebMvcConfigurerAdapter implements ApplicationContextAware {

  private ApplicationContext applicationContext;

  /* (非 Javadoc)
   * @see org.springframework.context.ApplicationContextAware#setApplicationContext(org.springframework.context.ApplicationContext)
   */
  public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  @Override
  public void configureContentNegotiation(ContentNegotiationConfigurer configurer) {
      configurer.mediaType("json", MediaType.APPLICATION_JSON);
  }

  @Override
  public void addResourceHandlers(final ResourceHandlerRegistry registry) {
      super.addResourceHandlers(registry);
      registry.addResourceHandler("/images/**").addResourceLocations("/images/");
      registry.addResourceHandler("/css/**").addResourceLocations("/css/");
      registry.addResourceHandler("/js/**").addResourceLocations("/js/");
  }

  @Bean
  public ResourceBundleMessageSource messageSource() {
      ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
      messageSource.setBasename("Messages");
      return messageSource;
  }

  @Override
  public void addFormatters(final FormatterRegistry registry) {
      super.addFormatters(registry);
  }

  @Bean
  public SpringResourceTemplateResolver templateResolver(){
      SpringResourceTemplateResolver templateResolver = new SpringResourceTemplateResolver();
      templateResolver.setApplicationContext(this.applicationContext);
      templateResolver.setPrefix("/WEB-INF/templates/");
      templateResolver.setSuffix(".html");
      templateResolver.setTemplateMode(TemplateMode.HTML);
      templateResolver.setCacheable(false);
      templateResolver.setCharacterEncoding("UTF-8");
      return templateResolver;
  }

  @Bean
  public SpringTemplateEngine templateEngine(){
      SpringTemplateEngine templateEngine = new SpringTemplateEngine();
      templateEngine.setTemplateResolver(templateResolver());
      templateEngine.setEnableSpringELCompiler(true);
      return templateEngine;
  }

  @Bean
  public ThymeleafViewResolver viewResolver(){
      ThymeleafViewResolver viewResolver = new ThymeleafViewResolver();
      viewResolver.setTemplateEngine(templateEngine());
      viewResolver.setCharacterEncoding("UTF-8");
      return viewResolver;
  }
}
