package com.ginkgooai.core.gateway.config;


import com.ginkgooai.core.gateway.filter.CachingRequestBodyFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class FilterConfig {

    /**
     * Creates and configures a FilterRegistrationBean for the CachingRequestBodyFilter.
     * This filter is registered to intercept all requests and is set to the highest precedence.
     *
     * @return A FilterRegistrationBean configured for the CachingRequestBodyFilter.
     */
    @Bean
    public FilterRegistrationBean<CachingRequestBodyFilter> cachingRequestBodyFilter() {
        FilterRegistrationBean<CachingRequestBodyFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new CachingRequestBodyFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

}
