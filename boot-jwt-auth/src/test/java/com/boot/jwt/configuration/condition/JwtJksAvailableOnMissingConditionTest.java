package com.boot.jwt.configuration.condition;


import org.junit.After;
import org.junit.Test;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.PropertiesPropertySource;

import java.util.Objects;
import java.util.Properties;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

public class JwtJksAvailableOnMissingConditionTest {


    private ConfigurableApplicationContext applicationContext;

    @After
    public void tearDown() throws Exception {
        if (Objects.nonNull(applicationContext)) {
            applicationContext.close();
        }
    }

    @Test
    public void whenJksIsAvailableCondition() throws Exception {
        loadContext("jwt.auth.keyStore", "classpath:sample.jks", JksAvailableConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(true));

    }

    @Test
    public void whenJksFileNotExists() throws Exception {
        loadContext("jwt.auth.keyStore", "xyz1", JksAvailableConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(false));
    }

    @Test
    public void whenJksPropertyIsMissing() throws Exception {
        loadContext("jwt.auth.abc", "xyz1", JksAvailableConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(false));
    }


    @Test
    public void JksOnMissingNoProperty() throws Exception {
        loadContext("jwt.auth.abc", "xyz1", JksOnMissingConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(true));
    }


    @Test
    public void JksOnMissingWhenFileNotExists() throws Exception {
        loadContext("jwt.auth.keyStore", "xyz1", JksOnMissingConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(true));
    }

    @Test
    public void JksOnMissingWhenJksExists() throws Exception {
        loadContext("jwt.auth.keyStore", "classpath:sample.jks", JksOnMissingConfig.class);
        assertThat(applicationContext.containsBean("testResource"), is(false));

    }

    void loadContext(String key, String value, Class<?> configClass) {
        Properties properties = new Properties();
        properties.put(key, value);

        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext();
        context.getEnvironment().getPropertySources().addFirst(new PropertiesPropertySource("custom", properties));
        context.register(configClass);
        context.refresh();
        applicationContext = context;
    }


    public static class TestResource {
    }


    @Configuration
    @Conditional(JwtJksAvailableCondition.class)
    public static class JksAvailableConfig {

        @Bean
        public TestResource testResource() {
            return new TestResource();
        }
    }

    @Configuration
    @Conditional(JwtJksOnMissingCondition.class)
    public static class JksOnMissingConfig {

        @Bean
        public TestResource testResource() {
            return new TestResource();
        }
    }

}