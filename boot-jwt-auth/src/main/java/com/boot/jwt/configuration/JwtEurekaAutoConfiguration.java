package com.boot.jwt.configuration;

import com.boot.jwt.configuration.condition.JwtJksOnMissingCondition;
import com.boot.jwt.core.key.GenratedRSAKeystore;
import com.boot.jwt.core.key.Keystore;
import com.boot.jwt.key.DiscoveryPublicKeyRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.netflix.eureka.EurekaClientAutoConfiguration;
import org.springframework.cloud.netflix.eureka.EurekaInstanceConfigBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertiesPropertySource;

import java.util.Properties;

@Configuration
@ConditionalOnClass({EurekaInstanceConfigBean.class})
@AutoConfigureBefore({EurekaClientAutoConfiguration.class, JwtAuthAutoConfiguration.class})
@ConditionalOnProperty(prefix = "jwt.auth", name = "algo", havingValue = "RSA")
public class JwtEurekaAutoConfiguration {

    public static final String JWT_EUREKA_SOURCE = "eurekajwtconfig";
    private final String EUREKA_PUBLIC_KEY = "eureka.instance.metadataMap.publickey";


    @Autowired
    private ConfigurableEnvironment environment;


    @Bean
    @ConditionalOnMissingBean(Keystore.class)
    @Conditional(JwtJksOnMissingCondition.class)
    public Keystore generatedKeystore(DiscoveryClient discoveryClient) {

        DiscoveryPublicKeyRegistry keyRegistry = new DiscoveryPublicKeyRegistry(discoveryClient);
        GenratedRSAKeystore genratedRSAKeystore = new GenratedRSAKeystore(keyRegistry);
        genratedRSAKeystore.init();

        Properties properties = new Properties();
        properties.setProperty(EUREKA_PUBLIC_KEY, genratedRSAKeystore.getPublicKeyBase64());
        environment.getPropertySources().addFirst(new PropertiesPropertySource(JWT_EUREKA_SOURCE, properties));

        return genratedRSAKeystore;
    }
}

