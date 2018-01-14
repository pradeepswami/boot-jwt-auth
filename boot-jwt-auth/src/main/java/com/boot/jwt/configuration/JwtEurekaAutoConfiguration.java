package com.boot.jwt.configuration;

import com.boot.jwt.core.key.GenratedRSAKeystore;
import com.boot.jwt.core.key.Keystore;
import com.boot.jwt.key.DiscoveryPublicKeyRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.cloud.netflix.eureka.EurekaClientAutoConfiguration;
import org.springframework.cloud.netflix.eureka.EurekaInstanceConfigBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.ConfigurableEnvironment;

@Configuration
@ConditionalOnClass({EurekaInstanceConfigBean.class})
@AutoConfigureBefore({EurekaClientAutoConfiguration.class, JwtAuthAutoConfiguration.class})
@Import(JwtSecurityConfigAdapter.class)
public class JwtEurekaAutoConfiguration {

    @Autowired
    private ConfigurableEnvironment environment;


    @Bean
    @ConditionalOnMissingBean(Keystore.class)
    public Keystore generatedKeystore(DiscoveryClient discoveryClient) {
        DiscoveryPublicKeyRegistry keyRegistry = new DiscoveryPublicKeyRegistry(discoveryClient);
        GenratedRSAKeystore genratedRSAKeystore = new GenratedRSAKeystore(keyRegistry);
        genratedRSAKeystore.init();
        return genratedRSAKeystore;
    }
}

