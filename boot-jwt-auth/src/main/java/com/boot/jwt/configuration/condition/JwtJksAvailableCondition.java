package com.boot.jwt.configuration.condition;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class JwtJksAvailableCondition extends SpringBootCondition {

    public static final String CONDITION_NAME = "JWTAuthJks";
    public static final String CONDITION_PREFIX = "jwt.auth.";
    public static final String PROPERTY_NAME = "keyStore";

    private final ResourceLoader defaultResourceLoader = new DefaultResourceLoader();

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        RelaxedPropertyResolver resolver = new RelaxedPropertyResolver(
                context.getEnvironment(), CONDITION_PREFIX);
        if (!resolver.containsProperty(PROPERTY_NAME)) {
            return ConditionOutcome.noMatch(ConditionMessage
                    .forCondition(this.getClass().getSimpleName())
                    .didNotFind("Resource ").items(ConditionMessage.Style.QUOTE, CONDITION_PREFIX + PROPERTY_NAME));
        }

        ResourceLoader loader = context.getResourceLoader() == null
                ? this.defaultResourceLoader : context.getResourceLoader();

        String value = resolver.getProperty(PROPERTY_NAME);
        Resource resource = loader.getResource(value);

        if (!resource.exists()) {
            return ConditionOutcome.noMatch(ConditionMessage
                    .forCondition(this.getClass().getSimpleName())
                    .notAvailable("Resource " + value));

        }
        return ConditionOutcome.match(ConditionMessage.forCondition(this.getClass().getSimpleName()).available("Resource " + value));
    }
}