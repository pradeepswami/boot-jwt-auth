package com.boot.jwt.configuration.condition;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

public class JwtJksOnMissingCondition extends JwtJksAvailableCondition {


    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return ConditionOutcome.inverse(super.getMatchOutcome(context, metadata));
    }
}
