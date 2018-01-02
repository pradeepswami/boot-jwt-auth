package com.boot.jwt.core.key;

import java.util.Objects;

public class AppMetadata {

    private String appName;

    private String instanceId;

    public AppMetadata(String appName, String instanceId) {
        Objects.requireNonNull(appName, "Application name is null");
        this.appName = appName;
        this.instanceId = instanceId;
        if (Objects.isNull(instanceId)) {
            this.instanceId = appName;
        }
    }

    public String getAppName() {
        return appName;
    }

    public String getInstanceId() {
        return instanceId;
    }

    @Override
    public String toString() {
        return "AppMetadata{" +
                "appName='" + appName + '\'' +
                ", instanceId='" + instanceId + '\'' +
                '}';
    }
}
