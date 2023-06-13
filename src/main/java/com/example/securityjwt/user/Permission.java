package com.example.securityjwt.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * @author vienlv
 */
@RequiredArgsConstructor
public enum Permission {

    ADMIN_READ("admin:read"),

    ADMIN_UPDATE("admin:update"),

    ADMIN_CREATE("admin:create"),

    ADMIN_DELETE("admin:delete"),

    MANAGER_READ("management:read"),

    MANAGER_UPDATE("management:update"),

    MANAGER_CREATE("manager:create"),

    MANAGER_DELETE("manager:delete");

    @Getter
    private final String permission;

}
