package org.wso2.carbon.crypto.tenant.hsmstore.mgt.internal;

import org.wso2.carbon.base.api.ServerConfigurationService;

/**
 * This class holds data required for functionality of the HSM Store component.
 */
public class HSMTenantMgtDataHolder {

    private static ServerConfigurationService serverConfigurationService;

    public static void unsetServerConfigurationService() {

        HSMTenantMgtDataHolder.serverConfigurationService = null;
    }

    public static ServerConfigurationService getServerConfigurationService() {

        return serverConfigurationService;
    }

    public static void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        HSMTenantMgtDataHolder.serverConfigurationService = serverConfigurationService;
    }
}
