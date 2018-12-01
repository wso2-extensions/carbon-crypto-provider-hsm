/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.crypto.tenant.hsmstore.mgt.internal;

import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.provider.hsm.storemanager.HSMStoreManagerService;

/**
 * This class holds data required for functionality of the HSM Store component.
 */
public class HSMTenantMgtDataHolder {

    private static ServerConfigurationService serverConfigurationService;
    private static HSMStoreManagerService hsmStoreManagerService;

    public static void unsetServerConfigurationService() {

        HSMTenantMgtDataHolder.serverConfigurationService = null;
    }

    public static ServerConfigurationService getServerConfigurationService() {

        return serverConfigurationService;
    }

    public static void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        HSMTenantMgtDataHolder.serverConfigurationService = serverConfigurationService;
    }

    public static HSMStoreManagerService getHsmStoreManagerService() {

        return hsmStoreManagerService;
    }

    public static void setHsmStoreManagerService(HSMStoreManagerService hsmStoreManagerService) {

        HSMTenantMgtDataHolder.hsmStoreManagerService = hsmStoreManagerService;
    }

    public static void unsetHsmStoreManagerService() {

        HSMTenantMgtDataHolder.hsmStoreManagerService = null;
    }
}
