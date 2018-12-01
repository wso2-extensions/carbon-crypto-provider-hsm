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

package org.wso2.carbon.crypto.tenant.hsmstore.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

/**
 * Implementation of {@link TenantMgtListener} which stores private key and public certificate of the
 * created tenant in the HSM device.
 */
public class HSMTenantMgtListener implements TenantMgtListener {

    private static final int EXEC_ORDER = 21;
    private static Log log = LogFactory.getLog(HSMTenantMgtListener.class);

    /**
     * Constructor of {@link HSMTenantMgtListener}.
     *
     * @throws CryptoException
     */
    public HSMTenantMgtListener() throws CryptoException {

    }

    /**
     * This method retrieves the generated keystore at the tenant creation, using {@link KeyStoreManager} and
     * stores the public certificate and private key in the HSM device.
     *
     * @param tenantInfoBean : Bean which stores information related to created tenant.
     * @throws StratosException
     */
    @Override
    public void onTenantCreate(TenantInfoBean tenantInfoBean) throws StratosException {

        logDebug(String.format("Storing '%s' tenant private key and public key in HSM store.",
                tenantInfoBean.getTenantDomain()));
        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantInfoBean.getTenantDomain())) {
            String errorMessage = "Super tenant domain can't be a new tenant domain.";
            throw new StratosException(errorMessage);
        }
        HSMStoreManager hsmStoreManager = new HSMStoreManager();
        hsmStoreManager.storeTenantKeyStore(tenantInfoBean);
    }

    @Override
    public void onTenantUpdate(TenantInfoBean tenantInfo) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantDelete(int tenantId) {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantRename(int tenantId, String oldDomainName,
                               String newDomainName) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public int getListenerOrder() {

        return EXEC_ORDER;
    }

    @Override
    public void onTenantInitialActivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantActivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onTenantDeactivation(int tenantId) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onSubscriptionPlanChange(int tenentId, String oldPlan,
                                         String newPlan) throws StratosException {
        // It is not required to implement this method for keystore mgt.
    }

    @Override
    public void onPreDelete(int tenantId) throws StratosException {
        // Implement this method to delete product specific data
    }

    protected void logDebug(String message) {

        if (log.isDebugEnabled()) {
            log.debug(message);
        }
    }
}
