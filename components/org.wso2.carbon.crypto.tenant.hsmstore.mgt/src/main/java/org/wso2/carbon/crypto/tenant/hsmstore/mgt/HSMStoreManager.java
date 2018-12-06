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
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.PKCS11CertificateData;
import org.wso2.carbon.crypto.provider.hsm.PKCS11JCEObjectMapper;
import org.wso2.carbon.crypto.provider.hsm.storemanager.HSMStoreManagerService;
import org.wso2.carbon.crypto.tenant.hsmstore.mgt.internal.HSMTenantMgtDataHolder;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;

import java.security.PrivateKey;
import java.security.cert.Certificate;

/**
 * This class is responsible for storing the tenant's private key and certificate in the HSM device.
 */
public class HSMStoreManager {

    private static Log log = LogFactory.getLog(HSMStoreManager.class);

    private HSMStoreManagerService hsmStoreManagerService;

    /**
     * Constructor of HSM store manager instance.
     *
     * @throws StratosException
     */
    public HSMStoreManager() throws StratosException {

        this.hsmStoreManagerService = HSMTenantMgtDataHolder.getHsmStoreManagerService();
    }

    /**
     * Store the tenant key store in the HSM store. {@link HSMStoreManagerService} default implementation
     * is used to store the certificate and private key.
     *
     * @param tenantInfoBean : Bean which stores information related to created tenant.
     * @throws StratosException
     */
    public void storeTenantKeyStore(TenantInfoBean tenantInfoBean) throws StratosException {

        PrivateKey privateKey;
        Certificate certificate;
        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantInfoBean.getTenantId());
            String keyStoreName = getTenantKeyStoreName(tenantInfoBean.getTenantDomain());
            privateKey = (PrivateKey) keyStoreManager.getPrivateKey(keyStoreName,
                    tenantInfoBean.getTenantDomain());
            certificate = keyStoreManager.getKeyStore(keyStoreName)
                    .getCertificate(tenantInfoBean.getTenantDomain());
            logDebug(String.format("Successfully retrieved private key and public certificate of tenant : '%s'",
                    tenantInfoBean.getTenantDomain()));
        } catch (Exception e) {
            String errorMessage = String.format("Error occurred while retrieving public certificate and " +
                    "private key of tenant : %s", tenantInfoBean.getTenantDomain());
            throw new StratosException(errorMessage, e);
        }
        try {
            PKCS11CertificateData pkcs11CertificateData = PKCS11JCEObjectMapper.mapCertificateJCEToPKCS11(certificate);
            iaik.pkcs.pkcs11.objects.PrivateKey privateKeyToStore =
                    PKCS11JCEObjectMapper.mapPrivateKeyJCEToPKCS11(privateKey);
            privateKeyToStore.getLabel().setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            pkcs11CertificateData.getCertificate().getLabel().
                    setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            pkcs11CertificateData.getPublicKey().getLabel().
                    setCharArrayValue(tenantInfoBean.getTenantDomain().toCharArray());
            hsmStoreManagerService.storeCertificate(pkcs11CertificateData);
            hsmStoreManagerService.storePrivateKey(privateKeyToStore);
            logDebug(String.format("Successfully stored private key and public certificate of tenant : '%s' " +
                    "in HSM device.", tenantInfoBean.getTenantDomain()));
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while storing the public certificate and private " +
                    "key of tenant : %s", tenantInfoBean.getTenantDomain());
            throw new StratosException(errorMessage);
        }
    }

    protected String getTenantKeyStoreName(String tenantDomain) {

        return tenantDomain.trim().replace(".", "-") + ".jks";
    }

    protected void logDebug(String message) {

        if (log.isDebugEnabled()) {
            log.debug(message);
        }
    }
}
