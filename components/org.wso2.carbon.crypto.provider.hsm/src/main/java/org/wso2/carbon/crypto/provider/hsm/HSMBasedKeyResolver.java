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

package org.wso2.carbon.crypto.provider.hsm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;

import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_ID;

/**
 * Implementation of {@link KeyResolver} to resolve keys and certificates from the HSM.
 */
public class HSMBasedKeyResolver extends KeyResolver {

    private static Log log = LogFactory.getLog(HSMBasedKeyResolver.class);

    private ServerConfigurationService serverConfigurationService;

    /**
     * Constructor of HSM based key resolver.
     *
     * @param serverConfigurationService : carbon.xml configuration is provided using this service.
     */
    public HSMBasedKeyResolver(ServerConfigurationService serverConfigurationService) {

        this.serverConfigurationService = serverConfigurationService;
    }

    /**
     * Checks if the given context can be resolved by this Key Resolver.
     *
     * @param cryptoContext Context information related to the cryptographic operation.
     * @return Return whether this resolver is applicable for the context.
     */
    @Override
    public boolean isApplicable(CryptoContext cryptoContext) {

        return true;
    }

    /**
     * Returns private key information related to given {@link CryptoContext}.
     *
     * @param cryptoContext Context information related to the cryptographic operation.
     * @return {@link PrivateKeyInfo} related to given context information.
     */
    @Override
    public PrivateKeyInfo getPrivateKeyInfo(CryptoContext cryptoContext) {

        String keyAlias;
        String keyPassword;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            keyAlias = serverConfigurationService.getFirstProperty(RegistryResources.SecurityManagement
                    .SERVER_PRIMARY_KEYSTORE_KEY_ALIAS);
        } else {
            keyAlias = cryptoContext.getTenantDomain();
            keyPassword = null; // Key password will be internally handled by the KeyStoreManager
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully resolved private key information related to crypto context : %s",
                    cryptoContext));
        }
        return new PrivateKeyInfo(keyAlias, null);
    }

    /**
     * Returns certificate information related to given {@link CryptoContext}.
     *
     * @param cryptoContext : Context information related to the cryptographic operation.
     * @return {@link CertificateInfo} related to given context information.
     */
    @Override
    public CertificateInfo getCertificateInfo(CryptoContext cryptoContext) {

        String certificateAlias;
        if (SUPER_TENANT_ID == cryptoContext.getTenantId()) {
            certificateAlias = serverConfigurationService.getFirstProperty(RegistryResources.SecurityManagement
                    .SERVER_PRIMARY_KEYSTORE_KEY_ALIAS);
        } else {
            certificateAlias = cryptoContext.getTenantDomain();
        }
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully resolved certificate information related to crypto context : %s",
                    cryptoContext));
        }
        return new CertificateInfo(certificateAlias, null);
    }
}
