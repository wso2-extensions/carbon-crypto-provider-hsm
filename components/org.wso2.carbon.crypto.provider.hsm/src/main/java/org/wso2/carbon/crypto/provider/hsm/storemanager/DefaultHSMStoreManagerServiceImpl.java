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

package org.wso2.carbon.crypto.provider.hsm.storemanager;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.PKCS11CertificateData;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

/**
 * Default implementation of {@link HSMStoreManagerService}.
 */
public class DefaultHSMStoreManagerServiceImpl implements HSMStoreManagerService {

    private static final String EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.ExternalProvider.ExternalProviderSlotID";

    private static Log log = LogFactory.getLog(DefaultHSMStoreManagerServiceImpl.class);

    private SessionHandler sessionHandler;
    private ServerConfigurationService serverConfigurationService;

    /**
     * Constructor of default HSM store manager service.
     *
     * @param serverConfigurationService : carbon.xml configuration as a service.
     * @throws CryptoException
     */
    public DefaultHSMStoreManagerServiceImpl(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        this.sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        this.serverConfigurationService = serverConfigurationService;
    }

    /**
     * This stores a given private key in the HSM's external provider slot.
     *
     * @param privateKey : PKCS #11 private key to be stored.
     * @throws CryptoException
     */
    @Override
    public void storePrivateKey(PrivateKey privateKey) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Storing the private key with %s alias in HSM's external provider slot.",
                    new String(privateKey.getLabel().getCharArrayValue())));
        }
        Session session = initiateSession();
        try {
            KeyHandler keyHandler = new KeyHandler(session);
            keyHandler.storeKey(privateKey);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully stored the certificate with %s alias in HSM's external provider " +
                        "slot.", new String(privateKey.getLabel().getCharArrayValue())));
            }
        } finally {
            if (session != null) {
                sessionHandler.closeSession(session);
            }
        }
    }

    /**
     * This stores a given certificate in the HSM's external provider slot.
     *
     * @param certificate : PKCS #11 certificate and public key to be stored.
     * @throws CryptoException
     */
    @Override
    public void storeCertificate(PKCS11CertificateData certificate) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Storing the certificate with %s alias in HSM's external provider slot.",
                    new String(certificate.getCertificate().getLabel().getCharArrayValue())));
        }
        Session session = initiateSession();
        try {
            CertificateHandler certificateHandler = new CertificateHandler(session);
            certificateHandler.storeCertificate(certificate.getCertificate());
            KeyHandler keyHandler = new KeyHandler(session);
            keyHandler.storeKey(certificate.getPublicKey());
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully stored the certificate with %s alias in HSM's external provider " +
                        "slot.", new String(certificate.getCertificate().getLabel().getCharArrayValue())));
            }
        } finally {
            if (session != null) {
                sessionHandler.closeSession(session);
            }
        }

    }

    protected Session initiateSession() throws CryptoException {

        return sessionHandler.initiateSession(Integer.parseInt(serverConfigurationService
                .getFirstProperty(EXTERNAL_PROVIDER_SLOT_PROPERTY_PATH)), null, true);
    }
}
