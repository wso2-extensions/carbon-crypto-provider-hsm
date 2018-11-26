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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Certificate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

/**
 * This class is responsible to handle certificate related operations with HSM.
 */
public class CertificateHandler {

    private static Log log = LogFactory.getLog(CertificateHandler.class);

    private final Session session;

    /**
     * Constructor of CertificateHandler instance.
     *
     * @param session : Session associated to handle the certificate related operation.
     */
    public CertificateHandler(Session session) {

        this.session = session;
    }

    /**
     * Method to retrieve a given certificate from the HSM.
     *
     * @param certificateTemplate : Template of the certificate to be retrieved
     * @return retrievedCertificate
     */
    public Certificate getCertificate(Certificate certificateTemplate) throws CryptoException {

        try {
            session.findObjectsInit(certificateTemplate);
            Object[] certificateArray = session.findObjects(1);
            if (certificateArray.length > 0) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Certificate with alias %s, retrieved successfully from HSM device.",
                            new String(certificateTemplate.getLabel().getCharArrayValue())));
                }
                return (Certificate) certificateArray[0];
            } else {
                String errorMessage = String.format("Requested certificate '%s' can't be found inside the HSM.",
                        String.valueOf(certificateTemplate.getLabel().getCharArrayValue()));
                throw new CryptoException(errorMessage);
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred during retrieving certificate with alias '%s'.",
                    String.valueOf(certificateTemplate.getLabel().getCharArrayValue()));
            throw new HSMCryptoException(errorMessage, e);
        }
    }

    /**
     * Store a PKCS #11 certificate in the HSM device.
     *
     * @param certificate : Certificate that needs to be stored.
     * @throws HSMCryptoException
     */
    public void storeCertificate(Certificate certificate) throws HSMCryptoException {

        certificate.getToken().setBooleanValue(true);
        try {
            session.createObject(certificate);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Certificate with alias %s, stored successfully in HSM device.",
                        new String(certificate.getLabel().getCharArrayValue())));
            }
        } catch (TokenException e) {
            String errorMessage = String.format("Error occurred while storing %s certificate in HSM device.",
                    new String(certificate.getLabel().getCharArrayValue()));
            throw new HSMCryptoException(errorMessage, e);
        }
    }
}
