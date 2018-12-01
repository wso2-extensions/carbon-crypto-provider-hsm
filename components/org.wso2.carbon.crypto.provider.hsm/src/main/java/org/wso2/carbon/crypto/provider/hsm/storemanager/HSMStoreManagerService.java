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

import iaik.pkcs.pkcs11.objects.PrivateKey;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.PKCS11CertificateData;

/**
 * This service provides capabilities to store certificates and private keys in the HSM device.
 */
public interface HSMStoreManagerService {

    /**
     * Store a PKCS #11 private key in the HSM device.
     *
     * @param privateKey
     * @throws CryptoException
     */
    void storePrivateKey(PrivateKey privateKey) throws CryptoException;

    /**
     * Store a PKCS #11 certifcate and public key in the HSM device.
     *
     * @param certificate
     * @throws CryptoException
     */
    void storeCertificate(PKCS11CertificateData certificate) throws CryptoException;
}
