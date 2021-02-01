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

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.objects.AESSecretKey;
import iaik.pkcs.pkcs11.objects.Certificate;
import iaik.pkcs.pkcs11.objects.DES2SecretKey;
import iaik.pkcs.pkcs11.objects.DES3SecretKey;
import iaik.pkcs.pkcs11.objects.DESSecretKey;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.PrivateKey;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.SecretKey;
import iaik.pkcs.pkcs11.parameters.GcmParameters;
import iaik.pkcs.pkcs11.parameters.InitializationVectorParameters;
import iaik.pkcs.pkcs11.parameters.Parameters;
import iaik.pkcs.pkcs11.wrapper.CK_GCM_PARAMS;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CertificateInfo;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.ExternalCryptoProvider;
import org.wso2.carbon.crypto.api.HybridEncryptionInput;
import org.wso2.carbon.crypto.api.HybridEncryptionOutput;
import org.wso2.carbon.crypto.api.PrivateKeyInfo;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators.Cipher;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.operators.SignatureHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.KeyTemplateGenerator;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismDataHolder;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.MechanismResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.DECRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.ENCRYPT_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.SIGN_MODE;
import static org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.CryptoConstants.VERIFY_MODE;

/**
 * Implementation of {@link ExternalCryptoProvider} to provide cryptographic operations using Hardware Security Modules.
 */
public class HSMBasedExternalCryptoProvider implements ExternalCryptoProvider {

    private static Log log = LogFactory.getLog(HSMBasedExternalCryptoProvider.class);

    private SessionHandler sessionHandler;
    private MechanismResolver mechanismResolver;
    private SlotResolver slotResolver;

    /**
     * Constructor of {@link HSMBasedExternalCryptoProvider}.
     * Sets default {@link SessionHandler}, {@link MechanismResolver} for External provider.
     *
     * @param serverConfigurationService : carbon.xml configuration is provided using this service.
     * @throws CryptoException If something unexpected happens during instantiating the External Crypto Provider.
     */
    public HSMBasedExternalCryptoProvider(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        mechanismResolver = MechanismResolver.getInstance();
        slotResolver = new DefaultSlotResolver(serverConfigurationService);
    }

    /**
     * Computes and returns the signature of given data, using the underlying HSM device.
     * Private key is retrieved from the HSM device.
     *
     * @param data                    The data whose signature is calculated.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information needed for signing.
     * @param privateKeyInfo          Information about the private key.
     * @return The signature
     * @throws CryptoException If something unexpected happens during the signing operation.
     */
    @Override
    public byte[] sign(byte[] data, String algorithm, String javaSecurityAPIProvider, CryptoContext cryptoContext,
                       PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Signing data with %s algorithm and %s private key using HSM device.", algorithm,
                    privateKeyInfo.getKeyAlias()));
        }
        Mechanism signMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(SIGN_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            PrivateKey signingKey = retrievePrivateKey(session, privateKeyInfo);
            SignatureHandler signatureHandler = new SignatureHandler(session);
            byte[] signedData = signatureHandler.sign(data, signingKey, signMechanism);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully signed data with %s algorithm and %s private key using HSM device.",
                        algorithm, privateKeyInfo.getKeyAlias()));
            }
            return signedData;
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Computes and returns the cleartext of the given cipher text using the underlying HSM device.
     * Assumes that keys are stored in the underlying HSM device.
     *
     * @param ciphertext              The ciphertext to be decrypted.
     * @param algorithm               The encryption / decryption algorithm
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information needed for signing.
     * @param privateKeyInfo          Information about the private key.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the decryption operation.
     */
    @Override
    public byte[] decrypt(byte[] ciphertext, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Decrypting data with %s algorithm and %s private key using HSM device.",
                    algorithm, privateKeyInfo.getKeyAlias()));
        }
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(DECRYPT_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            PrivateKey decryptionKey = retrievePrivateKey(session, privateKeyInfo);
            Cipher cipher = new Cipher(session);
            byte[] decryptedData = cipher.decrypt(ciphertext, decryptionKey, decryptionMechanism);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully decrypted data with %s algorithm and %s private key using HSM device.",
                        algorithm, privateKeyInfo.getKeyAlias()));
            }
            return decryptedData;
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Computes and returns the cipher text of the given cleartext using the underlying HSM device.
     * Public key is retrieved from the underlying HSM device.
     *
     * @param data                    The cleartext to be encrypted.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information which was used to find discovery information about the
     *                                certificate
     *                                of the external entity.
     * @param certificateInfo         The information which is needed to retrieve the certificate.
     *                                If this information is not sufficient the {@link CryptoContext} will be used to
     *                                get more information.
     * @return The cleartext
     * @throws CryptoException If something unexpected happens during the encryption operation.
     */
    @Override
    public byte[] encrypt(byte[] data, String algorithm, String javaSecurityAPIProvider,
                          CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Encrypting data with %s algorithm using HSM device with public certificate : %s",
                    algorithm, certificateInfo));
        }
        Mechanism encryptionMechanism = mechanismResolver.resolveMechanism(
                new MechanismDataHolder(ENCRYPT_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            PublicKey encryptionKey = retrievePublicKey(session, certificateInfo);
            Cipher cipher = new Cipher(session);
            byte[] encryptedData = cipher.encrypt(data, encryptionKey, encryptionMechanism);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully encrypted data with %s algorithm using HSM device with public " +
                        "certificate : %s", algorithm, certificateInfo));
            }
            return encryptedData;
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Verifies whether given signature of the given data was generated by a trusted external party.
     * Signature verification is carried out using the underlying HSM device.
     * Public key is retrieved from the HSM device.
     *
     * @param data                    The data which was the signature generated on.
     * @param signature               The signature bytes of data.
     * @param algorithm               The signature + hashing algorithm to be used in signing.
     * @param javaSecurityAPIProvider The Java Security API provider.
     * @param cryptoContext           The context information which is needed to discover the public key of
     *                                the external entity.
     * @param certificateInfo         The information which is needed to retrieve the certificate.
     *                                If this information is not sufficient the {@link CryptoContext} will be used to
     *                                get more information.
     * @return true if signature can be verified, false otherwise.
     * @throws CryptoException If something unexpected happens during the signature verification.
     */
    @Override
    public boolean verifySignature(byte[] data, byte[] signature, String algorithm, String javaSecurityAPIProvider,
                                   CryptoContext cryptoContext, CertificateInfo certificateInfo) throws CryptoException {

        failIfMethodParametersInvalid(algorithm);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Verifying digital signature with %s algorithm using the HSM device with public " +
                    "certificate : %s", algorithm, certificateInfo));
        }
        Mechanism verifyMechanism = mechanismResolver.resolveMechanism(new MechanismDataHolder(VERIFY_MODE, algorithm));
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            PublicKey verificationKey = retrievePublicKey(session, certificateInfo);
            SignatureHandler signatureHandler = new SignatureHandler(session);
            boolean verification = signatureHandler.verify(data, signature, verificationKey, verifyMechanism);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully verified digital signature with %s algorithm using the HSM device " +
                        "with public certificate : %s", algorithm, certificateInfo));
            }
            return verification;
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    /**
     * Returns the {@link java.security.cert.Certificate} based on the given {@link CryptoContext}
     * Certificate is retrieved from the underlying HSM device.
     *
     * @param cryptoContext   The context information which is used to discover the public key of the external entity.
     * @param certificateInfo The information which is needed to retrieve the certificate.
     *                        If this information is not sufficient the {@link CryptoContext} will be used to
     *                        get more information.
     * @return The {@link java.security.cert.Certificate} relates with the given context.
     * @throws CryptoException If something unexpected happens during certificate discovery.
     */
    @Override
    public java.security.cert.Certificate getCertificate(CryptoContext cryptoContext,
                                                         CertificateInfo certificateInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving certificate with alias %s related to crypto context : '%s' " +
                    "from the HSM device.", certificateInfo.getCertificateAlias(), cryptoContext));
        }
        Certificate retrievedCertificate = retrieveCertificate(certificateInfo.getCertificateAlias(), cryptoContext);
        java.security.cert.Certificate certificate = PKCS11JCEObjectMapper
                .mapCertificatePKCS11ToJCE(retrievedCertificate);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully retrieved the certificate related to crypto context : ",
                    cryptoContext));
        }
        return certificate;
    }

    /**
     * Returns the {@link java.security.PrivateKey} based on the given {@link CryptoContext}
     * This certificate is retrieved from the underlying HSM device.
     * This implementation supports only RSA private keys at the moment.
     *
     * @param cryptoContext  The context information which is used to discover the applicable private key.
     * @param privateKeyInfo The information which is needed to retrieve the private key.
     *                       If this information is not sufficient, the {@link CryptoContext} will be used to
     *                       get more information.
     * @return The {@link java.security.PrivateKey} relates with the given context.
     * @throws CryptoException If something unexpected happens during private key discovery.
     */
    @Override
    public java.security.PrivateKey getPrivateKey(CryptoContext cryptoContext,
                                                  PrivateKeyInfo privateKeyInfo) throws CryptoException {

        failIfContextInformationIsMissing(cryptoContext);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving %s private key related crypto context : '%s' from HSM device",
                    privateKeyInfo.getKeyAlias(), cryptoContext));
        }
        PrivateKey retrievedKey;
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            retrievedKey = retrievePrivateKey(session, privateKeyInfo);
        } finally {
            sessionHandler.closeSession(session);
        }
        if (!retrievedKey.getSensitive().getBooleanValue() && retrievedKey.getExtractable().getBooleanValue()) {
            java.security.PrivateKey privateKey = PKCS11JCEObjectMapper.mapPrivateKeyPKCS11ToJCE(retrievedKey);
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully retrieved the private key related to crypto context : %s",
                        cryptoContext));
            }
            return privateKey;
        } else {
            String errorMessage = String.format("Requested private key %s is not extractable.",
                    privateKeyInfo.getKeyAlias());
            throw new CryptoException(errorMessage);
        }
    }

    /**
     * Computes and returns the {@link HybridEncryptionOutput} based on provided {@link HybridEncryptionInput}
     * Hybrid encryption is carried out using the underlying HSM device.
     * Session object is created for symmetric key for decryption.
     *
     * @param hybridEncryptionInput Input data for hybrid encryption.
     * @param symmetricAlgorithm    The symmetric encryption/decryption algorithm.
     * @param asymmetricAlgorithm   The asymmetric encryption/decryption algorithm.
     * @param javaSecurityProvider  The Java Security API provider. This value is discarded in this component.
     * @param cryptoContext         The context information which is used to discover
     *                              the public key of the external entity.
     * @return {@link HybridEncryptionOutput} cipher text with required parameters
     * @throws CryptoException
     */
    @Override
    public HybridEncryptionOutput hybridEncrypt(HybridEncryptionInput hybridEncryptionInput, String symmetricAlgorithm,
                                                String asymmetricAlgorithm, String javaSecurityProvider,
                                                CryptoContext cryptoContext, CertificateInfo certificateInfo)
            throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Hybrid encrypting data with %s symmetric algorithm and %s asymmetric algorithm," +
                    " using HSM device with certificate : %s.", symmetricAlgorithm, asymmetricAlgorithm, certificateInfo));
        }
        MechanismDataHolder mechanismDataHolder = new MechanismDataHolder(ENCRYPT_MODE, symmetricAlgorithm,
                hybridEncryptionInput.getAuthData());
        Mechanism symmetricMechanism = mechanismResolver.resolveMechanism(mechanismDataHolder);
        SecretKey encryptionKey;
        byte[] encryptedData;
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), true);
        try {
            // Retrieving symmetric key for symmetric encryption.
            encryptionKey = generateRandomSymmetricKey(session, symmetricAlgorithm);
            encryptedData = symmetricEncrypt(session, symmetricMechanism, encryptionKey,
                    hybridEncryptionInput.getPlainData());
            if (log.isDebugEnabled()) {
                log.debug(String.format("Successfully encrypted the plain data with %s symmetric algorithm and %s symmetric " +
                        "key.", symmetricAlgorithm, encryptionKey.getClass().getName()));
            }
        } finally {
            sessionHandler.closeSession(session);
        }
        // Encrypting symmetric key.
        byte[] encryptedKey = encryptSymmetricKey(encryptionKey, asymmetricAlgorithm, cryptoContext, certificateInfo);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully encrypted '%s' symmetric key for hybrid encryption with %s asymmetric " +
                            "algorithm and public certificate : %s", encryptionKey.getClass().getName(),
                    asymmetricAlgorithm, certificateInfo));
        }
        // Generating output of the hybrid encryption.
        HybridEncryptionOutput hybridEncryptionOutput = generateHybridEncryptionOutput(symmetricMechanism,
                encryptedData, encryptedKey);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully hybrid encrypted data with %s symmetric algorithm and %s asymmetric " +
                            "algorithm, using HSM device with certificate : %s.", symmetricAlgorithm,
                    asymmetricAlgorithm, certificateInfo));
        }
        return hybridEncryptionOutput;
    }

    /**
     * Computes and return clear data based on provided {@link HybridEncryptionOutput}
     * Hybrid decryption is carried out using the underlying HSM device.
     * Session object is created for symmetric key for decryption.
     *
     * @param hybridDecryptionInput {@link HybridEncryptionOutput} ciphered data with parameters.
     * @param symmetricAlgorithm    The symmetric encryption/decryption algorithm.
     * @param asymmetricAlgorithm   The asymmetric encryption/decryption algorithm.
     * @param javaSecurityProvider  The Java Security API provider.
     * @param cryptoContext         The context information which is used to discover
     *                              the public key of the external entity.
     * @return the decrypted data
     * @throws CryptoException
     */
    @Override
    public byte[] hybridDecrypt(HybridEncryptionOutput hybridDecryptionInput, String symmetricAlgorithm,
                                String asymmetricAlgorithm, String javaSecurityProvider, CryptoContext cryptoContext,
                                PrivateKeyInfo privateKeyInfo) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Hybrid decrypting data with %s symmetric algorithm and %s asymmetric algorithm, " +
                            "using HSM device with private key %s.", symmetricAlgorithm, asymmetricAlgorithm,
                    privateKeyInfo.getKeyAlias()));
        }
        // Decrypting symmetric key value used for data encryption.
        byte[] decryptionKeyValue = decrypt(hybridDecryptionInput.getEncryptedSymmetricKey(), asymmetricAlgorithm,
                javaSecurityProvider, cryptoContext, privateKeyInfo);
        if (log.isDebugEnabled()) {
            log.debug(String.format("Successfully decrypted the value of symmetric key used for hybrid encryption."));
        }
        MechanismDataHolder mechanismDataHolder = new MechanismDataHolder(DECRYPT_MODE, symmetricAlgorithm,
                hybridDecryptionInput.getParameterSpec(), hybridDecryptionInput.getAuthData());
        Mechanism decryptionMechanism = mechanismResolver.resolveMechanism(mechanismDataHolder);
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), true);
        try {
            // Generating a symmetric key with given value, for data decryption.
            SecretKey decryptionKey = generateSecretKeyHandle(session, symmetricAlgorithm, decryptionKeyValue);
            Cipher cipher = new Cipher(session);
            if (hybridDecryptionInput.getAuthTag() != null) {
                byte[] encryptedData = concatByteArrays(new byte[][]{hybridDecryptionInput.getCipherData(),
                        hybridDecryptionInput.getAuthTag()});
                return cipher.decrypt(encryptedData, decryptionKey, decryptionMechanism);
            } else {
                return cipher.decrypt(hybridDecryptionInput.getCipherData(), decryptionKey, decryptionMechanism);
            }
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected byte[] symmetricEncrypt(Session session, Mechanism symmetricAlgorithm, Key encryptionKey,
                                      byte[] plainData) throws CryptoException {

        Cipher cipher = new Cipher(session);
        return cipher.encrypt(plainData, encryptionKey, symmetricAlgorithm);
    }

    protected Session initiateSession(SlotInfo slotInfo, boolean readWrite) throws CryptoException {

        return sessionHandler.initiateSession(slotInfo.getSlotID(), slotInfo.getPin(), readWrite);
    }

    protected void failIfContextInformationIsMissing(CryptoContext cryptoContext) throws CryptoException {

        if (cryptoContext == null || cryptoContext.getTenantId() == 0 ||
                StringUtils.isBlank(cryptoContext.getTenantDomain())) {
            throw new CryptoException("Tenant information is missing in the crypto context.");
        }
    }

    protected void failIfMethodParametersInvalid(String algorithm) throws CryptoException {

        if (!(algorithm != null && MechanismResolver.getSupportedMechanisms().containsKey(algorithm))) {
            String errorMessage = String.format("Requested algorithm '%s' is not valid/supported.", algorithm);
            throw new CryptoException(errorMessage);
        }
    }

    protected PublicKey retrievePublicKey(Session session, CertificateInfo certificateInfo) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving public key from certificate with alias %s",
                    certificateInfo.getCertificateAlias()));
        }
        if (certificateInfo.getCertificate() != null) {
            java.security.PublicKey publicKey = certificateInfo.getCertificate().getPublicKey();
            if (!(publicKey instanceof java.security.interfaces.RSAPublicKey)) {
                throw new CryptoException("HSM based crypto provider supports only for RSA public key session objects.");
            }
            PKCS11CertificateData certificateData = PKCS11JCEObjectMapper
                    .mapCertificateJCEToPKCS11(certificateInfo.getCertificate());
            certificateData.getPublicKey().getLabel().setCharArrayValue("RSA".toCharArray());
            return retrieveKeyHandle(session, certificateData.getPublicKey());
        } else {
            PublicKey publicKeyTemplate = new PublicKey();
            publicKeyTemplate.getLabel().setCharArrayValue(certificateInfo.getCertificateAlias().toCharArray());
            publicKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PUBLIC_KEY);
            return (PublicKey) retrieveKey(publicKeyTemplate, session);
        }
    }

    protected PublicKey retrieveKeyHandle(Session session, PublicKey publicKey) throws HSMCryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        return (PublicKey) keyHandler.getKeyHandle(publicKey);
    }

    protected PrivateKey retrievePrivateKey(Session session, PrivateKeyInfo privateKeyInfo) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Retrieving private key with alias '%s' from HSM device.",
                    privateKeyInfo.getKeyAlias()));
        }
        PrivateKey privateKeyTemplate = new PrivateKey();
        privateKeyTemplate.getLabel().setCharArrayValue(privateKeyInfo.getKeyAlias().toCharArray());
        privateKeyTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_PRIVATE_KEY);
        return (PrivateKey) retrieveKey(privateKeyTemplate, session);
    }

    protected Key retrieveKey(Key keyTemplate, Session session) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        return keyHandler.retrieveKey(keyTemplate);
    }

    protected Certificate retrieveCertificate(String label, CryptoContext cryptoContext) throws CryptoException {

        Certificate certificateTemplate = new Certificate();
        certificateTemplate.getLabel().setCharArrayValue(label.toCharArray());
        certificateTemplate.getObjectClass().setLongValue(PKCS11Constants.CKO_CERTIFICATE);
        Session session = initiateSession(slotResolver.resolveSlot(cryptoContext), false);
        try {
            CertificateHandler certificateHandler = new CertificateHandler(session);
            return certificateHandler.getCertificate(certificateTemplate);
        } finally {
            sessionHandler.closeSession(session);
        }
    }

    protected SecretKey generateRandomSymmetricKey(Session session, String symmetricAlgorithm) throws CryptoException {

        String[] keySpecification = symmetricAlgorithm.split("/")[0].split("_");
        String keyType = keySpecification[0];
        String errorMessage = String.format("Requested key type generation is not supported for '%s' " +
                "algorithm", symmetricAlgorithm);
        SecretKey secretKeyTemplate;
        switch (keyType) {
            case (CryptoConstants.KeyType.AES):
                long keyLength = 32L;
                if (keySpecification.length > 1) {
                    keyLength = Long.parseLong(keySpecification[1]) / 8;
                }
                secretKeyTemplate = KeyTemplateGenerator.generateAESKeyTemplate();
                ((AESSecretKey) secretKeyTemplate).getValueLen().setLongValue(keyLength);
                break;
            case (CryptoConstants.KeyType.DES):
                secretKeyTemplate = KeyTemplateGenerator.generateDESKeyTemplate();
                break;
            case (CryptoConstants.KeyType.DES2):
                secretKeyTemplate = KeyTemplateGenerator.generateDES2KeyTemplate();
                break;
            case (CryptoConstants.KeyType.DES3):
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
                break;
            case (CryptoConstants.KeyType.DESede):
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
                break;
            default:
                throw new CryptoException(errorMessage);
        }
        return generateKey(secretKeyTemplate, true, keyType, session);
    }

    protected SecretKey generateSecretKeyHandle(Session session, String symmetricAlgorithm, byte[] value) throws CryptoException {

        String[] keySpecification = symmetricAlgorithm.split("/")[0].split("_");
        String keyType = keySpecification[0];
        String errorMessage = String.format("Requested key type generation is not supported for '%s' " +
                "algorithm", symmetricAlgorithm);
        SecretKey secretKeyTemplate;
        switch (keyType) {
            case (CryptoConstants.KeyType.AES):
                secretKeyTemplate = KeyTemplateGenerator.generateAESKeyTemplate();
                ((AESSecretKey) secretKeyTemplate).getValue().setValue(value);
                break;
            case (CryptoConstants.KeyType.DES):
                secretKeyTemplate = KeyTemplateGenerator.generateDESKeyTemplate();
                ((DESSecretKey) secretKeyTemplate).getValue().setValue(value);
                break;
            case (CryptoConstants.KeyType.DES2):
                secretKeyTemplate = KeyTemplateGenerator.generateDES2KeyTemplate();
                ((DES2SecretKey) secretKeyTemplate).getValue().setValue(value);
                break;
            case (CryptoConstants.KeyType.DES3):
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
                ((DES3SecretKey) secretKeyTemplate).getValue().setValue(value);
                break;
            case (CryptoConstants.KeyType.DESede):
                secretKeyTemplate = KeyTemplateGenerator.generateDES3KeyTemplate();
                ((DES3SecretKey) secretKeyTemplate).getValue().setValue(value);
                break;
            default:
                throw new CryptoException(errorMessage);
        }
        return generateKey(secretKeyTemplate, false, keyType, session);
    }

    protected SecretKey generateKey(SecretKey secretKeyTemplate, boolean encryptMode, String keyGenAlgo, Session
            session) throws CryptoException {

        KeyHandler keyHandler = new KeyHandler(session);
        if (encryptMode) {
            return keyHandler.generateSecretKey(secretKeyTemplate, mechanismResolver.resolveMechanism(
                    new MechanismDataHolder(ENCRYPT_MODE, keyGenAlgo)));
        } else {
            return (SecretKey) keyHandler.getKeyHandle(secretKeyTemplate);
        }
    }

    protected HybridEncryptionOutput generateHybridEncryptionOutput(Mechanism symmetricMechanism, byte[] encryptedData,
                                                                    byte[] encryptedKey) throws CryptoException {

        Parameters paramObject = symmetricMechanism.getParameters();
        if (paramObject instanceof GcmParameters) {
            CK_GCM_PARAMS gcmParams = (CK_GCM_PARAMS) paramObject.getPKCS11ParamsObject();
            // Generate parameter specification for GCM symmetric encryption.
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec((int) gcmParams.ulTagBits, gcmParams.pIv);
            // Get authentication tag position in encrypted data.
            int tagPos = encryptedData.length - (int) (gcmParams.ulTagBits) / 8;
            // Get cipher data from encrypted data.
            byte[] cipherData = subArray(encryptedData, 0, tagPos);
            // Get authentication tag from encrypted data.
            byte[] authTag = subArray(encryptedData, tagPos, (int) (gcmParams.ulTagBits) / 8);
            return new HybridEncryptionOutput(cipherData, encryptedKey, gcmParams.pAAD,
                    authTag, gcmParameterSpec);
        } else if (paramObject instanceof InitializationVectorParameters) {
            IvParameterSpec ivParameterSpec = new IvParameterSpec(((InitializationVectorParameters)
                    paramObject).getInitializationVector());
            return new HybridEncryptionOutput(encryptedData, encryptedKey, ivParameterSpec);
        } else {
            String errorMessage = String.format("Invalid / Unsupported parameter specification for '%s' symmetric " +
                    "encryption algorithm.", symmetricMechanism.getName());
            throw new CryptoException(errorMessage);
        }
    }

    protected byte[] encryptSymmetricKey(SecretKey encryptionKey, String asymmetricAlgorithm, CryptoContext cryptoContext,
                                         CertificateInfo certificateInfo) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("Encrypting generated '%s' symmetric key for hybrid encryption with %s asymmetric " +
                            "algorithm and public certificate : %s", encryptionKey.getClass().getName(),
                    asymmetricAlgorithm, certificateInfo));
        }
        if (encryptionKey instanceof AESSecretKey) {
            return encrypt(((AESSecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, null, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DESSecretKey) {
            return encrypt(((DESSecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, null, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DES2SecretKey) {
            return encrypt(((DES2SecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, null, cryptoContext, certificateInfo);
        } else if (encryptionKey instanceof DES3SecretKey) {
            return encrypt(((DES3SecretKey) encryptionKey).getValue().getByteArrayValue(),
                    asymmetricAlgorithm, null, cryptoContext, certificateInfo);
        } else {
            String errorMessage = String.format("Symmetric encryption key instance '%s' provided for hybrid " +
                    "encryption is not supported by the provider", encryptionKey.getClass().getName());
            throw new CryptoException(errorMessage);
        }
    }

    protected byte[] subArray(byte[] byteArray, int beginIndex, int length) {

        byte[] subArray = new byte[length];
        System.arraycopy(byteArray, beginIndex, subArray, 0, subArray.length);
        return subArray;
    }

    protected byte[] concatByteArrays(byte[][] byteArrays) throws CryptoException {

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] byteArray : byteArrays) {
            try {
                outputStream.write(byteArray);
            } catch (IOException e) {
                String errorMessage = String.format("Error occurred while decrypting hybrid encrypted data.");
                throw new CryptoException(errorMessage, e);
            }
        }
        return outputStream.toByteArray();
    }
}
