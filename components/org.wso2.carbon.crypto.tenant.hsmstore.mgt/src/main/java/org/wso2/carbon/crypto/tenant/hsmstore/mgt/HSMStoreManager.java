package org.wso2.carbon.crypto.tenant.hsmstore.mgt;

import iaik.pkcs.pkcs11.Session;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.DefaultSlotResolver;
import org.wso2.carbon.crypto.provider.hsm.PKCS11CertificateData;
import org.wso2.carbon.crypto.provider.hsm.PKCS11JCEObjectMapper;
import org.wso2.carbon.crypto.provider.hsm.SlotInfo;
import org.wso2.carbon.crypto.provider.hsm.SlotResolver;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.CertificateHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.objecthandlers.KeyHandler;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util.SessionHandler;
import org.wso2.carbon.crypto.tenant.hsmstore.mgt.internal.HSMTenantMgtDataHolder;
import org.wso2.carbon.stratos.common.beans.TenantInfoBean;
import org.wso2.carbon.stratos.common.exception.StratosException;

import java.security.PrivateKey;
import java.security.cert.Certificate;

public class HSMStoreManager {

    private static Log log = LogFactory.getLog(HSMStoreManager.class);

    private ServerConfigurationService serverConfigurationService;
    private SessionHandler sessionHandler;
    private SlotResolver slotResolver;

    public HSMStoreManager() throws StratosException {

        this.serverConfigurationService = HSMTenantMgtDataHolder.getServerConfigurationService();
        this.slotResolver = new DefaultSlotResolver(serverConfigurationService);
        try {
            sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
        } catch (CryptoException e) {
            String errorMessage = "Error occurred while retrieving the SessionHandler default instance.";
            throw new StratosException(errorMessage, e);
        }
    }

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
            Session session = initiateSession(CryptoContext.buildEmptyContext(tenantInfoBean.getTenantId(),
                    tenantInfoBean.getTenantDomain()));
            KeyHandler keyHandler = new KeyHandler(session);
            CertificateHandler certificateHandler = new CertificateHandler(session);
            keyHandler.storeKey(privateKeyToStore);
            keyHandler.storeKey(pkcs11CertificateData.getPublicKey());
            certificateHandler.storeCertificate(pkcs11CertificateData.getCertificate());
            logDebug(String.format("Successfully stored private key and public certificate of tenant : '%s' " +
                    "in HSM device.", tenantInfoBean.getTenantDomain()));
            sessionHandler.closeSession(session);
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while storing the public certificate and private " +
                    "key of tenant : %s", tenantInfoBean.getTenantDomain());
            throw new StratosException(errorMessage);
        }
    }

    protected Session initiateSession(CryptoContext cryptoContext) throws CryptoException {

        SlotInfo slotInfo = slotResolver.resolveSlot(cryptoContext);
        return sessionHandler.initiateSession(slotInfo.getSlotID(), slotInfo.getPin(), true);
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
