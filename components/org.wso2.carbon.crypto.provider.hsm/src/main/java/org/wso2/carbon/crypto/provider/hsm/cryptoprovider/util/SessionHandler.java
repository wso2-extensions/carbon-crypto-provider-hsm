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

package org.wso2.carbon.crypto.provider.hsm.cryptoprovider.util;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.cryptoprovider.exception.HSMCryptoException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * This class is responsible for handling sessions between application and the HSM.
 */
public class SessionHandler {

    private static final String PKCS11_MODULE_PROPERTY_PATH =
            "CryptoService.HSMBasedCryptoProviderConfig.HSMConfiguration.PKCS11Module";
    private static Log log = LogFactory.getLog(SessionHandler.class);
    private static SessionHandler sessionHandler;

    private Map<Long, Slot> slotsWithTokensMap;
    private Module pkcs11Module;
    private ServerConfigurationService serverConfigurationService;
    private HashMap<Integer, String> configuredSlots;

    protected SessionHandler(ServerConfigurationService serverConfigurationService) throws CryptoException {

        String pkcs11ModulePath = serverConfigurationService.getFirstProperty(PKCS11_MODULE_PROPERTY_PATH);
        try {
            pkcs11Module = Module.getInstance(pkcs11ModulePath);
            pkcs11Module.initialize(null);
            if (log.isDebugEnabled()) {
                log.debug("PKCS #11 module successfully initialized.");
            }
        } catch (IOException e) {
            String errorMessage = String.format("Unable to locate PKCS #11 Module in path '%s'.", pkcs11ModulePath);
            throw new CryptoException(errorMessage, e);
        } catch (TokenException e) {
            String errorMessage = "PKCS #11 Module initialization failed.";
            throw new HSMCryptoException(errorMessage, e);
        }
        slotsWithTokensMap = new HashMap<>();
        this.serverConfigurationService = serverConfigurationService;
        configuredSlots = new HashMap<Integer, String>();
        setupSlotConfiguration();
    }

    /**
     * Singleton design pattern is used. Only one instance of {@link SessionHandler} is used.
     *
     * @param serverConfigurationService : Service to read carbon.xml configurations.
     * @return Default instance of SessionHandler.
     * @throws CryptoException
     */
    public static SessionHandler getDefaultSessionHandler(ServerConfigurationService serverConfigurationService)
            throws CryptoException {

        synchronized (SessionHandler.class) {
            if (sessionHandler == null) {
                sessionHandler = new SessionHandler(serverConfigurationService);
                if (log.isDebugEnabled()) {
                    log.debug("Default SessionHandler instance successfully instantiated.");
                }
            }
        }
        return sessionHandler;
    }

    /**
     * Initiate a session for a given slot.
     *
     * @param slotId : Slot ID of the required session
     * @return Instance of a Session.
     * @throws CryptoException
     */
    public Session initiateSession(int slotId, String slotPIN, boolean readWriteSession) throws CryptoException {

        if (log.isDebugEnabled()) {
            log.debug(String.format("A session initiation request for slot id : %d.", slotId));
        }
        if (slotsWithTokensMap.isEmpty()) {
            try {
                Slot[] slotsWithTokens = pkcs11Module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
                for (Slot slot : slotsWithTokens) {
                    slotsWithTokensMap.put(slot.getSlotID(), slot);
                }
                if (log.isDebugEnabled()) {
                    log.debug("List of slots with tokens successfully retrieved from the PKCS #11 module.");
                }
            } catch (TokenException e) {
                String errorMessage = String.format("Failed to retrieve slots with tokens.");
                throw new HSMCryptoException(errorMessage, e);
            }
        }
        if (slotsWithTokensMap.containsKey((long) slotId)) {
            Slot slot = slotsWithTokensMap.get((long) slotId);
            try {
                Token token = slot.getToken();
                Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
                        readWriteSession, null, null);
                if (slotPIN == null) {
                    session.login(Session.UserType.USER, getUserPIN(slotId));
                } else {
                    session.login(Session.UserType.USER, slotPIN.toCharArray());
                }
                if (log.isDebugEnabled()) {
                    log.debug(String.format("A session was initiated for slot id : %d.", slotId));
                }
                return session;
            } catch (TokenException e) {
                String errorMessage = String.format("Session initiation failed for slot id : '%d'.", slotId);
                throw new HSMCryptoException(errorMessage, e);
            }
        } else {
            String errorMessage = String.format("Slot '%d' is not configured for cryptographic operations.", slotId);
            throw new CryptoException(errorMessage);
        }
    }

    /**
     * Close the given session.
     *
     * @param session : Session that need to be closed.
     * @throws CryptoException
     */
    public void closeSession(Session session) throws CryptoException {

        if (session != null) {
            try {
                session.closeSession();
            } catch (TokenException e) {
                String errorMessage = "Error occurred during session termination.";
                throw new HSMCryptoException(errorMessage, e);
            }
        }
    }

    protected char[] getUserPIN(int slotID) throws CryptoException {

        if (configuredSlots.containsKey(slotID)) {
            return configuredSlots.get(slotID).toCharArray();
        } else {
            String errorMessage = String.format("Unable to retrieve slot configuration information for slot id " +
                    "'%d'.", slotID);
            throw new CryptoException(errorMessage);
        }
    }

    protected void setupSlotConfiguration() throws CryptoException {

        NodeList configuredSlotsCandidateNodes = serverConfigurationService.getDocumentElement().
                getElementsByTagName("SlotConfiguration");
        if (configuredSlotsCandidateNodes != null) {
            Node hsmSlotConfiguration = configuredSlotsCandidateNodes.item(0);
            NodeList configuredSlots = hsmSlotConfiguration.getChildNodes();
            for (int i = 0; i < configuredSlots.getLength(); i++) {
                Node configuredSlot = configuredSlots.item(i);
                if (configuredSlot.getNodeType() == Node.ELEMENT_NODE && StringUtils.equals("Slot",
                        configuredSlot.getNodeName())) {
                    NamedNodeMap attributes = configuredSlot.getAttributes();
                    int id = Integer.parseInt(attributes.getNamedItem("id").getTextContent());
                    String pin = attributes.getNamedItem("pin").getTextContent();
                    if (!this.configuredSlots.containsKey(id)) {
                        this.configuredSlots.put(id, pin);
                    }
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved slot configuration information from carbon.xml.");
            }
        } else {
            String errorMessage = "Unable to retrieve slot configuration information.";
            throw new CryptoException(errorMessage);
        }
    }
}
