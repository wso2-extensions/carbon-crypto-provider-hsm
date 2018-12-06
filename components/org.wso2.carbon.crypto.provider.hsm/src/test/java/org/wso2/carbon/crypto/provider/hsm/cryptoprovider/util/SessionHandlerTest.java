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

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.provider.hsm.TestUtil;

public class SessionHandlerTest {

    private ServerConfigurationService serverConfigurationService;
    private SessionHandler sessionHandler;

    @BeforeClass
    public void setUpClass() throws ServerConfigurationException, CryptoException {

        serverConfigurationService = TestUtil.getServerConfigurationService();
        sessionHandler = SessionHandler.getDefaultSessionHandler(serverConfigurationService);
    }

    @Test(dataProvider = "initiateSessionDataProvider")
    public void testInitiateSession(int slotNo, boolean readWrite) throws TokenException {

        try {
            Session session = sessionHandler.initiateSession(slotNo, null, readWrite);
            Assert.assertTrue((session.getSessionInfo().isRwSession() == readWrite));
            // Close the created session.
            sessionHandler.closeSession(session);
        } catch (CryptoException e) {

        }
    }

    @DataProvider(name = "initiateSessionDataProvider")
    public Object[][] createSessionInitiationData() {

        return new Object[][]{
                {
                        0, true
                },
                {
                        0, false
                },
                {
                        1, true
                },
                {
                        100, false
                }
        };
    }
}
