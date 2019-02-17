/*
 * Copyright (c) 2018, NARH https://github.com/NARH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * * Neither the name of the copyright holder nor the names of its contributors
 *   may be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.github.narh.cipher;

import java.security.Provider;
import java.security.Security;

import javax.swing.JOptionPane;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpATTRS;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherSftpStreamTest {

  private String USER_NAME = "";
  private String HOSTNAME  = "";
  private String IDENTITY_FILE = null;
  private byte[] PASSPHRASE = null;
  static {
    Security.insertProviderAt(new BouncyCastleProvider(),1);
  }

  @Test
  public void testConnectSFTP() throws Exception {
    Provider[] providers = Security.getProviders();
    for(Provider p:providers) {
      log.info("{}:#{}", p.getName(), p.getVersion());
      log.info(p.getInfo());
    }

    try {
      HOSTNAME  = JOptionPane.showInputDialog("Remote host name");
      USER_NAME = JOptionPane.showInputDialog("Your loggin account");
      IDENTITY_FILE = JOptionPane.showInputDialog("Your identity file.(.ssh/id_rsa)");
      PASSPHRASE = JOptionPane.showInputDialog("Your identity passphrase").getBytes();
    }
    catch(RuntimeException e) {}


    JSch.setLogger(new JSCLoggerAdapter());
    JSch jsch=new JSch();
    jsch.addIdentity(IDENTITY_FILE, PASSPHRASE);
    Session session=jsch.getSession(USER_NAME, HOSTNAME, 22);
    //session.setConfig("cipher.c2s", "3des-cbc,aes192-cbc,aes128-cbc,aes256-cbc");
    //session.setConfig("mac.c2s", "hmac-sha2-256");
    //session.setConfig("kex", "diffie-hellman-group1-sha1");
    //session.setConfig("kex", "diffie-hellman-group-exchange-sha256");
    //session.setConfig("cipher.s2c", "aes256-ctr");
    //session.setConfig("mac.s2c", "hmac-sha2-256");
    //session.setConfig("cipher.c2s", "aes256-ctr");
    //session.setConfig("mac.c2s", "hmac-sha2-256");
    session.setConfig("StrictHostKeyChecking", "no");
    //session.setPassword("");
    //session.setTimeout(5000);
    session.connect();
    if(session.isConnected()) {
      ChannelSftp channel=(ChannelSftp)session.openChannel("sftp");
      channel.connect();
      SftpATTRS result = channel.lstat(".");
      log.info("ls results is {}", result);
    }
    session.disconnect();
  }

  class JSCLoggerAdapter implements com.jcraft.jsch.Logger {

    /* (非 Javadoc)
     * @see com.jcraft.jsch.Logger#isEnabled(int)
     */
    public boolean isEnabled(int level) {
      switch(level) {
        case DEBUG: return log.isDebugEnabled();
        case INFO: return log.isInfoEnabled();
        case WARN: return log.isWarnEnabled();
        case ERROR: return log.isErrorEnabled();
        case FATAL: return true;
        default: return log.isTraceEnabled();
      }
    }

    /* (非 Javadoc)
     * @see com.jcraft.jsch.Logger#log(int, java.lang.String)
     */
    public void log(int level, String message) {
      switch(level) {
        case DEBUG: log.debug(message);
        break;
        case INFO:  log.info(message);
        break;
        case WARN:  log.warn(message);
        break;
        case ERROR:  log.error(message);
        break;
        case FATAL:  log.error(message);
        break;
        default: log.trace(message);
      }
    }

  }
}
