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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;
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
  public static final byte[] SEED = "abcdef".getBytes();
  public static final byte[] CIPHER_PASSPHRASE = "12345678".getBytes();

  public static final String PAYLOAD_STRING = "Salted__";
  public static final String KEY_ENCODING   = "AES";
  public static final String ENCODING_MODE  = "AES/CBC/PKCS5PADDING";
  public static String ORIGIN_NAME = "hoge";
  public static String FILE_256_NAME = "hoge_256.enc";

  private String USER_NAME = "";
  private String HOSTNAME  = "";
  private String IDENTITY_FILE = null;
  private byte[] PASSPHRASE = null;
  static {
    Security.insertProviderAt(new BouncyCastleProvider(),1);
  }

  /**
   * 元ファイルをZip 圧縮し、AES-256-CBC で暗号化し、SFTPでリモートへ送信までする
   * テストコード
   *
   * @throws Exception
   */
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

      Cipher cipher = Cipher.getInstance(ENCODING_MODE);
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.reset();
      md.update(SEED);
      md.update(CIPHER_PASSPHRASE);
      byte[] salt = Arrays.copyOfRange(md.digest(), 0,8);
      log.info("salt is {}.", Hex.encodeHexString(salt).toUpperCase());
      byte[] secretKey = CiperZipArchveTest.openSSLEvpBytesToKey(CIPHER_PASSPHRASE, salt, md, 1, null);
      log.info("secret key is {}.", Hex.encodeHexString(secretKey).toUpperCase());
      byte[] iv = Arrays.copyOfRange(
          CiperZipArchveTest.openSSLEvpBytesToKey(CIPHER_PASSPHRASE, salt, md, 1, secretKey), 0, 16);
      log.info("iv is {}.", Hex.encodeHexString(iv).toUpperCase());

      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, KEY_ENCODING)
          , new IvParameterSpec(iv));

      OutputStream channelOutputStream = channel.put("hoge.enc", ChannelSftp.OVERWRITE);
      channelOutputStream.write(ArrayUtils.addAll(PAYLOAD_STRING.getBytes(), salt));
      CipherOutputStream cipherOutputStream = new CipherOutputStream(channelOutputStream, cipher);
      ZipOutputStream zipOutput = new ZipOutputStream(cipherOutputStream);

      File archiveFiles = new File(
          getClass().getClassLoader().getResource(ORIGIN_NAME).toURI());
      zipOutput.putNextEntry(new ZipEntry(archiveFiles.getName()));

      InputStream in = new BufferedInputStream(new FileInputStream(archiveFiles));
      byte[] buf = new byte[1024];
      int len = 0;
      while ((len = in.read(buf)) != -1) {
        zipOutput.write(buf, 0, len);
        zipOutput.flush();
        cipherOutputStream.flush();
        channelOutputStream.flush();
      }
      zipOutput.flush();
      cipherOutputStream.flush();
      channelOutputStream.flush();

      IOUtils.closeQuietly(in);
      IOUtils.closeQuietly(zipOutput);
      IOUtils.closeQuietly(cipherOutputStream);
      IOUtils.closeQuietly(channelOutputStream);

      channel.disconnect();
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
