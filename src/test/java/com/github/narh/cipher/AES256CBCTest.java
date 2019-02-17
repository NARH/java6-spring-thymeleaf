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

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.narh.cipher.command.AES256CBCCryptCommand;
import com.github.narh.cipher.command.CryptCommand;

/**
 * @author narita
 *
 */
public class AES256CBCTest {
  Logger log = LoggerFactory.getLogger(AES256CBCTest.class);

  public static String ORIGIN_NAME = "hoge";
  public static String FILE_128_NAME = "hoge_128.enc";
  public static String FILE_256_NAME = "hoge_256.enc";
  public static String PASSPHRASE = "123456";

  @Test
  public void testGetSalt() throws Exception {
    log.info("start");
    URL filePath = getClass().getClassLoader().getResource(FILE_256_NAME);
    File file = new File(filePath.toURI());
    byte[] salt = new byte[8];
    byte[] secretKey = new byte[64];
    byte[] iv = new byte[32];
    if(file.exists()) {
      byte[] contents = convertFile(file);
      if(0 < contents.length) {
        log.error("size is {}", contents.length);
        salt = Arrays.copyOfRange(contents, 8, 16);
        byte[] secretKey1 = DigestUtils.md5(ArrayUtils.addAll(PASSPHRASE.getBytes(), salt));
        byte[] secretKey2 = DigestUtils.md5(ArrayUtils.addAll(secretKey1, ArrayUtils.addAll(PASSPHRASE.getBytes(), salt)));
        secretKey = ArrayUtils.addAll(secretKey1, secretKey2);
        iv = DigestUtils.md5(ArrayUtils.addAll(secretKey2, ArrayUtils.addAll(PASSPHRASE.getBytes(), salt)));
      }
      else
        log.error("size is 0");
    }
    String saltStr = Hex.encodeHexString(salt).toUpperCase();
    log.info("SALT:{}", saltStr);
    assertThat("SALT が期待値であること", saltStr, is("FD371BBFCC34FE95"));

    String secretKeyStr = Hex.encodeHexString(secretKey).toUpperCase();
    log.info("SECRET KEY:{}", secretKeyStr);
    assertThat("SECRET KEY が期待値であること", secretKeyStr, is("E5E6290CE26781B2BB44136A49A35669F79522AD4ED0909BF20550CC25A23718"));

    String ivStr = Hex.encodeHexString(iv).toUpperCase();
    log.info("IV:{}",ivStr);
    assertThat("IV が期待値であること",ivStr, is("0F6A53BC0764B87F3D0EB6B0A57B1E70"));

    log.info("end");
  }


  @Test
  public void testGetSaltAndKey() throws Exception {
    URL filePath = getClass().getClassLoader().getResource(FILE_256_NAME);
    File file = new File(filePath.toURI());

    byte[] origin = Utils.getContentsByFile(file);
    byte[] salt = CipherAESUtils.getSaltByOpenSSLCryptFiles(origin);
    byte[] secretKey = CipherAESUtils.generateSecretKey(PASSPHRASE.getBytes(), salt);
    byte[] iv = CipherAESUtils.generateIV(PASSPHRASE.getBytes(), salt, secretKey);

    CipherContext context = CipherContext.builder()
        .cryptMode(CryptMode.ENCRYPT)
        .salt(salt)
        .secretKey(secretKey)
        .iv(iv)
        .origin(origin)
        .build();

    assertThat("SALT が期待値であること"
        , Hex.encodeHexString(context.getSalt()).toUpperCase()
        , is("FD371BBFCC34FE95"));
    assertThat("SECRET KEY が期待値であること"
        , Hex.encodeHexString(context.getSecretKey()).toUpperCase()
        , is("E5E6290CE26781B2BB44136A49A35669F79522AD4ED0909BF20550CC25A23718"));
    assertThat("IV が期待値であること"
        , Hex.encodeHexString(context.getIv()).toUpperCase()
        , is("0F6A53BC0764B87F3D0EB6B0A57B1E70"));
  }

  @Test
  public void testEncryptFile() throws Exception {
    URL filePath = getClass().getClassLoader().getResource(FILE_256_NAME);
//    URL filePath = getClass().getClassLoader().getResource(FILE_128_NAME);
    File file = new File(filePath.toURI());

    byte[] encoded = Utils.getContentsByFile(file);
    byte[] salt = CipherAESUtils.getSaltByOpenSSLCryptFiles(encoded);
    byte[] secretKey = CipherAESUtils.generateSecretKey(PASSPHRASE.getBytes(), salt);
    byte[] iv = CipherAESUtils.generateIV(PASSPHRASE.getBytes(), salt, secretKey);
    log.info("encrypted data size {}", encoded.length);
    log.info("encrypted data {}", Hex.encodeHexString(encoded).toUpperCase());

    URL originPath = getClass().getClassLoader().getResource(ORIGIN_NAME);
    File originFile = new File(originPath.toURI());
    byte[] origin = Utils.getContentsByFile(originFile);

    CipherContext context = CipherContext.builder()
        .cryptMode(CryptMode.ENCRYPT)
        .passphrase(PASSPHRASE.getBytes())
        .salt(salt)
        .secretKey(secretKey)
        .iv(iv)
        .origin(origin)
        .build();

    CryptCommand command = new AES256CBCCryptCommand();
//    CryptCommand command = new AES128CryptCommand();
    command.encrypt(context);

    log.info("encrypt data size:{}", context.getContents().length);
    log.info("encrypt data {}", Hex.encodeHexString(context.getContents()).toUpperCase());

    CipherContext context2 = CipherContext.builder()
        .cryptMode(CryptMode.DECRYPT)
        .passphrase(PASSPHRASE.getBytes())
        .salt(salt)
        .secretKey(secretKey)
        .iv(iv)
        .origin(context.getContents())
        .build();
    command.encrypt(context2);
    log.info("encrypt2 data size:{}", context2.getContents().length);
    log.info("encrypt2 data {}", Hex.encodeHexString(context2.getContents()).toUpperCase());

    assertThat("エンコード済みのデータと同じサイズであること"
        , context2.getContents().length, is(context.getOrigin().length));
    assertThat("エンコード済みのデータと同じであること"
        , Hex.encodeHexString(context2.getContents())
        , is(Hex.encodeHexString(context.getOrigin())));

    assertThat("エンコード済みのデータと同じサイズであること"
        , context.getContents().length, is(encoded.length));
    assertThat("エンコード済みのデータと同じであること"
        , Hex.encodeHexString(context.getContents())
        , is(Hex.encodeHexString(encoded)));
  }

  public byte[] convertFile(File file) throws IOException {
    FileInputStream inputStream = new FileInputStream(file);
    byte[] contents = IOUtils.toByteArray(inputStream);
    inputStream.close();
    return contents;
   }
}
