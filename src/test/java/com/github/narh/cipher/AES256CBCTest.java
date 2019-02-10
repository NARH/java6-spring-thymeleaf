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

/**
 * @author narita
 *
 */
public class AES256CBCTest {
  Logger log = LoggerFactory.getLogger(AES256CBCTest.class);

//  public static String FILE_NAME = "bootstrap-honoka-4.1.3-dist.zip.enc";
  public static String FILE_NAME = "hoge.enc";
  public static String PASSPHRASE = "123456";

  @Test
  public void testGetSalt() throws Exception {
    log.info("start");
    URL filePath = getClass().getClassLoader().getResource(FILE_NAME);
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
    String saltStr = (new String(Hex.encodeHex(salt))).toUpperCase();
    log.info("SALT:{}", saltStr);
//    assertThat("SALT が期待値であること", saltStr, is("51630B328E08F084"));
    assertThat("SALT が期待値であること", saltStr, is("34A9DECA96AEBA08"));

    String secretKeyStr = (new String(Hex.encodeHex(secretKey))).toUpperCase();
    log.info("SECRET KEY:{}", secretKeyStr);
//    assertThat("SECRET KEY が期待値であること", secretKeyStr, is("7F25EAA66E85DDABB8414670ED4B1FC9C8EAAF814F918D6DECC0F1AC86223FCE"));
    assertThat("SECRET KEY が期待値であること", secretKeyStr, is("56FC5A2B0EEE5F387E24455644C57CFB827AC909288024FF40F1A4990C392585"));

    String ivStr = (new String(Hex.encodeHex(iv))).toUpperCase();
    log.info("IV:{}",ivStr);
//    assertThat("IV が期待値であること",ivStr, is("066E7718EE6FC6217603B77435E33D38"));
    assertThat("IV が期待値であること",ivStr, is("DFF2DB5B08CC74C2EF0D2799B330165D"));

    log.info("end");
  }

  public byte[] convertFile(File file) throws IOException {
    FileInputStream inputStream = new FileInputStream(file);
    byte[] contents = IOUtils.toByteArray(inputStream);
    inputStream.close();
    return contents;
   }
}
