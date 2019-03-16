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

package com.github.narh.cipher.stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.junit.Test;

import com.github.narh.cipher.CipherAESUtils;
import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.io.CipherInputStream;
import com.github.narh.cipher.io.CipherOutputStream;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherStreamFactoryTest {

  @Test
  public void testGetDecryptInputStream() throws Exception {
    String password  = "password12345";
    byte[] salt = Hex.decodeHex("57010827E1A17C40".toCharArray());
    byte[] secretKey = CipherAESUtils.generateSecretKey(password.getBytes(), salt);
    byte[] iv = CipherAESUtils.generateIV(password.getBytes(), salt, secretKey);

    String base64Str = "U2FsdGVkX19XAQgn4aF8QC2X/hGIz1cnGEeeX7QUAFMgZ8YDU6UmEy+44Dzd9y3Y";
    byte[] base64In = Base64.decodeBase64(base64Str);
    ByteArrayInputStream bin = new ByteArrayInputStream(base64In);
    byte[] payload = new byte[16];
    bin.read(payload, 0, 16);
    log.info(Hex.encodeHexString(Arrays.copyOfRange(payload, 8, 16)).toUpperCase());
    byte[] body = IOUtils.toByteArray(bin);

    Cipher cipher = Cipher.getInstance(CipherAlgorithm.AES256CBC.transration);
    cipher.init(Cipher.DECRYPT_MODE
        , new SecretKeySpec(secretKey, CipherAlgorithm.AES256CBC.algorithm())
        , new IvParameterSpec(iv));

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream out = new CipherOutputStream(outputStream, cipher);
    IOUtils.copy(new ByteArrayInputStream(body), out);
    log.info(new String(outputStream.toByteArray()));
    cipher.doFinal(body);


    log.info("body size is {}", body.length);

    Cipher cipher2 = Cipher.getInstance(CipherAlgorithm.AES256CBC.transration);
    cipher2.init(Cipher.DECRYPT_MODE
        , new SecretKeySpec(secretKey, CipherAlgorithm.AES256CBC.algorithm())
        , new IvParameterSpec(iv));

    ByteArrayInputStream inputStream = new ByteArrayInputStream(body);
    CipherInputStream in = new CipherInputStream(inputStream, cipher2);
    byte[] buf = new byte[1024];
    int read;
    while((read = in.read(buf, 0, buf.length)) != -1) {
      log.info("read size is {}", read);
      log.info(new String(Arrays.copyOfRange(buf, 0, read)));
    }
    IOUtils.closeQuietly(in);
  }

  @Test
  public void testGetDecryptInputStream2() throws Exception {
    String password  = "password12345";
    byte[] salt = Hex.decodeHex("0AF8B367697D3312".toCharArray());
    byte[] secretKey = CipherAESUtils.generateSecretKey(password.getBytes(), salt);
    byte[] iv = CipherAESUtils.generateIV(password.getBytes(), salt, secretKey);

    String base64Str = "U2FsdGVkX18K+LNnaX0zEjKjHrNRTV6VZmduOrq/nfw=";
    byte[] base64In = Base64.decodeBase64(base64Str);
    ByteArrayInputStream bin = new ByteArrayInputStream(base64In);
    byte[] payload = new byte[16];
    bin.read(payload, 0, 16);
    log.info(Hex.encodeHexString(Arrays.copyOfRange(payload, 8, 16)).toUpperCase());
    byte[] body = IOUtils.toByteArray(bin);

    Cipher cipher = Cipher.getInstance(CipherAlgorithm.AES256CBC.transration);
    cipher.init(Cipher.DECRYPT_MODE
        , new SecretKeySpec(secretKey, CipherAlgorithm.AES256CBC.algorithm())
        , new IvParameterSpec(iv));

    log.info("block size is {}.", cipher.getBlockSize());
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream out = new CipherOutputStream(outputStream, cipher);
    IOUtils.copy(new ByteArrayInputStream(body), out);
    IOUtils.closeQuietly(out);
    log.info("output result: {}", new String(outputStream.toByteArray(), "SJIS"));


    log.info("body size is {}", body.length);

    Cipher cipher2 = Cipher.getInstance(CipherAlgorithm.AES256CBC.transration);
    cipher2.init(Cipher.DECRYPT_MODE
        , new SecretKeySpec(secretKey, CipherAlgorithm.AES256CBC.algorithm())
        , new IvParameterSpec(iv));

    log.info("block size is {}.", cipher2.getBlockSize());
    ByteArrayInputStream inputStream = new ByteArrayInputStream(body);
    CipherInputStream in = new CipherInputStream(inputStream, cipher2);
    byte[] buf = new byte[1024];
    int read;
    while((read = in.read(buf, 0, buf.length)) != -1) {
      log.info("read size is {}", read);
      log.info("input result: {}", new String(Arrays.copyOfRange(buf, 0, read), "SJIS"));
    }
    IOUtils.closeQuietly(in);
  }
}
