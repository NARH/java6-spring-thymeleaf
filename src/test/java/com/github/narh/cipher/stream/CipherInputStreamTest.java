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
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import com.github.narh.cipher.CipherAESUtils;
import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;
import com.github.narh.cipher.io.BlockSizeInputStream;
import com.github.narh.cipher.io.CipherInputStream;
import com.github.narh.cipher.io.CipherInputStreamBuilder;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherInputStreamTest {

  @Test
  public void testCipherInputStreamの振舞い() throws Exception {
    if(log.isInfoEnabled()) log.info("start testCipherInputStreamの振舞い");
    String base64Str = "U2FsdGVkX1+DJgRE9Wn0JFh5FzCTTCbRfjA1/SuR5V3OhSW/VeXZ8zhZzHJ+LDdhiD09PAXHcQOcrfb7sZGnDNXdboiCF7dNAzyKSMdhHFW8kJGQtGKl4WSXAh68IrzyXbwV/ayy4UNWcyAl9ksBXH7oxWC/DW65Gs6yvRj3DGsyYHztoOhn5oS5fTedjV6wag67xwgKIbHcZDB/2WUuoku4luk1EIKseI8QTnCiygQXXqS8reHVCE2UCqqrgiZ2BaSlU+L3TCokH9UaDSE8amzoqYHMxsqCvJgdTWnt7SvS/wmbCC2a1mEi63aLlkGGlH2dw9mo/a29fHLH9ThEJvldJlSYgSGtFvjjrsuMJljtXrEoaugazFTyVkG08Gqx/9cZmOOB6cI8klgo/XazIHeuLvpr3sdYLmQ8q/C2ukk=";

    byte[] base64In = Base64.decodeBase64(base64Str);
    log.info("data size = {}", base64In.length);
    InputStream inputStream = new ByteArrayInputStream(base64In);
    byte[] payload = new byte[16];
    inputStream.read(payload, 0, 16);
    log.info(Hex.encodeHexString(Arrays.copyOfRange(payload, 8, 16)).toUpperCase());

    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    String password  = "password12345";
    byte[] salt = Hex.decodeHex("83260444F569F424".toCharArray());
    byte[] secretKey = CipherAESUtils.openSSLEvpBytesToKey(password.getBytes(), salt, messageDigest, 1, null);
    log.info("secret key = {}", Hex.encodeHexString(secretKey).toUpperCase());
    byte[] iv = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password.getBytes(), salt, messageDigest, 1, secretKey), 16);
    log.info("iv = {}", Hex.encodeHexString(iv).toUpperCase());

    CipherInputStream in = new CipherInputStreamBuilder()
        .algorithm(CipherAlgorithm.AES256CBC)
        .inputStream(inputStream)
        .operation(CipherOperationMode.DECRYPT)
        .secretkey(secretKey)
        .iv(iv)
        .build();

    BlockSizeInputStream bsis = new BlockSizeInputStream(in);

    int bufferSize = 300;
    byte[] data = new byte[bufferSize];
    int readed = 0;
    int count = 0;
    StringBuilder stb = new StringBuilder();
    //while((readed = in.read(data)) != -1) log.info("[{}] readed size = {}", ++count, readed);
    //while((readed = in.read()) != -1) log.info("[{}] readed = {}", ++count, readed);
    while((readed = bsis.read(data)) != -1) {
      stb.append(new String(data, "UTF-8"));
      log.info("[{}] readed size = {}", ++count, readed);
      Arrays.fill(data,(byte) 0);
    }
    bsis.close();
    log.info("data size is {}", stb.toString().trim().length());
    if(log.isInfoEnabled()) log.info("end testCipherInputStreamの振舞い");
  }
}
