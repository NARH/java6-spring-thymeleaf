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


import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

import javax.crypto.CipherInputStream;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.IOUtils;
import org.junit.Test;

import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherInputStreamBuilderTest {

  @Test
  public void test128bit読み込み正常系() throws Exception {
    log.info("test start.");
    /* 仕込み */
    byte[] salt = Hex.decodeHex("3228F10D3D2D1CC0");
    log.debug("salt is {}.", Hex.encodeHexString(salt));

    byte[] secretKey = Hex.decodeHex("23CC54926C5958DA8CED8B26323C0F52");
    log.debug("salt is {}.", Hex.encodeHexString(secretKey));

    byte[] iv = Hex.decodeHex("28ED23032405BE59D9CB204E7A286FE9");
    log.debug("salt is {}.", Hex.encodeHexString(iv));

    String targetFileName = "hoge_128.enc";
    InputStream input = new FileInputStream(new File(getClass().getClassLoader().getResource(targetFileName).toURI()));
    byte[] payload = new byte[16];
    int readed = input.read(payload);
    String payloadStr = new String(Arrays.copyOfRange(payload, 0, 8));
    log.debug("payload is {}.", payloadStr);
    assertThat("PAYLOAD が Salted__ であること", payloadStr, is("Salted__"));
    byte[] readSalt = Arrays.copyOfRange(payload, 8, 16);
    log.debug("read SALT is {}.", Hex.encodeHexString(readSalt));
    assertThat("16bytes 読み取ること", readed, is(16));
    assertThat("SALTが一致していること", readSalt, is(salt));

    /* InputStream 試験 */
    CipherInputStreamBuilder builder = new CipherInputStreamBuilder();
    CipherInputStream cipherInputStream = builder
      .algorithm(CipherAlgorithm.AES128CBC)
      .operation(CipherOperationMode.DECRYPT)
      .inputStream(input)
      .secretkey(secretKey)
      .iv(iv)
      .build();

    String outputFileName = "hoge.txt";
    File parentPath = new File(getClass().getClassLoader().getResource(targetFileName).toURI())
        .getParentFile().getParentFile().getParentFile();
    File outputFile = new File(parentPath.getAbsolutePath() + File.separator + outputFileName);
    OutputStream output = new FileOutputStream(outputFile);
    IOUtils.copy(cipherInputStream, output);
    /* 後始末 */
    IOUtils.closeQuietly(output);
    IOUtils.closeQuietly(cipherInputStream);
    log.info("test end.");
  }
}
