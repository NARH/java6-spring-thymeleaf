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

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import javax.crypto.CipherOutputStream;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherOutputStreamBuilderTest {

  @Test
  public void test128bit書き込み正常系() throws Exception {
    log.info("test start.");
    /* 仕込み */
    byte[] salt = Hex.decodeHex("3228F10D3D2D1CC0");
    log.debug("salt is {}.", Hex.encodeHexString(salt));

    byte[] secretKey = Hex.decodeHex("23CC54926C5958DA8CED8B26323C0F52");
    log.debug("salt is {}.", Hex.encodeHexString(secretKey));

    byte[] iv = Hex.decodeHex("28ED23032405BE59D9CB204E7A286FE9");
    log.debug("salt is {}.", Hex.encodeHexString(iv));

    File origFile = new File(getClass().getClassLoader().getResource("hoge").toURI());
    File parentDir = origFile.getAbsoluteFile().getParentFile().getParentFile().getParentFile();
    byte[] payload = ArrayUtils.addAll("Salted__".getBytes(), salt);

    String destFileName = "hoge_128.enc";
    File destFile = new File(parentDir.getAbsolutePath() + File.separator + destFileName);
    OutputStream output = new FileOutputStream(destFile);
    output.write(payload);
    output.flush();

    /* OutputStream 試験 */
    CipherOutputStreamBuilder builder = new CipherOutputStreamBuilder();
    CipherOutputStream cipherOutputStream = builder
      .algorithm(CipherAlgorithm.AES128CBC)
      .operation(CipherOperationMode.ENCRYPT)
      .outputStream(output)
      .secretkey(secretKey)
      .iv(iv)
      .build();

    InputStream origInputStream = getClass().getClassLoader().getResourceAsStream("hoge");
    IOUtils.copy(origInputStream, cipherOutputStream);
    cipherOutputStream.flush();
    output.flush();

    /* 後始末 */
    IOUtils.closeQuietly(cipherOutputStream);
    IOUtils.closeQuietly(output);

    assertThat("復号したファイルが存在すること", destFile.exists(), is(true));

    InputStream destData = new BufferedInputStream(new FileInputStream(destFile));
    ByteArrayOutputStream dest = new  ByteArrayOutputStream();
    IOUtils.copy(destData, dest);
    IOUtils.closeQuietly(destData);
    InputStream origData = getClass().getClassLoader().getResourceAsStream("hoge_128.enc");
    ByteArrayOutputStream orig = new ByteArrayOutputStream();
    IOUtils.copy(origData, orig);
    IOUtils.closeQuietly(origData);
    assertThat("元ファイルと同じであること", dest.toByteArray(), is(orig.toByteArray()));
    IOUtils.closeQuietly(dest);
    IOUtils.closeQuietly(orig);
    destFile.delete();
    log.info("test end.");
  }
}
