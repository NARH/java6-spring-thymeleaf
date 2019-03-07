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
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

import com.github.narh.cipher.CipherAESUtils;
import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;
import com.github.narh.cipher.io.CipherOutputStreamBuilder;
import com.github.narh.cipher.io.CipherZipOutputStream;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CipherZipOutputStreamTest {

  @Test
  public void testZipArchive() throws Exception {

    String password  = "password12345";
    byte[] salt = Hex.decodeHex("0AF8B367697D3312".toCharArray());

    MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
    byte[] secretKey = CipherAESUtils.openSSLEvpBytesToKey(password.getBytes(), salt, messageDigest, 1, null);
    byte[] iv = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password.getBytes(), salt, messageDigest, 1, secretKey), 16);

    File file = File.createTempFile("Hoge", ".enc");
    OutputStream out = new FileOutputStream(file);
    InputStream in = new ByteArrayInputStream(ArrayUtils.addAll(
        "Salted__".getBytes(), salt));
    IOUtils.copy(in, out);
    IOUtils.closeQuietly(in);

    ZipOutputStream zos = new CipherZipOutputStream(new CipherOutputStreamBuilder()
        .algorithm(CipherAlgorithm.AES256CBC)
        .operation(CipherOperationMode.ENCRYPT)
        .secretkey(secretKey)
        .iv(iv)
        .outputStream(out)
        .build());

    zos.putNextEntry(new ZipEntry("foo.txt"));
    in = new ByteArrayInputStream("これはテスト".getBytes(Charset.forName("UTF-8")));
    IOUtils.copy(in, zos);
    IOUtils.closeQuietly(in);
    IOUtils.closeQuietly(zos);

    if(file.renameTo(new File("/Users/narita/Desktop/Hoge.enc")))
      log.info("コピーしました");
  }
}
