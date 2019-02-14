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
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.junit.Test;

import lombok.extern.slf4j.Slf4j;

/**
 * @author narita
 *
 */
@Slf4j
public class CIperZipArchveTest {

  public static final byte[] SEED = "abcdef".getBytes();
  public static final byte[] PASSPHRASE = "12345678".getBytes();

  public static final String PAYLOAD_STRING = "Salted__";
  public static final String KEY_ENCODING   = "AES";
  public static final String ENCODING_MODE  = "AES/CBC/PKCS5PADDING";
  public static String ORIGIN_NAME = "hoge";
  public static String FILE_256_NAME = "hoge_256.enc";

  @Test
  public void testZipArchiveToChiper() throws Exception {
    log.info("start");
    Cipher cipher = Cipher.getInstance(ENCODING_MODE);
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    md.reset();
    md.update(SEED);
    md.update(PASSPHRASE);
    byte[] salt = Arrays.copyOfRange(md.digest(), 0,8);
    log.info("salt is {}.", Hex.encodeHexString(salt).toUpperCase());
    byte[] secretKey = openSSLEvpBytesToKey(PASSPHRASE, salt, md, 1, null);
    log.info("secret key is {}.", Hex.encodeHexString(secretKey).toUpperCase());
    byte[] iv = Arrays.copyOfRange(
        openSSLEvpBytesToKey(PASSPHRASE, salt, md, 1, secretKey), 0, 16);
    log.info("iv is {}.", Hex.encodeHexString(iv).toUpperCase());

    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(secretKey, KEY_ENCODING)
        , new IvParameterSpec(iv));

    URL filePath = getClass().getClassLoader().getResource(FILE_256_NAME);
    File parentDir = new File(filePath.toURI()).getParentFile().getParentFile().getParentFile();
    FileOutputStream fileOutput = new FileOutputStream(
        new File(parentDir.getAbsolutePath() + File.separator + FILE_256_NAME));
    fileOutput.write(ArrayUtils.addAll(PAYLOAD_STRING.getBytes(), salt));
    CipherOutputStream cipherOutput = new CipherOutputStream(fileOutput, cipher);

    ZipOutputStream zipOutput = new ZipOutputStream(cipherOutput);

    File archiveFiles = new File(
        getClass().getClassLoader().getResource(ORIGIN_NAME).toURI());
    zipOutput.putNextEntry(new ZipEntry(archiveFiles.getName()));

    InputStream in = new BufferedInputStream(new FileInputStream(archiveFiles));
    byte[] buf = new byte[1024];
    int len = 0;
    while ((len = in.read(buf)) != -1) zipOutput.write(buf, 0, len);

    IOUtils.closeQuietly(in);
    IOUtils.closeQuietly(zipOutput);
    IOUtils.closeQuietly(cipherOutput);
    IOUtils.closeQuietly(fileOutput);

    log.info("end");
  }

  public static byte[] openSSLEvpBytesToKey(final byte[] passphrase, final byte[] salt, MessageDigest messageDigest, int count, byte[] digest) {
    if(null == passphrase || 0 == passphrase.length) throw new IllegalArgumentException("passphrase is empty.");
    if(null == salt || 8 > salt.length) throw new IllegalArgumentException("salt is empty or too short.");
    messageDigest.reset();
    if(null != digest) messageDigest.update(digest);
    messageDigest.update(passphrase);
    messageDigest.update(salt, 0, 8);
    digest = messageDigest.digest();
    return (1 < count) ? openSSLEvpBytesToKey(passphrase, salt, messageDigest, count--, digest) : digest;
  }
}
