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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.NoSuchPaddingException;

import com.github.narh.cipher.io.CipherInputStream;
import com.github.narh.cipher.io.CipherInputStreamBuilder;
import com.github.narh.cipher.io.CipherOutputStream;
import com.github.narh.cipher.io.CipherOutputStreamBuilder;

/**
 * @author narita
 *
 */
public class CipherStreamFactory {

  private static CipherStreamFactory instance = new CipherStreamFactory();

  public static final String BYTE_ENCODING="ISO_8859_1";

  private CipherStreamFactory() {
  }

  public static CipherStreamFactory getInstance() {
    return instance;
  }

  public CipherInputStream getEncryptInputStream(CipherConfig config, CipherParam param, InputStream inputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
    byte[] password   = config.getPassword().getBytes(BYTE_ENCODING);
    byte[] salt       = CipherAESUtils.generateSalt();
    MessageDigest md  = config.getHashAlgorithm().getMessageDigest();
    byte[] secretKey  = CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, null);
    byte[] iv         = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, secretKey), 16);

    param.setSalt(salt);
    param.setSecretkey(secretKey);
    param.setIv(iv);

    return new CipherInputStreamBuilder()
        .operation(CipherOperationMode.ENCRYPT)
        .algorithm(config.getAlgorithm())
        .secretkey(secretKey)
        .iv(iv)
        .inputStream(inputStream)
        .build();
  }

  public CipherInputStream getDecryptInputStream(CipherConfig config, CipherParam param, InputStream inputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
    byte[] password   = config.getPassword().getBytes(BYTE_ENCODING);
    byte[] salt       = CipherAESUtils.readSaltFromInputStream(inputStream);
    MessageDigest md  = config.getHashAlgorithm().getMessageDigest();
    byte[] secretKey  = CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, null);
    byte[] iv         = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, secretKey), 16);

    param.setSalt(salt);
    param.setSecretkey(secretKey);
    param.setIv(iv);

    return new CipherInputStreamBuilder()
        .operation(CipherOperationMode.DECRYPT)
        .algorithm(config.getAlgorithm())
        .secretkey(secretKey)
        .iv(iv)
        .inputStream(inputStream)
        .build();
  }

  public CipherOutputStream getEncryptOutputStream(CipherConfig config, CipherParam param, OutputStream outputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
    byte[] password   = config.getPassword().getBytes(BYTE_ENCODING);
    byte[] salt       = CipherAESUtils.generateSalt();
    MessageDigest md  = config.getHashAlgorithm().getMessageDigest();
    byte[] secretKey  = CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, null);
    byte[] iv         = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, secretKey), 16);

    param.setSalt(salt);
    param.setSecretkey(secretKey);
    param.setIv(iv);

    CipherAESUtils.writePayload(outputStream, salt);
    return new CipherOutputStreamBuilder()
        .operation(CipherOperationMode.ENCRYPT)
        .algorithm(config.getAlgorithm())
        .secretkey(secretKey)
        .iv(iv)
        .outputStream(outputStream)
        .build();
  }

  public CipherOutputStream getDecryptOutputStream(CipherConfig config, CipherParam param, OutputStream outputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException {
    byte[] password   = config.getPassword().getBytes(BYTE_ENCODING);
    byte[] salt       = config.getSalt();
    MessageDigest md  = config.getHashAlgorithm().getMessageDigest();
    byte[] secretKey  = CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, null);
    byte[] iv         = Arrays.copyOf(
        CipherAESUtils.openSSLEvpBytesToKey(password, salt, md, 1, secretKey), 16);

    param.setSalt(salt);
    param.setSecretkey(secretKey);
    param.setIv(iv);

    return new CipherOutputStreamBuilder()
        .operation(CipherOperationMode.DECRYPT)
        .algorithm(config.getAlgorithm())
        .secretkey(secretKey)
        .iv(iv)
        .outputStream(outputStream)
        .build();
  }

  public ZipOutputStream getEncryptZipOutputStream(CipherConfig config, CipherParam param, OutputStream outputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
    return new ZipOutputStream(getEncryptOutputStream(config, param, outputStream));
  }

  public ZipInputStream getDecryptZipInputStream(CipherConfig config, CipherParam param, InputStream inputStream)
      throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException {
    return new ZipInputStream(getDecryptInputStream(config, param, inputStream));
  }
}