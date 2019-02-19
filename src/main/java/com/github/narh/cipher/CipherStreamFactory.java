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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.zip.ZipOutputStream;

import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

import com.github.narh.cipher.stream.CipherInputStreamBuilder;
import com.github.narh.cipher.stream.CipherOutputStreamBuilder;

/**
 * @author narita
 *
 */
public class CipherStreamFactory {

  private final Properties prop;

  public CipherStreamFactory(final Properties prop) {
    this.prop = prop;
  }

  public CipherInputStream getEncryptInputStream(InputStream inputStream)
    throws Exception {
    try {
      return new CipherInputStreamBuilder().build();
    } catch (InvalidKeyException e) {
      throw e;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    } catch (NoSuchPaddingException e) {
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      throw e;
    }
  }

  public CipherInputStream getDecryptInputStream(InputStream inputStream)
    throws Exception {
    try {
      return new CipherInputStreamBuilder().build();
    } catch (InvalidKeyException e) {
      throw e;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    } catch (NoSuchPaddingException e) {
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      throw e;
    }
  }

  public CipherOutputStream getEncryptOutputStream(OutputStream outputStream)
    throws Exception {
    try {
      return new CipherOutputStreamBuilder().build();
    } catch (InvalidKeyException e) {
      throw e;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    } catch (NoSuchPaddingException e) {
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      throw e;
    }
  }

  public CipherOutputStream getDecryptOutputStream(OutputStream outputStream)
    throws Exception {
    try {
      return new CipherOutputStreamBuilder().build();
    } catch (InvalidKeyException e) {
      throw e;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    } catch (NoSuchPaddingException e) {
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      throw e;
    }
  }

  public ZipOutputStream getZipOutputStream(OutputStream outputStream)
    throws Exception {
    try {
      return new ZipOutputStream(new CipherOutputStreamBuilder().build());
    } catch (InvalidKeyException e) {
      throw e;
    } catch (NoSuchAlgorithmException e) {
      throw e;
    } catch (NoSuchPaddingException e) {
      throw e;
    } catch (InvalidAlgorithmParameterException e) {
      throw e;
    }
  }
}
