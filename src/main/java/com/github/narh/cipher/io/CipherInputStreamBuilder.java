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

package com.github.narh.cipher.io;

import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;

import lombok.ToString;

/**
 * @author narita
 *
 */
@ToString
public class CipherInputStreamBuilder {

  protected CipherOperationMode operation;
  protected CipherAlgorithm algorithm;
  protected byte[] secretkey;
  protected byte[] iv;
  protected InputStream inputStream;

  public CipherInputStreamBuilder algorithm(final CipherAlgorithm algorithm) {
    this.algorithm = algorithm;
    return this;
  }

  public CipherInputStreamBuilder operation(final CipherOperationMode operation) {
    this.operation = operation;
    return this;
  }

  public CipherInputStreamBuilder secretkey(final byte[] secretkey) {
    this.secretkey = secretkey;
    return this;
  }

  public CipherInputStreamBuilder iv(final byte[] iv) {
    this.iv = iv;
    return this;
  }

  public CipherInputStreamBuilder inputStream(InputStream inputStream) {
    this.inputStream = inputStream;
    return this;
  }

   public CipherInputStream build() throws NoSuchAlgorithmException, NoSuchPaddingException
     , InvalidKeyException, InvalidAlgorithmParameterException {
     valid();
     Cipher cipher = Cipher.getInstance(algorithm.transration);
     if(algorithm.useIV) {
       cipher.init(operation.mode, new SecretKeySpec(secretkey, algorithm.algorithm()), new IvParameterSpec(iv));
     }
     else {
       cipher.init(operation.mode, new SecretKeySpec(secretkey, algorithm.algorithm()));
     }
     return new CipherInputStream(inputStream, cipher);
   }

   protected void valid() {
     if(validAlgorithm() && validOperationMode() && validSecretkey() && validIv() && validInputStream()) {
       return;
     }
     throw new IllegalArgumentException("bad context parameter.[" + toString() + "]");
   }

  /**
   * @return
   */
  private boolean validAlgorithm() {
    return (null != algorithm);
  }

  /**
   * @return
   */
  private boolean validOperationMode() {
    return (null != operation);
  }

  /**
   * @return
   */
  private boolean validSecretkey() {
    return (null != secretkey && algorithm.length / 8 <= secretkey.length);
  }

  /**
   * @return
   */
  protected boolean validIv() {
    return (null != iv && 16 <= iv.length);
  }

  /**
   * @return
   */
  protected boolean validInputStream() {
    return (null != inputStream);
  }
}
