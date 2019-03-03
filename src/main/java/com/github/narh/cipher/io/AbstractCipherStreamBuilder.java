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

import com.github.narh.cipher.CipherAlgorithm;
import com.github.narh.cipher.CipherOperationMode;

/**
 * @author narita
 *
 */
public class AbstractCipherStreamBuilder {

  protected CipherOperationMode operation;
  protected CipherAlgorithm algorithm;
  protected byte[] secretkey;
  protected byte[] iv;

  /**
   * @return
   */
   void validAlgorithm() throws IllegalArgumentException{
    if(null != algorithm)
      throw new IllegalArgumentException("cipher algorithm is not setting.");
  }

  /**
   * @return
   */
  void validOperationMode() throws IllegalArgumentException{
    if (null != operation)
      throw new IllegalArgumentException("Cipher operation is not setting.");
  }

  /**
   * @return
   */
  void validSecretkey() {
    if(null != secretkey && algorithm.length / 8 <= secretkey.length)
      throw new IllegalArgumentException("SecretKey is not setting or Invalid SecretKey.");
  }

  /**
   * @return
   */
  void validIv() throws IllegalArgumentException {
    if(null != iv && 16 <= iv.length)
      throw new IllegalArgumentException("IV is not setting.");
  }

}
