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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NullCipher;

/**
 * @author narita
 *
 */
public class CipherOutputStream extends FilterOutputStream {
  private final Cipher cipher;
  private OutputStream output;
  private byte[] ibuffer = new byte[1];
  private byte[] obuffer;
  private boolean closed = false;

  /**
   * コンストラクタ
   * @param os アウトプットストリーム
   * @param c java.crypto.Cipher 暗号化変換
   */
  public CipherOutputStream(OutputStream os, Cipher c) {
    super(os);
    output = os;
    cipher = c;
  }
  /**
   * コンストラクタ
   * @param os アウトプットストリーム
   */
  protected CipherOutputStream(OutputStream os) {
    super(os);
    output = os;
    cipher = new NullCipher();
  }
  /**
   * ストリームに書き込む
   * @see java.io.OutputStream#write(int)
   */
  public void write(int b) throws IOException {
    ibuffer[0] = (byte) b;
    obuffer = cipher.update(ibuffer, 0, 1);
    if (obuffer != null) {
        output.write(obuffer);
        obuffer = null;
    }
  }
  /**
   * ストリームに書き込む
   * @see java.io.OutputStream#write(byte[])
   */
  public void write(byte b[]) throws IOException {
    write(b, 0, b.length);
  }
  /**
   * ストリームに書き込む
   * @see java.io.OutputStream#write(byte[], int, int)
   */
  public void write(byte b[], int off, int len) throws IOException {
    obuffer = cipher.update(b, off, len);
    if (obuffer != null) {
        output.write(obuffer);
        obuffer = null;
    }
  }
  /**
   * 書き込みを確定する
   * @see java.io.OutputStream#flush()
   */
  public void flush() throws IOException {
    if (obuffer != null) {
        output.write(obuffer);
        obuffer = null;
    }
    output.flush();
  }
  /**
   * ストリームを閉じる
   * @see java.io.OutputStream#close()
   */
  public void close() throws IOException {
    if (closed) {
        return;
    }

    closed = true;
    try {
        obuffer = cipher.doFinal();
    } catch (IllegalBlockSizeException e) {
        obuffer = null;
    } catch (BadPaddingException e) {
        obuffer = null;
    }
    try {
        flush();
    } catch (IOException ignored) {}
    out.close();
  }

}
