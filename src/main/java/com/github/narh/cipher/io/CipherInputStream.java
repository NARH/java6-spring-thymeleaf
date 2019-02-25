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

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NullCipher;

/**
 * @author narita
 *
 */
public class CipherInputStream extends FilterInputStream {

  private final Cipher cipher;
  private InputStream input;
  private byte[] ibuffer = new byte[512];
  private boolean done = false;
  private byte[] obuffer;
  private int ostart = 0;
  private int ofinish = 0;
  private boolean closed = false;

  /**
   * @param arg0
   */
  protected CipherInputStream(InputStream is) {
    super(is);
    input = is;
    cipher = new NullCipher();
  }
  public CipherInputStream(InputStream is, Cipher c) {
    super(is);
    input = is;
    cipher = c;
  }
  public int read() throws IOException {
    if (ostart >= ofinish) {
        // we loop for new data as the spec says we are blocking
        int i = 0;
        while (i == 0) i = getMoreData();
        if (i == -1) return -1;
    }
    return ((int) obuffer[ostart++] & 0xff);
  }
  public int read(byte b[]) throws IOException {
    return read(b, 0, b.length);
  }
  private int getMoreData() throws IOException {
    if (done) return -1;
    int readin = input.read(ibuffer);
    if (readin == -1) {
        done = true;
        try {
            obuffer = cipher.doFinal();
        }
        catch (IllegalBlockSizeException e) {
            obuffer = null;
            throw new IOException(e);
        }
        catch (BadPaddingException e) {
            obuffer = null;
            throw new IOException(e);
        }
        if (obuffer == null) {
            return -1;
        }
        else {
            ostart = 0;
            ofinish = obuffer.length;
            return ofinish;
        }
    }
    try {
        obuffer = cipher.update(ibuffer, 0, readin);
    }
    catch (IllegalStateException e) {
        obuffer = null;
        throw e;
    }
    ostart = 0;
    ofinish = (obuffer == null) ? 0 : obuffer.length;
    return ofinish;
  }
  public int read(byte b[], int off, int len) throws IOException {
    if (ostart >= ofinish) {
        int i = 0;
        while (i == 0) i = getMoreData();
        if (i == -1) return -1;
    }
    if (len <= 0) {
        return 0;
    }
    int available = ofinish - ostart;
    if (len < available) available = len;
    if (b != null) {
        System.arraycopy(obuffer, ostart, b, off, available);
    }
    ostart = ostart + available;
    return available;
  }
  public long skip(long n) throws IOException {
    int available = ofinish - ostart;
    if (n > available) {
        n = available;
    }
    if (n < 0) {
        return 0;
    }
    ostart += n;
    return n;
  }
  public int available() throws IOException {
    return (ofinish - ostart);
  }
  public void close() throws IOException {
    if (closed) {
        return;
    }

    closed = true;
    input.close();

    if (!done) {
        try {
            cipher.doFinal();
        }
        catch (BadPaddingException ex) {
        }
        catch (IllegalBlockSizeException ex) {
        }
    }
    ostart = 0;
    ofinish = 0;
  }
  public boolean markSupported() {
    return false;
  }
}
