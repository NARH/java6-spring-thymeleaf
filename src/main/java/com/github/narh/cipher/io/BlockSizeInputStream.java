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

/**
 * @author narita
 *
 */
public class BlockSizeInputStream extends FilterInputStream {

  public final int EOD = -1;

  private boolean done = false;

  public BlockSizeInputStream(InputStream in) {
    super(in);
  }

  /**
   * スタックにデータがある場合はスタックより1byte返却する
   * 無い場合は、InputStream{@link #read()} より取得したデータを返却する
   */
  public int read() throws IOException {
    return in.read();
  }

  public int read(byte[] data, int offset, int length) throws IOException {
    return read(data, offset, length, 0);
  }

  private int read(byte[] data, int offset, int length, int size) throws IOException {
    if(done) return EOD;
    int bufferSize = Math.min(data.length, length);
    int fetched = in.read(data, offset, bufferSize);
    if (EOD == fetched) {
      done = true;
      return (0 == size) ? EOD : size;
    }
    size += fetched;
    if(size == bufferSize) return size;
    return read(data, offset + size, length, size);
  }

  public int read(byte[] data) throws IOException {
    return read(data, 0, data.length);
  }

  public long skip(long n) throws IOException {
    return in.skip(n);
  }

  public int available() throws IOException {
    return in.available();
  }

  public void close() throws IOException {
    in.close();
  }

  public boolean markSupported() {
    return in.markSupported();
  }
}
