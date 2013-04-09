package com.fastlink2.ssdeep;

/*
 * Copyright (C) 2013 Marius Mailat http://fastlink2.com/contact.htm
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public class SpamSumSignature
{
    private long blockSize;
    private byte[] hash1;
    private byte[] hash2;

     /**
      * GetBytes
      * 
      * Change a String into an array of bytes
      * 
      * @param str
      * @return - byte representation of the string
      */
    public static byte[] GetBytes(String str)
    {
        byte[] r = new byte[str.length()];
        for (int i=0; i<r.length; i++)
            r[i] = (byte)str.charAt(i);
        return r;
    }

    /**
     * GetString
     * 
     * Change an array of bytes into a String
     * 
     * @param hsh
     * @return
     */
    public static  String GetString(byte[] hsh)
    {
        String r = "";
        for (int i=0; i<hsh.length; i++)
            r += (char) hsh[i];
        return r;
    }

    /**
     * SpamSumSignature
     * 
     * Initializes a new instance of the {@code SpamSumSignature} class.
     * 
     * @param signature - the signature
     */
    public SpamSumSignature(String signature)
    {
        if (null == signature)
            throw new IllegalArgumentException("Signature string cannot be null or empty." + "\r\nParameter name: " + "signature");

        int idx1 = signature.indexOf(':');
        int idx2 = signature.indexOf(':', idx1 + 1);

        if (idx1 < 0)
            throw new IllegalArgumentException("Signature is not valid." + "\r\nParameter name: " + "signature");

        if (idx2 < 0)
            throw new IllegalArgumentException("Signature is not valid." + "\r\nParameter name: " + "signature");

        blockSize = Integer.parseInt( signature.substring((0), (0) + (idx1)));
        hash1 = GetBytes(signature.substring(idx1 + 1, idx1 + 1 + idx2 - idx1 - 1));
        hash2 = GetBytes(signature.substring(idx2 + 1));
    }

    /**
     * SpamSumSignature
     * 
     * @param blockSize
     * @param hash1
     * @param hash2
     */
    public SpamSumSignature(long blockSize, byte[] hash1, byte[] hash2)
    {
        this.blockSize = blockSize;
        this.hash1 = hash1;
        this.hash2 = hash2;
    }

    public boolean equals(Object obj)
    {
        if (!(obj instanceof SpamSumSignature))
            return false;

        return this.equals((SpamSumSignature)obj);
    }

    public boolean equals(SpamSumSignature other)
    {
        if (this.blockSize != other.blockSize)
            return false;

        if (this.hash1.length != other.hash1.length)
            return false;

        if (this.hash2.length != other.hash2.length)
            return false;

        for (int idx = 0; idx < hash1.length; idx++)
        {
            if (this.hash1[idx] != other.hash1[idx])
                return false;
        }

        for (int idx = 0; idx < hash2.length; idx++)
        {
            if (this.hash2[idx] != other.hash2[idx])
                return false;
        }

        return true;
    }

    public String toString()
    {
        String hashText1 = GetString(hash1);
        String hashText2 = GetString(hash2);
        return blockSize + ":" + hashText1 + ":" + hashText2;
    }

    /**
     * getBlockSize
     * 
     * Gets the size of the block.
     * 
     * @return - the size of the block.
     */
    public long getBlockSize() { 
    	return blockSize; 
    }

    /**
     * getHashPart1
     * 
     * Gets the first hash part.
     * @return - the first hash part.
     */
    public byte[] getHashPart1() { 
    	return hash1; 
    }

    /**
     * getHashPart2
     * 
     * Gets the second hash part.
     * @return - the second hash part.
     */
    public byte[] getHashPart2() { 
    	return hash2; 
    }
}