/*
 * A Java implementation of a Time-based One-Time Password algorithm,
 * an extension of the algorithm defined in RFC4226, and designed
 * to be used on low memory devices such as java/doja mobile phones.
 *
 * Copyright (C) 2008  Vincent Bouillet  http://www.vincentbouillet.com/
 * Based on the Time-based One-time Password Algorithm by David M'Raihi
 * and the code of Johan Rydell :
 * http://www.ietf.org/internet-drafts/draft-mraihi-totp-timebased-01.txt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Este c�digo � uma adapta��o do c�digo liberado por Vincent Bouillet
 * para que seja poss�vel a execu��o em celulares com J2ME.
 * This is an adaptation of the code released by Vincent Bouillet
 * to be possible to implement in mobile phones with J2ME.
 *
 * chazgps@gmail.com - Abril / 2009
 */
package smartpass;

import java.util.Date;

public class TOTPGenerator {
    
    public static final int DEFAULT_INTERVAL = 30;    
    private static final Sha1 hmac = new Sha1();
    private static final int[] DIGITS_POWER // 0 1  2   3    4     5      6       7        8
            = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    private int nbDigits;
    private String seed;
    	private static final int PIN_LENGTH = 6; // HOTP or TOTP
    
    public TOTPGenerator(String keyInBase32) {
        this.seed = keyBase32ToHex(keyInBase32);
        this.nbDigits = PIN_LENGTH;
    }
    
    public TOTPGenerator(String keyInBase32, int NbDigits) {
        this.seed = keyBase32ToHex(keyInBase32);
        this.nbDigits = NbDigits;
    }
    
    private String keyBase32ToHex(String keyInBase32) {
        String secretInHex = "";
        byte[] decoded = Base32.decode(keyInBase32);
        for (int i = 0; i < decoded.length; i++) {
            int b = decoded[i];
            if (b < 0) {
                b += 256;
            }
            secretInHex += Integer.toHexString(b + 256).substring(1);
        }
        return secretInHex;
    }

    /**
     * This method generates an TOTP value for the given set of parameters.
     *
     * @param key the shared secret, HEX encoded
     * @param time a value that reflects a time, HEX encoded
     * @param returnDigits number of return digits
     *
     * @return A numeric String in base 10 that includes
     * {@link truncationDigits} digits
     */
    private String generateTOTP(String time) {
        byte[] hash;
        String hexsha1;
        String result = null;

        // compute hmac hash
        //hexsha1 = hmac.hex_hmac_sha1(toBinaryString(seed), toBinaryString(time));
        hexsha1 = hmac.hex_hmac_sha1(toBinaryString(seed), toBinaryString(time));
        
        hash = toByteArray(hexsha1);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        
        int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        
        int otp = binary % DIGITS_POWER[this.nbDigits];
        
        result = Integer.toString(otp);
        while (result.length() < this.nbDigits) {
            result = "0" + result;
        }
        
        return result;
    }

    /**
     * This method generates a byte array in in big-endian byte-order as
     * BigInteger's same function
     *
     * @param number the number to be converted, HEX encoded
     *
     * @return A byte array of 8 bytes
     */
    private byte[] toByteArray(String number) {
        int nBytes = number.length() / 2;
        byte[] msg = new byte[nBytes];
        int i;
        int bytePointer = 0;
        String chunk;
        short s = 0;
        for (i = 0; i < nBytes; i++) {
            chunk = number.substring(i * 2, i * 2 + 2);
            s = Short.parseShort(chunk, 16);
            if (s > 127) {
                s -= 256;
            }
            chunk = String.valueOf(s);
            msg[bytePointer++] = Byte.parseByte(chunk);
        }
        return msg;
    }

    /**
     * This method generates a binary string
     *
     * @param number the number to be converted, HEX encoded
     *
     * @return A byte array of 8 bytes
     */
    private String toBinaryString(String number) {
        
        
        
        
        int nBytes = number.length() / 2;
        String msg = "";
        int i;
        String chunk;
        short s = 0;
        for (i = 0; i < nBytes; i++) {
            chunk = number.substring(i * 2, i * 2 + 2);
            s = Short.parseShort(chunk, 16);
            msg = msg + (char) s;
        }
        return msg;
    }
    
    private String toHexString(byte[] binData) {
        String hex_tab = "0123456789abcdef";
        String str = "";
        int myByte;
        for (int i = 0; i < binData.length; i++) {
            myByte = (binData[i] < 0) ? binData[i] + 256 : binData[i];
            str = str + hex_tab.charAt(myByte >> 4) + hex_tab.charAt(myByte & 0xF);
        }
        return str;
    }
    
    public String computeOTP(Date pNow) {
        long lTimeWindow = DEFAULT_INTERVAL * 1000;
        
        long l = pNow.getTime() / lTimeWindow;
        String time = Long.toString(l, 16).toUpperCase();
        while (time.length() < 16) {
            time = "0" + time;
        }
        
        String totp = generateTOTP(time);
        
        return totp;
    }
}
