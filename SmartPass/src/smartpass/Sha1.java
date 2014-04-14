/*
 * A Java implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1, and designed to be used on low memory devices such as
 * java/doja mobile phones.
 * Copyright (C) 2008  Vincent Bouillet  http://www.vincentbouillet.com/
 * Based on the work of Paul Johnston    http://pajhome.org.uk/crypt/md5   
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
 */
 
package smartpass;
	
public class Sha1 {

	private boolean hexcase;  /* hex output format. false - lowercase; true - uppercase */
	private int chrsz;  		 /* bits per input character. 8 - ASCII; 16 - Unicode */
	
	public static final int BITSPERCHAR_8 = 8;
	public static final int BITSPERCHAR_16 = 16;

	public Sha1() {
		/*
		 * Configurable variables. You may need to tweak these to be compatible with
		 * the server-side, but the defaults work in most cases.
		 */
		setBitsPerChar(BITSPERCHAR_8);
		setUppercase(false);
	}

	/*
	 * These are the functions you'll usually want to call
	 * They take string arguments and return either raw strings hex encoded strings
	 */
	public String hex_sha1(String s){return binb2hex(core_sha1(str2binb(s),s.length() * chrsz));}
	public String str_sha1(String s){return binb2str(core_sha1(str2binb(s),s.length() * chrsz));}
	public String hex_hmac_sha1(String key, String data){ return binb2hex(core_hmac_sha1(key, data));}
	public String str_hmac_sha1(String key, String data){ return binb2str(core_hmac_sha1(key, data));}

	/*
	 * Perform a simple self-test to see if the VM is working
	 */
	public boolean sha1_vm_test()
	{
		String stest = "abc";
		String result = "a9993e364706816aba3e25717850c26c9cd0d89d";
		return hex_sha1(stest).equals((hexcase)?result.toUpperCase():result);
	}

	/*
	 * Calculate the SHA-1 of an array of big-endian words, and a bit length
	 */
	private int[] core_sha1(int[] y, int len)
	{
		/* allocation of a new, bigger array */
		int xlength = Math.max(y.length, ((len + 64 >> 9) << 4) + 15 + 1);
		int[] x = new int[xlength];
		for(int j = 0; j < y.length; j++) x[j] = y[j];

		/* append padding */
		x[len >> 5] |= 0x80 << (24 - len % 32);
		x[((len + 64 >> 9) << 4) + 15] = len;

		int[] w =new int[80];
		int a =  1732584193;
		int b = -271733879;
		int c = -1732584194;
		int d =  271733878;
		int e = -1009589776;

		for(int i = 0; i < x.length; i += 16)
		{
			int olda = a;
			int oldb = b;
			int oldc = c;
			int oldd = d;
			int olde = e;

			for(int j = 0; j < 80; j++)
			{
				if(j < 16) w[j] = x[i + j];
				else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
				int t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
						safe_add(safe_add(e, w[j]), sha1_kt(j)));
				e = d;
				d = c;
				c = rol(b, 30);
				b = a;
				a = t;
			}

			a = safe_add(a, olda);
			b = safe_add(b, oldb);
			c = safe_add(c, oldc);
			d = safe_add(d, oldd);
			e = safe_add(e, olde);
		}
		return new int[]{a, b, c, d, e};

	}

	/*
	 * Perform the appropriate triplet combination function for the current
	 * iteration
	 */
	private int sha1_ft(int t, int b, int c, int d)
	{
		if(t < 20) return (b & c) | ((~b) & d);
		if(t < 40) return b ^ c ^ d;
		if(t < 60) return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	}

	/*
	 * Determine the appropriate additive constant for the current iteration
	 */
	private int sha1_kt(int t)
	{
		return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
			(t < 60) ? -1894007588 : -899497514;
	}

	/*
	 * Calculate the HMAC-SHA1 of a key and some data
	 */
	private int[] core_hmac_sha1(String key, String data)
	{
		int[] bkey = new int[(((key.length()-1) * chrsz) >> 5 ) + 1];
		int[] bdata = new int[(((data.length()-1) * chrsz) >> 5 ) + 1];

		bkey = str2binb(key);
		bdata = str2binb(data);

		if(bkey.length > 16) bkey = core_sha1(bkey, key.length() * chrsz);

		int[] ipad = new int[16];
		int[] opad = new int[16];
		for(int i = 0; i < 16; i++)
		{
			ipad[i] = ((i >= bkey.length)? 0 : bkey[i]) ^ Integer.parseInt("36363636",16) ;
			opad[i] = ((i >= bkey.length)? 0 : bkey[i]) ^ Integer.parseInt("5C5C5C5C",16) ;
		}

		int[] hash = core_sha1(concat(ipad,bdata), 512 + data.length() * chrsz);  
		return core_sha1(concat(opad,hash), 512 + 160);
	}

	/*
	 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
	 * to work around bugs in some JS interpreters.
	 */
	private int safe_add(int x, int y)
	{
		int lsw = (x & 0xFFFF) + (y & 0xFFFF);
		int msw = (x >> 16) + (y >> 16) + (lsw >> 16);
		return (msw << 16) | (lsw & 0xFFFF);
	}

	/*
	 * Bitwise rotate a 32-bit number to the left.
	 */
	private int rol(int num, int cnt)
	{
		return (num << cnt) | (num >>> (32 - cnt));
	}

	/*
	 * Convert an 8-bit or 16-bit string to an array of big-endian words
	 * In 8-bit function, characters >255 have their hi-byte silently ignored.
	 */
	private int[] str2binb(String str)
	{
		int[] bin = new int[(((str.length()-1) * chrsz) >> 5 ) + 1];
		int mask = (1 << chrsz) - 1;
		for(int i = 0; i < str.length() * chrsz; i += chrsz)
			bin[i>>5] |= (str.charAt(i / chrsz) & mask) << (32 - chrsz - i%32);
		return bin;
	}

	/*
	 * Convert an array of big-endian words to a string
	 */
	private String binb2str(int[] bin)
	{
		String str = "";
		int mask = (1 << chrsz) - 1;
		for(int i = 0; i < bin.length * 32; i += chrsz)
			str = str + (char)((bin[i>>5] >>> (32 - chrsz - i%32)) & mask); 
		return str;
	}

	/*
	 * Convert an array of big-endian words to a hex string.
	 */
	private String binb2hex(int[] binarray)
	{
		String hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
		String str = "";
		for(int i = 0; i < binarray.length * 4; i++)
		{
			str = str + hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) + hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
		}
		return str;
	}

	/*
	 * Add arrays together.
	 */
	private int[] concat(int[] a, int[] b) {
		int[] r = new int[a.length + b.length];
		int i;
		for(i=0 ; i<a.length ; i++) r[i] = a[i];
		for(i=0 ; i<b.length ; i++) r[a.length+i] = b[i];
		return r;
	}


	public boolean isUppercase() {
		return hexcase;
	}


	public void setUppercase(boolean hexcase) {
		this.hexcase = hexcase;
	}


	public int getBitsPerChar() {
		return chrsz;
	}


	public void setBitsPerChar(int chrsz) {
		if(chrsz != BITSPERCHAR_8 && chrsz != BITSPERCHAR_16) {
			this.chrsz = BITSPERCHAR_8;
		}
		else this.chrsz = chrsz;
	}

}
