////////////////////////////////////////////////////////////////////////////
//	Copyright 2009 : Vladimir Novick    https://www.linkedin.com/in/vladimirnovick/  
//
//    NO WARRANTIES ARE EXTENDED. USE AT YOUR OWN RISK. 
//
// To contact the author with suggestions or comments, use  :vlad.novick@gmail.com
//
////////////////////////////////////////////////////////////////////////////
using System;

namespace Vlad2net.Crypto
{

    public class CryptoProvader
    {
        public CryptoProvader()
        {

        }

        private static byte[] StrToByteArray(string str)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            return encoding.GetBytes(str);
        }

        protected static  string ByteArrayToString(byte[] bytes,int count)
        {
            System.Text.UTF8Encoding encoding = new System.Text.UTF8Encoding();
            return encoding.GetString(bytes, 0, count);
        }


        public static string Decode(String str)
        {

            CryptoDecoder decoder = new CryptoDecoder();
            byte[] encoded = new byte[4096];
            byte[] original = HexEncoding.GetBytes(str);


            int encodedBytes = decoder.GetBytes(original, 0, original.Length, encoded, 0, true);
            return ByteArrayToString(encoded, encodedBytes);

        }


        public static string Encode(String str)
        {

            CryptoEncoder encoder = new CryptoEncoder(128, new byte[] { 46, 9 }, true );
            byte[] encoded = new byte[4096];
            byte[] original = StrToByteArray(str);

            int encodedBytes = encoder.GetBytes(original, 0, original.Length, encoded, 0, true);
            string pp = HexEncoding.ToString(encoded, 0, encodedBytes);
            return pp ; 

        }



    }
}
