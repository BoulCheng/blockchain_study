package com.cv4j.blockchain.study.wallet;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.math.BigInteger;

/**
 * Created by tony on 2018/3/12.
 */
public class GenerateBitcoinAddress {

    public static void main(String[] args) {

        /**
         * 1.通过OpenSSL命令随机生成密钥对
         *
         *
         * 生成椭圆曲线的私钥
         *
         * openssl ecparam -name secp256k1 -genkey -out ec-priv.pem
         * 执行上述命令会生成ec-prive.pem文件，将其快速解码为可读的16进制形式。
         *
         * openssl ec -in ec-priv.pem -text -noout
         * 将上述密钥对中的公钥部分取出，存储到一个叫做ec-pub.pem的外部文件中:
         *
         * openssl ec -in ec-priv.pem -pubout -out ec-pub.pem
         * 接着将它解码
         *
         * openssl ec -in ec-pub.pem -pubin -text -noout
         * 公钥部分就会显示出来
         *
         * read EC key
         * Private-Key: (256 bit)
         * pub:
         *     04:4d:d2:58:cc:3e:05:0b:57:02:99:ef:45:de:5d:
         *     96:e5:24:05:10:96:a2:a9:ae:52:d2:2b:a8:92:7b:
         *     16:7f:ce:f2:97:f3:5a:0d:e8:b7:c5:78:92:64:d2:
         *     de:85:8d:c8:58:2c:39:36:8c:39:9f:d9:1d:c5:a9:
         *     2c:33:d8:5a:a1
         * ASN1 OID: secp256k1
         */

        //提取上述16进制的公钥，转换成字符串 044dd258cc3e050b570299ef45de5d96e524051096a2a9ae52d22ba8927b167fcef297f35a0de8b7c5789264d2de858dc8582c39368c399fd91dc5a92c33d85aa1
        byte[] publicKey = new BigInteger("044dd258cc3e050b570299ef45de5d96e524051096a2a9ae52d22ba8927b167fcef297f35a0de8b7c5789264d2de858dc8582c39368c399fd91dc5a92c33d85aa1", 16).toByteArray();
        byte[] sha256Bytes = Utils.sha256(publicKey);
        System.out.println("sha256加密=" + Utils.bytesToHexString(sha256Bytes));

        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256Bytes, 0, sha256Bytes.length);
        byte[] ripemd160Bytes = new byte[digest.getDigestSize()];
        digest.doFinal(ripemd160Bytes, 0);

        System.out.println("ripemd160加密=" + Utils.bytesToHexString(ripemd160Bytes));

        byte[] networkID = new BigInteger("00", 16).toByteArray();
        byte[] extendedRipemd160Bytes = Utils.add(networkID, ripemd160Bytes);

        System.out.println("添加NetworkID=" + Utils.bytesToHexString(extendedRipemd160Bytes));

        byte[] twiceSha256Bytes = Utils.sha256(Utils.sha256(extendedRipemd160Bytes));

        System.out.println("两次sha256加密=" + Utils.bytesToHexString(twiceSha256Bytes));

        byte[] checksum = new byte[4];
        System.arraycopy(twiceSha256Bytes, 0, checksum, 0, 4);

        System.out.println("checksum=" + Utils.bytesToHexString(checksum));

        byte[] binaryBitcoinAddressBytes = Utils.add(extendedRipemd160Bytes, checksum);

        System.out.println("添加checksum之后=" + Utils.bytesToHexString(binaryBitcoinAddressBytes));

        String bitcoinAddress = Base58.encode(binaryBitcoinAddressBytes);
        System.out.println("bitcoinAddress=" + bitcoinAddress);
    }

}
