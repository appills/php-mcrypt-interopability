<?php

// number of test runs
define('RUNS', 1000);

for ($i = 0; $i < RUNS; $i++) {
	$test = new McryptCompatabilityTest();
	$test->run();
}

echo 'done';

/**
 * Class McryptCompatabilityTest
 * Note the exemption of the following mcrypt modes:
 *      ofb, stream
 *
 * mcrypt's OFB mode uses an 8-bit feedback block (same for CFB mode)
 * However, openssl does not support an 8-bit feedback block for OFB mode, only for CFB mode (see aes-128-cfb8)
 *
 * This class also excludes the following mcrypt ciphers:
 *      rijndael-192, rijndael-256
 * This is because they are not AES (see comment in class)
 */
class McryptInteropabilityTest
{
    /**
     * AES is a subset of the Rijndael ciphers
     * Rijndael came in 3 different block sizes:
     *      128, 192, and 256 bits
     * Each block size was compatible with three different key sizes:
     *      128, 192, and 256 bits
     * AES is rijndael with 128 bit blocks, and any of the three key sizes
     */
    const AES = 'rijndael-128';

    public function __construct()
    {
        // key is 16 bytes because openssl's aes-128 expects a 16-byte key
        $this->key = openssl_random_pseudo_bytes(16);
        // iv is the block size for AES
        $this->iv = openssl_random_pseudo_bytes(16);
    }
	
	public function run()
    {
        $data = $this->hexlify(openssl_random_pseudo_bytes(rand(1, 32)));
        $this->cbc($data);
        $this->cfb($data);
        $this->ctr($data);
        $this->ecb($data);
        $this->ncfb($data);
        $this->nofb($data);
    }

    /**
     * mcrypt: rijndael-128-cbc
     * openssl: aes-128-cbc
     */
    private function cbc($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'cbc', $this->iv);
        $openssl = openssl_decrypt($mcrypt, 'aes-128-cbc', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        return $this->compare($data, $openssl, 'cbc: ' . $openssl);
    }

    /**
     * mcrypt: rijndael-128-cfb
     * openssl: aes-128-cfb8
     */
    private function cfb($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'cfb', $this->iv);
        $openssl = openssl_decrypt($mcrypt, 'aes-128-cfb8', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        return $this->compare($data, $openssl, 'cfb:' . $openssl);
    }

    /**
     * mcrypt: rijndael-128-ctr
     * openssl: aes-128-ctr
     */
    private function ctr($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'ctr', $this->iv);
        $openssl = openssl_decrypt($mcrypt, 'aes-128-ctr', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        return $this->compare($data, $openssl, 'ctr:' . $openssl);
    }

    /**
     * mcrypt: rijndael-128-ecb
     * openssl: aes-128-ecb
     */
    private function ecb($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'ecb');
        $openssl = openssl_decrypt($mcrypt, 'aes-128-ecb', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        return $this->compare($data, $openssl, 'ecb:' . $openssl);
    }

    /**
     * mcrypt: rijndael-128-ncfb
     * openssl: aes-128-cfb
     */
    private function ncfb($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'ncfb', $this->iv);
        $openssl = openssl_decrypt($mcrypt, 'aes-128-cfb', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        return $this->compare($data, $openssl, 'ncfb:' . $openssl);
    }

    /**
     * mcrypt: rijndael-128-nofb
     * openssl: aes-128-ofb
     */
    private function nofb($data)
    {
        $mcrypt = mcrypt_encrypt(self::AES, $this->key, $data, 'nofb', $this->iv);
        $openssl = openssl_decrypt($mcrypt, 'aes-128-ofb', $this->key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $this->iv);
        return $this->compare($data, $openssl, 'nofb:' . $openssl);
    }

    private function compare($expected, $actual, $mcryptMode)
    {
        // all expected characters should be hex-encoded so we don't have to worry about 0x0 being valid plaintext
        $actual = rtrim($actual, chr(0));

        if ($expected === $actual) {
            return true;
        } else {
            throw new Exception($mcryptMode);
        }
    }

    private function hexlify($bytes)
    {
        $hex = unpack('H*', $bytes);
        return $hex[1];
    }
}
