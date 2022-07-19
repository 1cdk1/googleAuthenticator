<?php

namespace GoogleAuthenticator;

/**
 * class Main
 */
class Main
{

    protected $codeLength = 6;

    /**
     * 创建新的秘钥
     *
     * @param int $secretLength 秘钥长度
     *
     * @return string
     * @throws \Exception
     */
    public function createSecret($secretLength = 16)
    {
        $validChars = $this->_getBase32Array();

        if ($secretLength < 16 || $secretLength > 128) {
            return false;
        }
        $secret = '';
        $random = false;
        if (function_exists('random_bytes')) {
            $random = random_bytes($secretLength);
        } elseif (function_exists('mcrypt_create_iv')) {
            $random = mcrypt_create_iv($secretLength, MCRYPT_DEV_URANDOM);
        } elseif (function_exists('openssl_random_pseudo_bytes')) {
            $random = openssl_random_pseudo_bytes($secretLength, $cryptoStrong);
            if (!$cryptoStrong) {
                $random = false;
            }
        }
        if ($random !== false) {
            for ($i = 0; $i < $secretLength; ++$i) {
                $secret .= $validChars[ord($random[$i]) & 31];
            }
        } else {
            return false;
        }

        return $secret;
    }

    /**
     * 使用给定的秘钥和时间计算出6位数字密码。
     *
     * @param string   $secret
     * @param int|null $timeSlice
     *
     * @return string
     */
    public function getCode($secret, $timeSlice = null)
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }

        $secretKey = $this->_base32Decode($secret);

        // 将时间打包为二进制字符串
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // 用户密钥散列
        $hm = hash_hmac('SHA1', $time, $secretKey, true);
        // 使用结果的最后一个作为索引/偏移
        $offset = ord(substr($hm, -1)) & 0x0F;
        // 抓取结果的4个字节
        $hashPart = substr($hm, $offset, 4);

        // 解包二进制值
        $value = unpack('N', $hashPart);
        $value = $value[1];
        // 32位
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->codeLength);

        return str_pad($value % $modulo, $this->codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * 通过谷歌获取二维码
     *
     * @param string $name
     * @param string $secret
     * @param string $title
     * @param array  $params
     *
     * @return string
     */
    public function getQRCodeGoogleUrl($name, $secret, $title = null, $params = array())
    {
        $width = !empty($params['width']) && (int)$params['width'] > 0 ? (int)$params['width'] : 200;
        $height = !empty($params['height']) && (int)$params['height'] > 0 ? (int)$params['height'] : 200;
        $level = !empty($params['level']) && in_array($params['level'], ['L', 'M', 'Q', 'H']) ? $params['level'] : 'M';

        $urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $secret . '');
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer=' . urlencode($title));
        }

        return "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size=${width}x${height}&ecc=$level";
    }

    /**
     * 验证密码是否正确。
     *
     * @param string   $secret
     * @param string   $code
     * @param int      $discrepancy      这是以30秒为单位的允许时间偏移（比如2为前后1分钟）
     * @param int|null $currentTimeSlice 当前参与计算的时间
     *
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1, $currentTimeSlice = null)
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = floor(time() / 30);
        }

        if (strlen($code) != 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 设置密码长度，应大于等于6
     *
     * @param int $length
     *
     */
    public function setCodeLength($length)
    {
        $this->codeLength = $length;

        return $this;
    }

    /**
     * 用于解码base32的Helper类
     *
     * @param $secret
     *
     * @return bool|string
     */
    protected function _base32Decode($secret)
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->_getBase32Array();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount == $allowedValues[$i]
                && substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])
            ) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], $base32chars)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); ++$z) {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * 获取包含所有32个字符的数组，用于解码/编码到base32。
     *
     * @return array
     */
    protected function _getBase32Array()
    {
        return ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                'Z', '2', '3', '4', '5', '6', '7', '='];
    }

    /**
     * 安全时间对比
     *
     * @param string $safeString 要检查的内部（安全）值
     * @param string $userString 用户提交的（不安全）值
     *
     * @return bool 如果两个字符串相同，则为True
     */
    private function timingSafeEquals($safeString, $userString)
    {
        if (function_exists('hash_equals')) {
            return hash_equals($safeString, $userString);
        }
        $safeLen = strlen($safeString);
        $userLen = strlen($userString);

        if ($userLen != $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (ord($safeString[$i]) ^ ord($userString[$i]));
        }

        return $result === 0;
    }

}