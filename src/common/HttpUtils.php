<?php

namespace shophy\miniprogram\common;

use shophy\miniprogram\exception\HttpException;
use shophy\miniprogram\exception\NetWorkException;
use shophy\miniprogram\exception\InternalException;

class HttpUtils
{
	public static function MakeUrl($queryArgs)
	{
		$base = "https://api.weixin.qq.com";
		if (substr($queryArgs, 0, 1) === "/")
			return $base . $queryArgs;
		return $base . "/" . $queryArgs;
	}

	public static function Array2Json($arr)
	{
	    $parts = array ();
	    $is_list = false;
	    $keys = array_keys ( $arr );
	    $max_length = count ( $arr ) - 1;
	    if (isset($keys[0]) && ($keys [0] === 0) && ($keys [$max_length] === $max_length )) {
	        $is_list = true;
	        for($i = 0; $i < count ( $keys ); $i ++) {
	            if ($i != $keys [$i]) {
	                $is_list = false;
	                break;
	            }
	        }
	    }
	    foreach ( $arr as $key => $value ) {
	        if (is_array ( $value )) {
	            if ($is_list)
	                $parts [] = self::array2Json ( $value );
	            else
	                $parts [] = '"' . $key . '":' . self::array2Json ( $value );
	        } else {
	            $str = '';
	            if (! $is_list)
	                $str = '"' . $key . '":';
	            if (!is_string ( $value ) && is_numeric ( $value ) && $value<2000000000)
	                $str .= $value;
	            elseif ($value === false)
					$str .= 'false';
	            elseif ($value === true)
					$str .= 'true';
	            else
	                $str .= '"' .addcslashes($value, "\\\"\n\r\t/"). '"';
	            $parts[] = $str;
	        }
	    }
	    $json = implode ( ',', $parts );
	    if ($is_list)
	        return '[' . $json . ']';
	    return '{' . $json . '}';
	}

	/**
	 * http get
	 * @param string $url
	 * @return http response body
	 */
	public static function httpGet($url)
	{
		self::__checkDeps();
        $ch = curl_init();

		self::__setSSLOpts($ch, $url);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

        return self::__exec($ch);
	}

	/**
	 * http post
	 * @param string $url
	 * @param string or dict $postData
	 * @return http response body
	 */
	public static function httpPost($url, $postData)
	{
		self::__checkDeps();
		$ch = curl_init();

		self::__setSSLOpts($ch, $url);

		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
		
		return self::__exec($ch);
	}

	// 
	// private:
	// 

	static private function __setSSLOpts($ch, $url)
	{
		if (stripos($url,"https://") !== false) {
	        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
	        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	        curl_setopt($ch, CURLOPT_SSLVERSION, 1);
	    }
	}

	static private function __exec($ch)
	{
		$output = curl_exec($ch);
		$status = curl_getinfo($ch);
		curl_close($ch);

		if ($output === false) {
			throw new NetWorkException("network error");
		}
		
	    if (intval($status["http_code"]) != 200) {
			throw new HttpException(
				"unexpected http code ". intval($status["http_code"]));
	    }

		return $output;
	}

	static private function __checkDeps()
	{
		if (!function_exists("curl_init")) {
			throw new InternalException("missing curl extend");
		}
	}
}
