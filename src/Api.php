<?php

namespace shophy\miniprogram;

use shophy\miniprogram\common\Utils;

class Api
{
    const BASE_URL = 'https://api.weixin.qq.com';

    const JSCODETOSESSION = '/sns/jscode2session?'; // 登录凭证校验
    
    public $errCode = 40001;
    public $errMsg = "no access";
    
    protected $appid = null;
    protected $secret = null;
    protected $accessToken = null;

	public function __construct($appid, $secret)
	{
        Utils::checkNotEmptyStr($appid, 'appid');
        Utils::checkNotEmptyStr($secret, 'secret');

        $this->appid = $appid;
        $this->secret = $secret;
    }

    public function getSessionByCode($code)
    {
        Utils::checkNotEmptyStr($code, 'code');
        
	    $result = $this->http_get(self::BASE_URL.self::JSCODETOSESSION.'appid='.$this->appid.'&secret='.$this->secret.'&js_code='.$code.'&grant_type=authorization_code');
	    if ($result) {
	        $json = json_decode($result, true);
	        if (!$json)	return false;
			if (isset($json['errcode']) && intval($json['errcode']) !== 0) {
				$this->errCode = $json['errcode'];
	            $this->errMsg = $json['errmsg'];
	            return false;
			}
            
	        return $json;
        }
        
	    return false;
    }
    
    /**
	 * GET 请求
	 * @param string $url
	 */
	private function http_get($url, &$http_info=null){
		$oCurl = curl_init();
		if(stripos($url,"https://")!==FALSE){
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, FALSE);
			curl_setopt($oCurl, CURLOPT_SSLVERSION, 1); //CURL_SSLVERSION_TLSv1
		}
		curl_setopt($oCurl, CURLOPT_URL, $url);
		curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1 );
		$sContent = curl_exec($oCurl);
		$http_info = curl_getinfo($oCurl);
		curl_close($oCurl);
		if(intval($http_info["http_code"])==200){
			return $sContent;
		}else{
			return false;
		}
	}

	/**
	 * POST 请求
	 * @param string $url
	 * @param array $param
	 * @param boolean $post_file 是否文件上传
	 * @return string content
	 */
	private function http_post($url,$param,$post_file=false){
		$oCurl = curl_init();
		if(stripos($url,"https://")!==FALSE){
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYPEER, FALSE);
			curl_setopt($oCurl, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt($oCurl, CURLOPT_SSLVERSION, 1); //CURL_SSLVERSION_TLSv1
		}
	        if (PHP_VERSION_ID >= 50500 && class_exists('\CURLFile')) {
	            	$is_curlFile = true;
	        } else {
	        	$is_curlFile = false;
	            	if (defined('CURLOPT_SAFE_UPLOAD')) {
	                	curl_setopt($oCurl, CURLOPT_SAFE_UPLOAD, false);
	            	}
	        }
		if (is_string($param)) {
	            	$strPOST = $param;
	        }elseif($post_file) {
	            	if($is_curlFile) {
		                foreach ($param as $key => $val) {
		                    	if (substr($val, 0, 1) == '@') {
		                        	$param[$key] = new \CURLFile(realpath(substr($val,1)));
		                    	}
		                }
	            	}
			$strPOST = $param;
		} else {
			$aPOST = array();
			foreach($param as $key=>$val){
				$aPOST[] = $key."=".urlencode($val);
			}
			$strPOST =  join("&", $aPOST);
		}
		curl_setopt($oCurl, CURLOPT_URL, $url);
		curl_setopt($oCurl, CURLOPT_RETURNTRANSFER, 1 );
		curl_setopt($oCurl, CURLOPT_POST,true);
		curl_setopt($oCurl, CURLOPT_POSTFIELDS,$strPOST);
		$sContent = curl_exec($oCurl);
		$aStatus = curl_getinfo($oCurl);
		curl_close($oCurl);
		if(intval($aStatus["http_code"])==200){
			return $sContent;
		}else{
			return false;
		}
	}

	/**
	 * 设置缓存，按需重载
	 * @param string $cachename
	 * @param mixed $value
	 * @param int $expired
	 * @return boolean
	 */
	protected function setCache($cachename,$value,$expired){
		//TODO: set cache implementation
		//return Yii::$app->cache->set($cachename, $value, $expired);
	}

	/**
	 * 获取缓存，按需重载
	 * @param string $cachename
	 * @return mixed
	 */
	protected function getCache($cachename){
		//TODO: get cache implementation
		//return Yii::$app->cache->get($cachename);
	}

	/**
	 * 清除缓存，按需重载
	 * @param string $cachename
	 * @return boolean
	 */
	protected function removeCache($cachename){
		//TODO: remove cache implementation
		//return Yii::$app->cache->delete($cachename);;
	}
}
