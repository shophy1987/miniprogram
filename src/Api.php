<?php

namespace shophy\miniprogram;

use shophy\miniprogram\common\Utils;
use shophy\miniprogram\common\HttpUtils;
use shophy\miniprogram\exception\ApiException;
use shophy\miniprogram\exception\InternalException;
use shophy\miniprogram\exception\ParameterException;

class Api
{
	const GET_ACCESSTOKEN = '/cgi-bin/token'; // 接口调用凭证
	const JSCODETOSESSION = '/sns/jscode2session'; // 登录凭证校验
	const MESSAGE_SUBSCRIBE_SEND = '/cgi-bin/message/subscribe/send?access_token=ACCESS_TOKEN'; // 发送订阅消息
	
	public $rspJson = null;
	public $rspRawStr = null;
	
    protected $appid = null;
	protected $secret = null;
	protected $sessionKey = null;
    protected $accessToken = null;

	public function __construct($appid, $secret)
	{
        Utils::checkNotEmptyStr($appid, 'appid');
        Utils::checkNotEmptyStr($secret, 'secret');

        $this->appid = $appid;
        $this->secret = $secret;
	}

	/**
	 * 登录
	 */
    public function getSessionByCode($code)
    {
		Utils::checkNotEmptyStr($code, 'code');
        self::_HttpCall(self::JSCODETOSESSION, 'GET', array('appid' => $this->appid, 'secret' => $this->secret, 'js_code' => $code, 'grant_type' => 'authorization_code'));
        
        isset($this->rspJson['session_key']) && $this->setCache($this->appid.'-sessionKey', $this->rspJson['session_key']);
	}

	/**
     * 发送订阅消息
     * @param $toUser 接收者（用户）的 openid
     * @param $templateId 模板id
     * @param $data
     * @return throw exception
     */
	public function subscribeMessage($toUser, $templateId, $data, $page='')
	{
		$params = array(
            'touser' => $toUser,
            'template_id' => $templateId,
			'data' => $data
		);
		empty($page) || $params['page'] = $page;
		self::_HttpCall(self::MESSAGE_SUBSCRIBE_SEND, 'POST', $params);
    }

	/**
     * @brief getAccessToken : 获取 accesstoken，不用主动调用
     *
     * @return : string accessToken
     */
    public function getAccessToken()
    {
        if ( ! Utils::notEmptyStr($this->accessToken)) { 
            $this->refreshAccessToken();
        } 
        return $this->accessToken;
    }

    protected function refreshAccessToken($bflush=false)
    {
        if (!Utils::notEmptyStr($this->appid) || !Utils::notEmptyStr($this->secret))
            throw new ParameterException("invalid appid or secret");

        // 尝试从缓存读取,corpid 作为key
        $this->accessToken = $bflush ? '' : $this->getCache($this->appid);
        if( ! Utils::notEmptyStr($this->accessToken)) {
			$url = self::BASE_URL.self::GET_ACCESSTOKEN."?grant_type=client_credential&appid={$this->appid}&secret={$this->secret}";
            $this->_HttpGetParseToJson($url, false);
            $this->_CheckErrCode();
    
            // 写入缓存
			$this->accessToken = $this->rspJson["access_token"];
			$this->setCache($this->appid, $this->accessToken, $this->rspJson['expires_in']);
        }
    }
    
    public function getSessionKey()
    {
        if ( ! Utils::notEmptyStr($this->sessionKey)) { 
            $this->sessionKey = $this->getCache($this->appid.'-sessionKey');
        }
    }
	
	/**
     * 检验数据的真实性，并且获取解密后的明文
     * @param $encryptedData string 加密的用户数据
     * @param $iv string 与用户数据一同返回的初始向量
     * @param $data string 解密后的原文
     *
     * @return int 成功0，失败返回对应的错误信息
     */
    public function decryptData($encryptedData, $iv, &$data )
    {
        $this->getSessionKey();
		if (!Utils::notEmptyStr($this->sessionKey) || strlen($this->sessionKey) != 24) {
			throw new ParameterException("invalid sessionKey");
		}
		if (!Utils::notEmptyStr($iv) || strlen($iv) != 24) {
			throw new ParameterException("invalid iv");
		}

		$aesIV = base64_decode($iv);
		$aesKey = base64_decode($this->sessionKey);
		$aesCipher = base64_decode($encryptedData);

		$result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);
		$dataObj = json_decode( $result );
		if( $dataObj  == NULL )
		{
			throw new InternalException("decrypt failed");
		}
		if( $dataObj->watermark->appid != $this->appid )
		{
			throw new InternalException("invalid decrypt data");
		}

		$data = $result;
    }
	
	/**
	 * 设置缓存，按需重载
	 * @param string $cachename
	 * @param mixed $value
	 * @param int $expired
	 * @return boolean
	 */
	protected function setCache($cachename,$value,$expired=null){
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
    
    protected function _HttpCall($url, $method, $args)
    {
        if ('POST' == $method) { 
            $url = HttpUtils::MakeUrl($url);
            $this->_HttpPostParseToJson($url, $args);
            $this->_CheckErrCode();
        } else if ('GET' == $method) { 
            if (is_array($args) && count($args) > 0) { 
                foreach ($args as $key => $value) {
                    if ($value == null) continue;
                    if (strpos($url, '?')) {
                        $url .= ('&'.$key.'='.$value);
                    } else { 
                        $url .= ('?'.$key.'='.$value);
                    }
                }
            }
            $url = HttpUtils::MakeUrl($url);
            $this->_HttpGetParseToJson($url);
            $this->_CheckErrCode();
        } else { 
            throw new ApiException('wrong method');
        }
    }

    protected function _HttpGetParseToJson($url, $refreshTokenWhenExpired=true)
    {
        $retryCnt = 0;
        $this->rspJson = null;
        $this->rspRawStr = null;

        while ($retryCnt < 2) {
            $tokenType = null;
            $realUrl = $url;

            if (strpos($url, "ACCESS_TOKEN")) {
                $token = $this->getAccessToken();
                $realUrl = str_replace("ACCESS_TOKEN", $token, $url);
                $tokenType = "ACCESS_TOKEN";
            } else { 
                $tokenType = "NO_TOKEN";
            }

            $this->rspRawStr = HttpUtils::httpGet($realUrl);

            if ( ! Utils::notEmptyStr($this->rspRawStr)) throw new ApiException("empty response"); 
			
			$this->rspJson = json_decode($this->rspRawStr, true/*to array*/);
            if (strpos($this->rspRawStr, "errcode") !== false) {
                $errCode = Utils::arrayGet($this->rspJson, "errcode");
                if ($errCode == 40014 || $errCode == 41001 || $errCode == 42001) { // token expired
                    if ("NO_TOKEN" != $tokenType && true == $refreshTokenWhenExpired) {
                        if ("ACCESS_TOKEN" == $tokenType) { 
                            $this->refreshAccessToken(true);
                        }
                        $retryCnt += 1;
                        continue;
                    }
                }
            }
            return $this->rspRawStr;
        }
    }

    protected function _HttpPostParseToJson($url, $args, $refreshTokenWhenExpired=true, $isPostFile=false)
    {
        $postData = $args;
        if (!$isPostFile) {
            if (!is_string($args)) {
                $postData = HttpUtils::Array2Json($args);
            }
        }
        $this->rspJson = null; $this->rspRawStr = null;

        $retryCnt = 0;
        while ($retryCnt < 2) {
            $tokenType = null;
            $realUrl = $url;

    		if (strpos($url, "ACCESS_TOKEN")) {
                $token = $this->getAccessToken();
                $realUrl = str_replace("ACCESS_TOKEN", $token, $url);
                $tokenType = "ACCESS_TOKEN";
            } else { 
                $tokenType = "NO_TOKEN";
            }

            $this->rspRawStr = HttpUtils::httpPost($realUrl, $postData);

            if ( ! Utils::notEmptyStr($this->rspRawStr)) throw new ApiException("empty response"); 

            $json = json_decode($this->rspRawStr, true/*to array*/);
            $this->rspJson = $json;

            $errCode = Utils::arrayGet($this->rspJson, "errcode");
            if ($errCode == 40014 || $errCode == 41001 || $errCode == 42001) { // token expired
                if ("NO_TOKEN" != $tokenType && true == $refreshTokenWhenExpired) {
                    if ("ACCESS_TOKEN" == $tokenType) { 
                        $this->refreshAccessToken(true);
                    }
                    $retryCnt += 1;
                    continue;
                }
            }

            return $json;
        }
    } 

    protected function _CheckErrCode()
    {
        $rsp = $this->rspJson;
        $raw = $this->rspRawStr;
        if (is_null($rsp))
            return;

        if (!is_array($rsp))
            throw new ParameterException("invalid type " . gettype($rsp));
        if (!array_key_exists("errcode", $rsp)) {
            return;
        }
        $errCode = $rsp["errcode"];
        if (!is_int($errCode))
            throw new ApiException("invalid errcode type " . gettype($errCode) . ":" . $raw);
        if ($errCode != 0)
            throw new ApiException("response error:" . $raw);
    }
}
