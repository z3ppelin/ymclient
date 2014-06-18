<?php
/**
 * Unit test for \bogcon\ymclient\Engine class.
 * 
 * @author      Bogdan Constantinescu <bog_con@yahoo.com>
 * @link        GitHub  https://github.com/z3ppelin/ymclient.git
 * @licence     The BSD License (http://opensource.org/licenses/BSD-3-Clause); see LICENSE.txt
 */
namespace bogcon\ymclient\tests;
use bogcon\ymclient\Engine;

/**
 * @covers \bogcon\ymclient\Engine
 */
class EngineTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test username.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param username. Must be a string.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamUsername1()
    {
        $objYM = new Engine(array(), '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param username. Must contain at most one @.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamUsername2()
    {
        $objYM = new Engine('john@doe@yahoo.com', '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param username. ID must match [a-z0-9_.+] and must have at most 32 chars.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamUsername3()
    {
        $strName = '';
        for ($intI = 0; $intI < 33; $intI++) {
            $strName .= 'a';
        }
        $objYM = new Engine($strName, '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param username. ID must match [a-z0-9_.+] and must have at most 32 chars.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamUsername4()
    {
        $objYM = new Engine('#johndoe', '', '', '');
    }
    
    
    
    /**
     * Test username.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param username. DNS must match [a-z0-9_.+] and must have at most 64 chars.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamUsername5()
    {
        $strDns = '';
        for ($intI = 0; $intI < 62; $intI++) {
            $strDns .= 'a';
        }
        $objYM = new Engine('johndoe@' . $strDns . '.com', '', '', '');
    }
    
    
    
    /**
     * Test password.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param password.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamPassword1()
    {
        $objYM = new Engine('johndoe', array(), '', '');
    }
    
    
    
    /**
     * Test password.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param password.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamPassword2()
    {
        $strPwd = '';
        for ($intI = 0; $intI < 33; $intI++) {
            $strPwd .= 'a';
        }
        $objYM = new Engine('johndoe', $strPwd, '', '');
    }
    
    
    
    /**
     * Test app key param.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param app key.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamAppKey1()
    {
        $objYM = new Engine('johndoe', 'pass123', array(), '');
    }
    
    
    
    /**
     * Test app key param.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param app key.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamAppKey2()
    {
        $objYM = new Engine('johndoe', 'pass123', '', '');
    }
    
    
    
    /**
     * Test app secret param.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param app secret.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamAppSecret1()
    {
        $objYM = new Engine('johndoe', 'pass123', 'appKey', array());
    }
    
    
    
    /**
     * Test app secret param.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage    Invalid param app secret.
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorParamAppSecret2()
    {
        $objYM = new Engine('johndoe', 'pass123', 'appKey', '');
    }
    
    
    
    /**
     * @requires extension curl
     * @covers \bogcon\ymclient\Engine::__construct
     */
    public function testConstructorCurl()
    {
        $objYM = new Engine('johndoe', 'abcdefgppppp', 'testAppKey', 'testAppSecret');
    }
    
    
    
    /**
     * Test everything goes ok with some valid params, test default values.
     * @covers \bogcon\ymclient\Engine::__construct
     * @covers \bogcon\ymclient\Engine::hasAccessToken
     * @covers \bogcon\ymclient\Engine::hasRequestToken
     * @covers \bogcon\ymclient\Engine::hasSession
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testConstructor()
    {
        $objYM = new Engine('johndoe', 'abcdefgppppp', 'testAppKey', 'testAppSecret');
        $this->assertFalse($objYM->hasRequestToken());
        $this->assertFalse($objYM->hasAccessToken());
        $this->assertFalse($objYM->hasSession());
        $this->assertFalse($objYM->isTokenRenewed());
    }
    
    
    
    /**
     * Test setter/getter method for tokens.
     * @covers \bogcon\ymclient\Engine::setTokens
     * @covers \bogcon\ymclient\Engine::getTokens
     * @covers \bogcon\ymclient\Engine::hasAccessToken
     * @covers \bogcon\ymclient\Engine::hasRequestToken
     */
    public function testSetGetHasTokens()
    {
        $arrTokens = array(
            'request' => 'someTestRequestToken',
            'access' => array(
                'oauth_token' => 'sometestOAuthToken',
                'oauth_token_secret' => 'someTestOAuthTokenSecret',
                'oauth_expires_in' => '3600',
                'oauth_session_handle' => 'someTestOAuthSessionHandle',
                'oauth_authorization_expires_in' => '770477963',
                'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
            ),
        );
        $objYM = new Engine('das1sdas', 'dasda123sdas', 'appKey', 'appSecret');
        $this->assertSame(array(), $objYM->getTokens());
        $objYM->setTokens($arrTokens);
        $this->assertSame($arrTokens, $objYM->getTokens());
        $this->assertTrue($objYM->hasAccessToken());
        $this->assertTrue($objYM->hasRequestToken());
        
        $objYM->setTokens(array());
        $this->assertFalse($objYM->hasAccessToken());
        $this->assertFalse($objYM->hasRequestToken());
    }
    
    
    
    /**
     * Test setter/getter method for session.
     * @covers \bogcon\ymclient\Engine::setSession
     * @covers \bogcon\ymclient\Engine::getSession
     * @covers \bogcon\ymclient\Engine::hasSession
     */
    public function testSetGetHasSession()
    {
        $arrSession = array(
            'sessionId' => 'someTestSessionId',
            'primaryLoginId' => 'someLoginId',
            'displayInfo' => array(
                'avatarPreference' => 0,
            ),
            'server' => 'rcore3.messenger.yahooapis.com',
            'notifyServer' => 'rproxy3.messenger.yahooapis.com',
            'constants' => array(
                'presenceSubscriptionsMaxPerRequest' => 500,
            ),
        );

        $objYM = new Engine('das1sdas', 'dasda123sdas', 'appKey', 'appSecret');
        $this->assertSame(array(), $objYM->getSession());
        
        $objYM->setSession($arrSession);
        $this->assertSame($arrSession, $objYM->getSession());
        $this->assertTrue($objYM->hasSession());
        
        $objYM->setSession(array());
        $this->assertFalse($objYM->hasSession());
    }
    
    
    
    /**
     * Test setter/getter method for renewed token flag.
     * @covers \bogcon\ymclient\Engine::setTokenRenewed
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testSetIsTokenRenewed()
    {
        $objYM = new Engine('vxc123ads', 'das_+DAS', 'appKey', 'appSecret');
        $this->assertFalse($objYM->isTokenRenewed());
        $objYM->setTokenRenewed(true);
        $this->assertTrue($objYM->isTokenRenewed());
        $objYM->setTokenRenewed(false);
        $this->assertFalse(false, $objYM->isTokenRenewed());
        $objYM->setTokenRenewed(0);
        $this->assertFalse($objYM->isTokenRenewed());
        $objYM->setTokenRenewed('trueeee');
        $this->assertTrue($objYM->isTokenRenewed());
    }
    
    
    
    /**
     * Test exception is thrown when request token is not received from api call.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::getRequestToken
     * @covers \bogcon\ymclient\Engine::hasRequestToken
     */
    public function testGetRequestTokenIsThrowingException()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaaaaa'));
        $objStub->getRequestToken();
    }
    
    
    
    /**
     * Test method works properly.
     * @covers \bogcon\ymclient\Engine::getRequestToken
     * @covers \bogcon\ymclient\Engine::hasRequestToken
     */
    public function testGetRequestTokenWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once()) // first time make api call
                ->method('makeApiCall')
                ->will($this->returnValue('RequestToken=cadscas1231234wre'));
        $this->assertEquals('cadscas1231234wre', $objStub->getRequestToken());
        $this->assertTrue($objStub->hasRequestToken());
        
        $objStub->expects($this->never()) // second time retrieve directly
                ->method('makeApiCall');
        $this->assertEquals('cadscas1231234wre', $objStub->getRequestToken());
        
        $objStub->setTokens(array('request' => 'testRequestToken'));
        $objStub->expects($this->never()) // test no api call is made after request is set manually
                ->method('makeApiCall');
        $this->assertEquals('testRequestToken', $objStub->getRequestToken());
    }
    
    
    
    /**
     * Test exception is thrown when access token is not received from api call.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::getAccessToken
     */
    public function testGetAccessTokenIsThrowingExceptionWhenNoAccessTokenIsReceived()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaaaaa'));
        $objStub->setTokens(array('request' => 'testRequestToken'))
                ->getAccessToken();
    }
    
    
    
    /**
     * Test method is working properly when access token is received from api call.
     * @covers \bogcon\ymclient\Engine::getAccessToken
     * @covers \bogcon\ymclient\Engine::hasAccessToken
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testGetAccessTokenWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once()) // first time fetch access token from Yahoo API
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->setTokens(array('request' => 'testRequestToken'));
        $accessToken = $objStub->getAccessToken();
        $this->assertNotEmpty($accessToken);
        $this->assertTrue($objStub->hasAccessToken());
        $this->assertTrue($objStub->isTokenRenewed()); // first call to isTokenRenewed should return true
        
        $objStub->expects($this->never()) // second time fetch internal
                ->method('makeApiCall');
        $this->assertSame($accessToken, $objStub->getAccessToken());
        $this->assertFalse($objStub->isTokenRenewed()); // second call to isTokenRenewed should return false
    }
    
    
    
    /**
     * Test method is working properly when access token is received from api call and also request token was not previously set.
     * @covers \bogcon\ymclient\Engine::getAccessToken
     * @covers \bogcon\ymclient\Engine::hasAccessToken
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testGetAccessTokenWorksFine2()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->at(0)) // fetch request token call
                ->method('makeApiCall')
                ->will($this->returnValue('RequestToken=cadscas1231234wre'));
        $objStub->expects($this->at(1)) // fetch access token from Yahoo API
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        
        $accessToken = $objStub->getAccessToken();
        $this->assertNotEmpty($accessToken);
        $this->assertTrue($objStub->hasAccessToken());
        $this->assertTrue($objStub->isTokenRenewed()); // first call to isTokenRenewed should return true
        
        $objStub->expects($this->never()) // fetch access token internal
                ->method('makeApiCall');
        $this->assertSame($accessToken, $objStub->getAccessToken());
        $this->assertFalse($objStub->isTokenRenewed()); // second call to isTokenRenewed should return false
    }
    
    
    
    /**
     * Test access token renewal is throwing exception when no renewed access token is received from api call.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::getAccessToken
     */
    public function testGetAccessTokenForcedIsThrowingExceptionWhenNoNewAccessTokenIsReceived()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('dasdasdas'));
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477963',
                    'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
                ),
            )
        );
        
        try {
            $objStub->getAccessToken(true);
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === mb_strpos($objEx->getMessage(), 'Could not fetch access token. Api response:')) {
                $this->fail('Not the expected exception. Received instead: ' . $objEx->getMessage());
            }
            throw $objEx;
        }
    }
    
    
    
    /**
     * Test access token renewal is working fine.
     * @covers \bogcon\ymclient\Engine::getAccessToken
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     * @covers \bogcon\ymclient\Engine::hasAccessToken
     * @covers \bogcon\ymclient\Engine::hasRequestToken
     */
    public function testGetAccessTokenForcedWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477970&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477963',
                    'xoauth_yahoo_guid' => 'someTestXOAuthYahooGuid'
                ),
            )
        )->getAccessToken(true);
        
        $this->assertTrue($objStub->isTokenRenewed());
        $this->assertSame(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'testOAuthToken',
                    'oauth_token_secret' => 'testOAuthTokenSecret',
                    'oauth_expires_in' => '3600',
                    'oauth_session_handle' => 'testOAuthSessionHandle',
                    'oauth_authorization_expires_in' => '770477970',
                    'xoauth_yahoo_guid' => 'testXOAuthYahooGuid'
                ),
            ),
            $objStub->getTokens()
        );
        $this->assertTrue($objStub->hasAccessToken());
        $this->assertTrue($objStub->hasRequestToken());
        
        // test second call to getAccessToken() fetch internal, not from API
        $objStub->expects($this->never())
                ->method('makeApiCall');
        $this->assertSame(array(
            'oauth_token' => 'testOAuthToken',
            'oauth_token_secret' => 'testOAuthTokenSecret',
            'oauth_expires_in' => '3600',
            'oauth_session_handle' => 'testOAuthSessionHandle',
            'oauth_authorization_expires_in' => '770477970',
            'xoauth_yahoo_guid' => 'testXOAuthYahooGuid'
            
        ), $objStub->getAccessToken());
        $this->assertFalse($objStub->isTokenRenewed()); // was renewed(taken from api) last call, now it is returned from internal field.
    }
    
    
    
    /**
     * Test login fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::logIn
     */
    public function testLogInThrowsExceptionWhenHttpStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will($this->returnValue('aaaa'));
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
    }
    
    
    
    /**
     * Test login fails when the response retreived from curl call is not valid json.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::logIn
     */
    public function testLogInFailsWhenResponseIsNotValidJson()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'aaaa';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn(100000, 'I am very busy'); // invalid status, should set the default one + status message
    }
    
    
    
    /**
     * Test login works ok.
     * @covers \bogcon\ymclient\Engine::logIn
     * @covers \bogcon\ymclient\Engine::getHeadersForCurlCall
     * @covers bogcon\ymclient\Engine::getAuthorizationHeader
     */
    public function testLogInWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $arrSession = array(
            'sessionId' => 'someTestSessionId',
            'primaryLoginId' => 'someLoginId',
            'displayInfo' => array(
                'avatarPreference' => '0',
            ),
            'server' => 'rcore3.messenger.yahooapis.com',
            'notifyServer' => 'rproxy3.messenger.yahooapis.com',
            'constants' => array(
                'presenceSubscriptionsMaxPerRequest' => 500,
            ),
        );
        $objStub->expects($this->once())
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'displayInfo' => array(
                                        'avatarPreference' => '0',
                                    ),
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                    'notifyServer' => 'rproxy3.messenger.yahooapis.com',
                                    'constants' => array(
                                        'presenceSubscriptionsMaxPerRequest' => 500,
                                    ),
                                )
                            );
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $this->assertSame($arrSession, $objStub->getSession());
    }
    
    
    
    /**
     * Test logout works fine if previously not logged in; just do nothing
     * @covers \bogcon\ymclient\Engine::logOut
     */
    public function testLogOutWorksFineIfNotLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->never())
                ->method('makeApiCall')
                ->will($this->returnValue('dasdas'));
        $objStub->logOut();
    }
    
    
    
    /**
     * Test logout fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage logout
     * @covers \bogcon\ymclient\Engine::logOut
     */
    public function testLogOutFailsWhenHttpStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $objStub->expects($this->at(0)) // login call
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(                 
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 302;
                            return '';
                        }
                    )
                );          
                    
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        try {
            $objStub->logOut();
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Could not log out. Api response')) {
                $this->fail('Exception should have been thrown.');
            }
            throw new \bogcon\ymclient\Exception('logout');
        }
    }
    
    
    
    /**
     * Test logout works fine if previously logged in.
     * @covers \bogcon\ymclient\Engine::logOut
     */
    public function testLogOutWorksFineIfLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->logOut();
    }
    
    
    
    /**
     * Test logout works fine if token expired.
     * @covers \bogcon\ymclient\Engine::logOut
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testLogOutWorksFineIfLoggedInAndTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for logout to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for logout to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for logout to successfully logout
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->logOut();
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test headers from HTTP response are parsed well.
     * @covers \bogcon\ymclient\Engine::getHeadersFromCurlResponse
     */
    public function testGetHeadersFromCurlResponse()
    {
        $objYM = new Engine('johndoe', 'abcdefgppppp', 'appKey', 'appSecret');
        
        $class = new \ReflectionClass($objYM); // method is protected, use reflection to make it accessible
        $method = $class->getMethod('getHeadersFromCurlResponse');
        $method->setAccessible(true);
        
        $arrWithHeaders = array(
            'http_code' => 'HTTP/1.1 200 OK',
            'date' => 'Wed, 04 Sep 2013 08:48:31 GMT',
            'p3p' => 'policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"',
            'cache-control' => 'public,must-revalidate',
            'x-yahoo-msgr-imageurl' => 'http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ',
            'connection' => 'close',
            'content-type' => '',
        );
        
        $this->assertSame(
            $method->invokeArgs(
                $objYM,
                array(
                    'HTTP/1.1 200 OK' . "\r\n"
                  . 'Date: Wed, 04 Sep 2013 08:48:31 GMT' . "\r\n"
                  . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                  . 'cache-control: public,must-revalidate' . "\r\n"
                  . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                  . 'Connection: close' . "\r\n"
                  . 'Content-Type: ' . "\r\n" . "\r\n"
                  . 'bla bla some content'
                )
            ),
            $arrWithHeaders
        );
    }
    
    
    
    /**
     * Test user avatar retrieval works fine.
     * @covers \bogcon\ymclient\Engine::fetchCustomAvatar
     */
    public function testFetchCustomAvatarWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // needed for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                 . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                 . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                 . 'cache-control: public,must-revalidate' . "\r\n"
                                 . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                                 . 'Connection: close' . "\r\n"
                                 . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $url = $objStub->fetchCustomAvatar('yahooid');
        $this->assertSame('http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ', $url);
    }
    
    
    
    /**
     * Test user avatar retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::fetchCustomAvatar
     */
    public function testFetchCustomAvatarThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // needed for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'displayInfo' => array(
                                        'avatarPreference' => '0',
                                    ),
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                    'notifyServer' => 'rproxy3.messenger.yahooapis.com',
                                    'constants' => array(
                                        'presenceSubscriptionsMaxPerRequest' => 500,
                                    ),
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'bla bla bla';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchCustomAvatar('yahooid');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test user avatar retrieval fails when header with the avatar url is not set
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::fetchCustomAvatar
     */
    public function testFetchCustomAvatarThrowsExceptionWhenNoAvatarIsReceived()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1))  // stubbing for fetchCustomAvatar
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                . 'cache-control: public,must-revalidate' . "\r\n"
                                . 'Connection: close' . "\r\n"
                                . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchCustomAvatar('yahooid');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test user avatar retrieval works fine token is expired.
     * @covers \bogcon\ymclient\Engine::fetchCustomAvatar
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testFetchCustomAvatarWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for fetchCustomAvatar to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for fetchCustomAvatar to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for fetchCustomAvatar to successfully fetchCustomAvatar
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return 'HTTP/1.1 200 OK' . "\r\n"
                                . 'Date: Wed, 04 Sep 2013 08:40:43 GMT' . "\r\n"
                                . 'P3P: policyref="http://info.yahoo.com/w3c/p3p.xml", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE LOC GOV"' . "\r\n"
                                . 'cache-control: public,must-revalidate' . "\r\n"
                                . 'x-yahoo-msgr-imageurl: http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ' . "\r\n"
                                . 'Connection: close' . "\r\n"
                                . 'Content-Type: ' . "\r\n" . "\r\n";
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $url = $objStub->fetchCustomAvatar('yahooid');
        $this->assertSame('http://msgr.zenfs.com/msgrDisImg/KMU47EN7G7XKKZJRK3EFJZSABQ', $url);
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test groups retrieval works fine.
     * @covers \bogcon\ymclient\Engine::fetchGroups
     */
    public function testFetchGroupsWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $groups = $objStub->fetchGroups();
        $this->assertTrue(is_array($groups));
        $this->assertSame($groups, json_decode('{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}', true));
    }
    
    
    
    /**
     * Test groups retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchGroups();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test groups retrieval throws exception when bad json is retrieved in response.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage json
     * @covers \bogcon\ymclient\Engine::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenBadJson()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objStub->fetchGroups();
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \bogcon\ymclient\Exception('json');
        }
    }
    
    
    
    /**
     * Test groups retrieval throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::fetchGroups
     */
    public function testFetchGroupsThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->fetchGroups();
    }
    
    
    
    /**
     * Test groups retrieval works fine if token expired.
     * @covers \bogcon\ymclient\Engine::fetchGroups
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testFetchGroupsWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for fetchGroups to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for fetchGroups to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for fetchGroups to successfully fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $groups = $objStub->fetchGroups();
        $this->assertTrue(is_array($groups));
        $this->assertSame($groups, json_decode('{"groups":[{"group":{"name":"GroupX","uri":"rcore3.messenger.yahooapis.com\/v1\/group\/GroupX","contacts":[{"contact":{"id":"yahooid1","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid1","presence":{"presenceState":0},"clientCapabilities":[{"clientCapability":"richText"},{"clientCapability":"smiley"},{"clientCapability":"buzz"},{"clientCapability":"fileXfer"},{"clientCapability":"voice"},{"clientCapability":"interop"},{"clientCapability":"typing"}],"addressbook":{"id":"12","firstname":"Jonh","lastname":"Doe","lastModified":1376325172}}},{"contact":{"id":"yahooid2","uri":"rcore3.messenger.yahooapis.com\/v1\/contact\/yahoo\/yahooid2","presence":{"presenceState":-1},"clientCapabilities":[],"addressbook":{"id":"3","firstname":"Johnny","lastname":"Doe","lastModified":1192198013}}}]}}],"start":0,"total":1,"count":1}', true));
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test notifications retrieval works fine.
     * @covers \bogcon\ymclient\Engine::fetchNotifications
     */
    public function testFetchNotificationsWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $notifications = $objStub->fetchNotifications(4);
        $this->assertTrue(is_array($notifications));
        $this->assertSame($notifications, json_decode('{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }', true));
    }
    
    
    
    /**
     * Test notifications retrieval fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for fetchNotifications
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->fetchNotifications(4);
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test notifications throws exception when bad json is retrieved in response.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage json
     * @covers \bogcon\ymclient\Engine::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenBadJson()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objStub->fetchNotifications(10000);
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \bogcon\ymclient\Exception('json');
        }
    }
    
    
    
    /**
     * Test notifications retrieval throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::fetchNotifications
     */
    public function testFetchNotificationsThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->fetchNotifications(321);
    }
    
    
    
    /**
     * Test notifications retrieval works fine if token expired.
     * @covers \bogcon\ymclient\Engine::fetchNotifications
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testFetchNotificationsWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for fetchGroups to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for fetchGroups to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for fetchGroups to successfully fetchGroups
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        $notifications = $objStub->fetchNotifications(4);
        $this->assertTrue(is_array($notifications));
        $this->assertSame($notifications, json_decode('{ "@pendingMsg" : 0, "@syncStatus" : 0, "responses" : [ { "message" : { "status" : 1, "sequence" : 4, "sender" : "yahooId1" , "receiver" : "myYahooId" , "msg" : "how are you?" , "timeStamp" : 1378303022, "hash" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ==" , "msgContext" : "QuyxE57kKbX4vp7K+OP1nTbfJ30hAQ=="  } } ] }', true));
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test message sending works fine.
     * @covers \bogcon\ymclient\Engine::sendMessage
     */
    public function testSendMessageWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
    }
    
    
    
    /**
     * Test message sending fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::sendMessage
     */
    public function testSendMessageThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test message sending throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::sendMessage
     */
    public function testSendMessageThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->sendMessage('How are you my friend?', 'buddyYahooId');
    }
    
    
    
    /**
     * Test message sending works fine if token expired.
     * @covers \bogcon\ymclient\Engine::sendMessage
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testSendMessageWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for sendMessage to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for sendMessage to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for sendMessage to successfully sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->sendMessage('How are you my friend?', 'buddyYahooId');
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test presence state changing works fine.
     * @covers \bogcon\ymclient\Engine::changePresenceState
     */
    public function testChangePresenceStateWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1))
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\bogcon\ymclient\Engine::USER_IS_ONLINE, 'I \'m online :)');
    }
    
    
    
    /**
     * Test presence state changing fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::changePresenceState
     */
    public function testChangePresenceStateThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for sendMessage
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\bogcon\ymclient\Engine::USER_IS_BUSY, 'Very very busy...');
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test presence state changing throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::changePresenceState
     */
    public function testChangePresenceStateThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->changePresenceState(\bogcon\ymclient\Engine::USER_IS_BUSY, 'Very very busy...');
    }
    
    
    
    /**
     * Test presence state changing works fine if token expired.
     * @covers \bogcon\ymclient\Engine::changePresenceState
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testChangePresenceStateWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for changePresenceState to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for changePresenceState to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for changePresenceState to successfully changePresenceState
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->changePresenceState(\bogcon\ymclient\Engine::USER_IS_BUSY, 'Very very busy...');
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test buddy authorization works fine.
     * @covers \bogcon\ymclient\Engine::authorizeBuddy
     */
    public function testAuthorizeBuddyWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1)) // stubbing for authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->authorizeBuddy('buddyYahooId', \bogcon\ymclient\Engine::BUDDY_ACCEPT);
    }
    
    
    
    /**
     * Test buddy authorization fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage authbuddy
     * @covers \bogcon\ymclient\Engine::authorizeBuddy
     */
    public function testAuthorizeBuddyThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        try {
            $objStub->authorizeBuddy('buddyYahooId', \bogcon\ymclient\Engine::BUDDY_DECLINE, 'yahoo', 'I dont know you');
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Could not authorize buddy.')) {
                $this->fail('Exception should have been thrown.');
            }
            throw new \bogcon\ymclient\Exception('authbuddy');
        }
    }
    
    
    
    /**
     * Test buddy authorization throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::authorizeBuddy
     */
    public function testAuthorizeBuddyThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->authorizeBuddy('buddyYahooId');
    }
    
    
    
    /**
     * Test buddy authorization works fine if token expired.
     * @covers \bogcon\ymclient\Engine::authorizeBuddy
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testAuthorizeBuddyWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for authorizeBuddy to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for authorizeBuddy to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for authorizeBuddy to successfully authorizeBuddy
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->authorizeBuddy('buddyYahooId', \bogcon\ymclient\Engine::BUDDY_ACCEPT);
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    /**
     * Test check session works fine.
     * @covers \bogcon\ymclient\Engine::checkSession
     */
    public function testCheckSessionWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{}';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $returnedValue = $objStub->checkSession();
        $this->assertTrue(is_array($returnedValue));
        $this->assertSame($returnedValue, json_decode('{}', true));
    }
    
    
    
    /**
     * Test check session fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::checkSession
     */
    public function testCheckSessionThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                           $intHttpStatusCode = 401;
                           return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->checkSession();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test check session fails when invalid json is retrieved as response.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage json
     * @covers \bogcon\ymclient\Engine::checkSession
     */
    public function testCheckSessionThrowsExceptionWhenInvalidJson()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
       $objStub->expects($this->at(1)) // stubbing for checkSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '---bad---json---';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        
        try {
            $objStub->checkSession();
        } catch (\bogcon\ymclient\Exception $objEx) {
            if (false === strpos($objEx->getMessage(), 'Json error code')) {
                $this->fail("Exception should have been thrown");
            }
            throw new \bogcon\ymclient\Exception('json');
        }
    }
    
    
    
    /**
     * Test check session works fine if token has expired
     * @covers \bogcon\ymclient\Engine::checkSession
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testCheckSessionWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for checkSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for checkSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for checkSession to successfully execute
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '{}';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn();
        $returnedValue = $objStub->checkSession();
        $this->assertTrue(is_array($returnedValue));
        $this->assertSame($returnedValue, json_decode('{}', true));
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
     /**
     * Test keep session alive works fine.
     * @covers \bogcon\ymclient\Engine::keepAliveSession
     */
    public function testKeepAliveSessionWorksFine()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
                
        $objStub->expects($this->at(1)) // stubbing for keepAliveSession
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
    }
    
    
    
    /**
     * Test keep session alive fails when http status code retreived from curl call is not 200.
     * @expectedException \bogcon\ymclient\Exception
     * @covers \bogcon\ymclient\Engine::keepAliveSession
     */
    public function testKeepAliveSessionThrowsExceptionWhenStatusIsNot200()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        
        $objStub->expects($this->at(0))  // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for keepAliveSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for keepAliveSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for keepAliveSession second try
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 500;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
        $this->fail("Exception should have been thrown");
    }
    
    
    
    /**
     * Test keep session alive throws exception when trying to access directly, without previously logging in.
     * @expectedException \bogcon\ymclient\Exception
     * @expectedExceptionMessage You have to be logged in in order to perform this action.
     * @covers \bogcon\ymclient\Engine::keepAliveSession
     */
    public function testKeepAliveSessionThrowsExceptionWhenNoPreviouslyLoggedIn()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('ter34dgf', 'tert34gdh', 'appKey123', 'appSecret123'));
        $objStub->keepAliveSession();
    }
    
    
    
    /**
     * Test keep session alive works fine if token has expired
     * @covers \bogcon\ymclient\Engine::keepAliveSession
     * @covers \bogcon\ymclient\Engine::isTokenRenewed
     */
    public function testKeepAliveSessionWorksFineIfTokenExpired()
    {
        $objStub = $this->getMock('\bogcon\ymclient\Engine', array('makeApiCall'), array('usr', 'pass', 'appKey123', 'appSecret123'));
        $intHttpStatusCode = 0;
        $objStub->expects($this->at(0)) // stubbing for login
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return json_encode(
                                array(
                                    'sessionId' => 'someTestSessionId',
                                    'primaryLoginId' => 'someLoginId',
                                    'server' => 'rcore3.messenger.yahooapis.com',
                                )
                            );
                        }
                    )
                );
        $objStub->expects($this->at(1)) // stubbing for keepAliveSession to get access token expired
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 401;
                            return 'oauth_problem="token_expired"';
                        }
                    )
                );
        $objStub->expects($this->at(2)) // stubbing for keepAliveSession to renew access token
                ->method('makeApiCall')
                ->will($this->returnValue('oauth_token=testOAuthToken&oauth_token_secret=testOAuthTokenSecret&oauth_expires_in=3600&oauth_session_handle=testOAuthSessionHandle&oauth_authorization_expires_in=770477963&xoauth_yahoo_guid=testXOAuthYahooGuid'));
        $objStub->expects($this->at(3)) // stubbing for keepAliveSession to successfully execute
                ->method('makeApiCall')
                ->will(
                    $this->returnCallback(
                        function ($strUrl, $strMethod, $arrHeaders, $strPostData, $blnSuprimeResponseHeader, &$intHttpStatusCode) {
                            $intHttpStatusCode = 200;
                            return '';
                        }
                    )
                );
        $objStub->setTokens(
            array(
                'request' => 'someTestRequestToken',
                'access' => array(
                    'oauth_token' => 'sometestOAuthToken',
                    'oauth_token_secret' => 'someTestOAuthTokenSecret',
                    'oauth_session_handle' => 'someTestOAuthSessionHandle',
                ),
            )
        )->logIn()
         ->keepAliveSession();
        $this->assertTrue($objStub->isTokenRenewed());
    }
    
    
    
    /**
     * Test destructor.
     * @covers \bogcon\ymclient\Engine::__destruct
     */
    public function testDestruct()
    {
        $objYM = new Engine('test', 'testpass', 'testapikey', 'testapisecret');
        unset($objYM);
    }
}
