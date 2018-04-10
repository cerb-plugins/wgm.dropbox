<?php
if(class_exists('Extension_PageMenuItem')):
class WgmDropbox_SetupPluginsMenuItem extends Extension_PageMenuItem {
	const POINT = 'wgmdropbox.setup.menu.plugins.dropbox';
	
	function render() {
		$tpl = DevblocksPlatform::services()->template();
		$tpl->assign('extension', $this);
		$tpl->display('devblocks:wgm.dropbox::setup/menu_item.tpl');
	}
};
endif;

if(class_exists('Extension_PageSection')):
class WgmDropbox_SetupSection extends Extension_PageSection {
	const ID = 'wgmdropbox.setup.dropbox';
	
	function render() {
		$tpl = DevblocksPlatform::services()->template();

		$visit = CerberusApplication::getVisit();
		$visit->set(ChConfigurationPage::ID, 'dropbox');
		
		$credentials = DevblocksPlatform::getPluginSetting('wgm.dropbox', 'credentials', [], true, true);
		$tpl->assign('credentials', $credentials);
		
		$tpl->display('devblocks:wgm.dropbox::setup/index.tpl');
	}
	
	function saveJsonAction() {
		try {
			@$client_id = DevblocksPlatform::importGPC($_REQUEST['client_id'],'string','');
			@$client_secret = DevblocksPlatform::importGPC($_REQUEST['client_secret'],'string','');
			
			if(empty($client_id) || empty($client_secret))
				throw new Exception("Both the API Auth Token and URL are required.");
			
			$credentials = [
				'client_id' => $client_id,
				'client_secret' => $client_secret,
			];
			
			DevblocksPlatform::setPluginSetting('wgm.dropbox', 'credentials', $credentials, true, true);
			
			echo json_encode(array('status'=>true,'message'=>'Saved!'));
			return;
			
		} catch (Exception $e) {
			echo json_encode(array('status'=>false,'error'=>$e->getMessage()));
			return;
		}
	}
};
endif;

class WgmDropbox_API {
	const DROPBOX_OAUTH_HOST = "https://api.dropboxapi.com";
	const DROPBOX_AUTHORIZE_URL = "https://www.dropbox.com/oauth2/authorize";
	const DROPBOX_ACCESS_TOKEN_URL = "https://api.dropboxapi.com/oauth2/token";
	
	static $_instance = null;
	
	private $_oauth = null;
	private $_client_id = null;
	private $_client_secret = null;
	
	private function __construct() {
		$credentials = DevblocksPlatform::getPluginSetting('wgm.dropbox', 'credentials', [], true, true);
		
		$this->_client_id = @$credentials['client_id'];
		$this->_client_secret = @$credentials['client_secret'];
		
		$this->_oauth = DevblocksPlatform::services()->oauth($this->_client_id, $this->_client_secret);
	}
	
	/**
	 * @return WgmDropbox_API
	 */
	static public function getInstance() {
		if(null == self::$_instance) {
			self::$_instance = new WgmDropbox_API();
		}

		return self::$_instance;
	}
	
	public function setCredentials($token) {
		$this->_oauth->setTokens($token);
	}
	
	public function getAuthorizationUrl($callback_url) {
		return self::DROPBOX_AUTHORIZE_URL . "?response_type=code&state=&client_id=" . urlencode($this->_client_id) . "&redirect_uri=" . urlencode($callback_url);
	}
	
	public function post($url, $params) {
		return $this->_fetch($url, 'POST', $params);
	}
	
	public function get($url) {
		return $this->_fetch($url, 'GET');
	}
	
	private function _fetch($url, $method = 'GET', $params = array()) {
		if(false == ($response = $this->_oauth->executeRequestWithToken($method, $url, $params, 'OAuth')))
			return false;
		
		return $response;
	}
}

class ServiceProvider_Dropbox extends Extension_ServiceProvider implements IServiceProvider_OAuth, IServiceProvider_HttpRequestSigner {
	const ID = 'wgm.dropbox.service.provider';
	
	function renderConfigForm(Model_ConnectedAccount $account) {
		$tpl = DevblocksPlatform::services()->template();
		$active_worker = CerberusApplication::getActiveWorker();
		
		$tpl->assign('account', $account);
		
		$params = $account->decryptParams($active_worker);
		$tpl->assign('params', $params);
		
		$tpl->display('devblocks:wgm.dropbox::providers/dropbox.tpl');
	}
	
	function saveConfigForm(Model_ConnectedAccount $account, array &$params) {
		@$edit_params = DevblocksPlatform::importGPC($_POST['params'], 'array', array());
		
		$active_worker = CerberusApplication::getActiveWorker();
		$encrypt = DevblocksPlatform::services()->encryption();
		
		// Decrypt OAuth params
		if(isset($edit_params['params_json'])) {
			if(false == ($outh_params_json = $encrypt->decrypt($edit_params['params_json'])))
				return "The connected account authentication is invalid.";
				
			if(false == ($oauth_params = json_decode($outh_params_json, true)))
				return "The connected account authentication is malformed.";
			
			if(is_array($oauth_params))
			foreach($oauth_params as $k => $v)
				$params[$k] = $v;
		}
		
		return true;
	}
	
	private function _getAppKeys() {
		$credentials = DevblocksPlatform::getPluginSetting('wgm.dropbox','credentials',[],true,true);
		
		if(!isset($credentials['client_id']) || !isset($credentials['client_secret']))
			return false;
		
		return array(
			'key' => $credentials['client_id'],
			'secret' => $credentials['client_secret'],
		);
	}
	
	function oauthRender() {
		@$form_id = DevblocksPlatform::importGPC($_REQUEST['form_id'], 'string', '');
		
		$oauth_state = CerberusApplication::generatePassword(32);
		
		// Store the $form_id in the session
		$_SESSION['oauth_form_id'] = $form_id;
		$_SESSION['oauth_state'] = $oauth_state;
		
		// [TODO] Report about missing app keys
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		$url_writer = DevblocksPlatform::services()->url();
		$oauth = DevblocksPlatform::services()->oauth($app_keys['key'], $app_keys['secret']);
		
		// OAuth callback
		$redirect_url = $url_writer->write(sprintf('c=oauth&a=callback&ext=%s', ServiceProvider_Dropbox::ID), true);
		
		$url = sprintf("%s?response_type=code&client_id=%s&state=%s&redirect_uri=%s",
			$oauth->getAuthenticationURL(WgmDropbox_API::DROPBOX_AUTHORIZE_URL),
			$app_keys['key'],
			$oauth_state,
			rawurlencode($redirect_url)
		);
		
		header('Location: ' . $url);
	}
	
	function oauthCallback() {
		@$code = $_REQUEST['code'];
		@$state = $_REQUEST['state'];
		
		$form_id = $_SESSION['oauth_form_id'];
		$oauth_state = $_SESSION['oauth_state'];
		
		unset($_SESSION['oauth_form_id']);
		unset($_SESSION['oauth_state']);
		
		if($oauth_state != $state)
			DevblocksPlatform::dieWithHttpError('Forbidden', 403);
		
		$url_writer = DevblocksPlatform::services()->url();
		$encrypt = DevblocksPlatform::services()->encryption();
		$active_worker = CerberusApplication::getActiveWorker();
		
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		// OAuth callback
		$redirect_url = $url_writer->write(sprintf('c=oauth&a=callback&ext=%s', ServiceProvider_Dropbox::ID), true);
		
		$oauth = DevblocksPlatform::services()->oauth($app_keys['key'], $app_keys['secret']);
		$oauth->setTokens($code);
		
		$postdata = [
			'code' => $code,
			'grant_type' => 'authorization_code',
			'client_id' => $app_keys['key'],
			'client_secret' => $app_keys['secret'],
			'redirect_uri' => $redirect_url,
		];
		
		$ch = DevblocksPlatform::curlInit(WgmDropbox_API::DROPBOX_ACCESS_TOKEN_URL);
		curl_setopt($ch, CURLOPT_POST, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $postdata);
		$out = DevblocksPlatform::curlExec($ch);
		
		@$params = json_decode($out, true);
		
		// Output
		$tpl = DevblocksPlatform::services()->template();
		$tpl->assign('form_id', $form_id);
		$tpl->assign('label', 'Dropbox');
		$tpl->assign('params_json', $encrypt->encrypt(json_encode($params)));
		$tpl->display('devblocks:cerberusweb.core::internal/connected_account/oauth_callback.tpl');
	}
	
	function authenticateHttpRequest(Model_ConnectedAccount $account, &$ch, &$verb, &$url, &$body, &$headers) {
		$credentials = $account->decryptParams();
		
		if(
			!isset($credentials['access_token'])
			)
			return false;
			
		// Add a bearer token
		$headers[] = sprintf('Authorization: Bearer %s', $credentials['access_token']);
		
		return true;
	}
}