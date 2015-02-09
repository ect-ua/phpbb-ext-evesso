<?php
/**
*
* EveSSO - An phpBB extension adding EVE Online SSO authentication to your forum.
*
* @copyright (c) 2015 Jordy Wille (http://github.com/cyerus)
* @license GNU General Public License, version 2 (GPL-2.0)
*
*/

namespace cyerus\evesso\core;

/**
* EVE Online SSO / OAuth2 service
*
* @package auth
*/
class evesso extends \phpbb\auth\provider\oauth\service\base
{
	/**
	* phpBB config
	*
	* @var phpbb_config
	*/
	protected $config;

	/**
	* phpBB request
	*
	* @var phpbb_request
	*/
	protected $request;

	/**
	* Constructor
	*
	* @param    phpbb_config     $config
	* @param    phpbb_request    $request
	*/
	public function __construct(\phpbb\config\config $config, \phpbb\request\request_interface $request)
	{
		$this->config = $config;
		$this->request = $request;

		global $user;
		$user->add_lang_ext('cyerus/evesso', 'evesso');
		
		// TODO: Find a better way to load this class
		global $phpbb_root_path;
		require_once($phpbb_root_path . '/ext/cyerus/evesso/service/Evesso.php');
	}

	/**
	* {@inheritdoc}
	*/
	public function get_service_credentials()
	{
		return array(
			'key'		=> $this->config['auth_oauth_evesso_key'],
			'secret'	=> $this->config['auth_oauth_evesso_secret'],
		);
	}

	/**
	* {@inheritdoc}
	*/
	public function perform_auth_login()
	{
		if (!($this->service_provider instanceof \OAuth\OAuth2\Service\Evesso))
		{
			throw new phpbb\auth\provider\oauth\service\exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
		}

		// This was a callback request from EVE Online SSO, get the token
		$this->service_provider->requestAccessToken($this->request->variable('code', ''));
		
		// Send a request to /verify to determine user information
		$result = json_decode($this->service_provider->request('https://login.eveonline.com/oauth/verify'), true);

		// Return the CharacterOwnerHash is this is unique for each character on each account.
		// If a character is transferred, the CharacterOwnerHash is newly generated.
		return $result['CharacterOwnerHash'];
	}

	/**
	* {@inheritdoc}
	*/
	public function perform_token_auth()
	{
		if (!($this->service_provider instanceof \OAuth\OAuth2\Service\Evesso))
		{
			throw new phpbb\auth\provider\oauth\service\exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
		}

		// Send a request to /verify to determine user information
		$result = json_decode($this->service_provider->request('https://login.eveonline.com/oauth/verify'), true);
		
		// Return the CharacterOwnerHash is this is unique for each character on each account.
		// If a character is transferred, the CharacterOwnerHash is newly generated.
		return $result['CharacterOwnerHash'];
	}
}
