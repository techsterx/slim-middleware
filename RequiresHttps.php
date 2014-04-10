<?php

namespace techsterx\SlimMiddleware;

class RequiresHttps extends \Slim\Middleware
{
	protected $methods;

	public function __construct(array $methods = array())
	{
		$this->methods = $methods;
	}

	public function call()
	{
		$method = $this->app->request()->getmethod();

		if (count($this->methods) == 0 || in_array($method, $this->methods)) {
			if ($this->app->environment['slim.url_scheme']  != 'https') {
				// Status 426 isn't currently support by Slim :(
				//$this->app->response()->setStatus(426);
				//$this->app->response()->header('Upgrade', 'TLS/1.0, HTTP/1.1');
				//$this->app->response()->header('Connection', 'Upgrade');
				$this->app->response()->setStatus(501);
				return;
			}
		}

		$this->next->call();
	}
}
