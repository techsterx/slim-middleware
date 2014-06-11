<?php

namespace techsterx\SlimMiddleware;

class VerifyOrigin extends \Slim\Middleware
{
	protected $allowedOrigins;

	public function __construct(array $origins = array())
	{
		$this->allowedOrigins = $origins;
	}

	public function call()
	{
		$origin = $this->app->request()->headers->get('Origin');

		if (count($this->allowedOrigins) && !in_array($origin, $this->allowedOrigins))
		{
			$this->app->response()->setStatus(403);
			return;
		}

		// Set the allow origin header
		if (strlen($origin) > 0) {
			$this->app->response()->headers->set('Access-Control-Allow-Origin', $origin);
		}

		$this->next->call();
	}
}
