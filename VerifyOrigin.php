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
		$origin = $this->app->request()->headers('Origin');

		if (count($this->allowedOrigins) && !in_array($origin, $this->allowedOrigins))
		{
			$this->app->response()->setStatus(403);
			return;
		}

		$this->next->call();
	}
}
