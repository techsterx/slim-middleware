<?php

namespace techsterx\Middleware;

class RequiresHttps extends \Slim\Middleware
{
	protected $methods;

	public function __constrcut(array $methods = array())
	{
		$this->methods = $methods;
	}

	public function call()
	{
		$method = $this->app->request()->getmethod();

		if (count($this->methods) == 0 || in_array($method, $this->methods)) {
			if ($this->app->environment['slim.url_scheme']  != 'https') {
				$this->app->response()->setStatus(501);
				return;
			}
		}

		$this->next->call();
	}
}
