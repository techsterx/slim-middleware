<?php

namespace techsterx\SlimMiddleware;

class HmacAuth extends \Slim\Middleware
{
	protected $hashes;
	protected $allowedRoutes;

	public function __construct(array $hashes, array $allowedRoutes = array())
	{
		$this->allowedRoutes = $allowedRoutes;
		$this->hashes = $hashes;
	}

	public function call()
	{
		$req = $this->app->request();

		if (!count($this->allowedRoutes) || !$this->checkRoute($req->getMethod().$req->getResourceUri())) {
			$publicHash = $req->headers('X-Public');
			$contentHash = $req->headers('X-Hash');

			// If we didn't receive the X-Public or X-Hash headers, the request is 
			// malformed
			if (!$publicHash || !$contentHash) {
				$this->app->response()->setStatus(400);
				return;
			}

			// If the public hash doesn't exist, access is forbidden
			if (!array_key_exists($publicHash, $this->hashes)) {
				$this->app->response()->setStatus(400);
				return;
			}

			$content = $publicHash . $req->getMethod() . $req->getResourceUri() . $req->getBody();

			$hash = hash_hmac('sha256', $content, $this->hashes[$publicHash]);

			// If our hash doesn't match the submitted hash, the request is bad
			if ($hash !== $contentHash) {
				$this->app->response()->setStatus(400);
				return;
			}
		}

		$this->next->call();
	}

	private function checkRoute($uri)
	{
		foreach ($this->allowedRoutes as $route) {
			$pattern = '|^' . str_replace('*', '.+', $route) . '$|';

			if (preg_match($pattern, $uri)) {
				return true;
			}
		}

		return false;
	}
}
