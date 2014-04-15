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

		if(count($this->allowedRoutes) && !in_array($req->getMethod().$res->getResourceUri(), $this->allowedRoutes)) {
			$publicHash = $req->headers('X-Public');
			$contentHash = $req->headers('X-Hash');

			// If we didn't receive the X-Public or X-Hash headers, the request is 
			// malformed
			if(!$publicHash || !$contentHash) {
				$this->app->response()->setStatus(400);
				return;
			}

			// If the public hash doesn't exist, access is forbidden
			if (!array_key_exists($publicHash, $this->hashes)) {
				$this->app->response()->setStatus(403);
				return;
			}

			$content = $publicHash . $req->getMethod() . $req->getResourceUri() . $req->getBody();

			$hash = hash_hmac('sha256', $content, $this->hashes[$publicHash]);

			// If our has doesn't match the submitted hash, the request is bad
			if ($hash !== $contentHash) {
				$this->app->response()->setStatus(400);
				return;
			}
		}

		$this->next->call();
	}
}
