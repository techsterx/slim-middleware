<?php

namespace techsterx\SlimMiddleware;

class HmacAuth extends \Slim\Middleware
{
	protected $hashes;
	protected $options;

	protected $dateFormat = 'D, d M Y H:i:s T';

	public function __construct(array $hashes, array $options = array())
	{
		$this->hashes = $hashes;

		$this->options = array_merge(array(
			'allowedRoutes' => array(),
			'header' => array(
				'authorization' => 'X-HmacAuth-Authorization',
				'date' => 'X-HmacAuth-Date',
			),
		), $options);
	}

	// TODO: This is way too long, break this up into functions
	public function call()
	{
		$req = $this->app->request();

		if (!count($this->options['allowedRoutes']) || !$this->checkRoute($req->getMethod().$req->getResourceUri())) {
			// X-HmacAuth-Authorization:
			// AccessKeyId=MyAccessKey,
			// Algorithm=HmacSHA1|HmacSHA256,
			// Signature=Base64(Algorithm(ValueOfDateHeader, SigningKey))
			$authHeader = $req->headers->get($this->options->headers['authorization']);

			// If we didn't recieve the authorization header, the request is 
			// malformed
			if ($authHeader === null) {
				$this->app->response()->setStatus(400);
				return;
			}

			$dateHeader = $req->headers->get($this->options->headers['date']) ?: $req->headers->get('Date');

			$clientDate = $this->getDateTime($dateHeader);
			$serverDate = $this->getDateTime();

			if (!$this->checkTimestamp($clientDate, $serverDate)) {
				$this->app->response()->setStatus(400);
				return;
			}

			// Split the header into the appropriate parts
			$authHeaderParts = explode($authHeader, ',', 3);

			// If we didn't get all the parts, the request is malformed
			if (count($authHeaderParts) < 3) {
				$this->app->response()->setStatus(400);
				return;
			}

			foreach ($authHeaderParts as $part) {
				list($key, $value) = explode('=', $part);

				$key = strtolower(trim($key));

				switch($key) {
					case 'accesskeyid':
						$accessKeyId = trim($value);
						break;
					case 'algorithm':
					case 'signature':
						$$key = trim($value);
						break;
					default:
						$this->app->response()->setStatus(400);
						return;
				}
			}

			// If the public hash doesn't exist, access is forbidden
			if (!array_key_exists($accessKeyId, $this->hashes)) {
				$this->app->response()->setStatus(400);
				return;
			}

			switch ($algorithm) {
				case 'HmacSHA256':
					$algorithm = 'sha256';
					break;
				case 'HmacSHA1':
					$algorithm = 'sha1';
					break;
				default:
					$this->app->response()->setStatus(400);
					return;
			}

			// If our hash doesn't match the signature, the request is bad
			if (!$this->isValid()) {
				$this->app->response()->setStatus(400);
				return;
			}
		}

		$this->next->call();
	}

	/**
	 * isValid() - Determines if the signature is valid
	 *
	 * @param string $algorithm
	 * @param \DateTime $clientDate
	 *
	 * @return bool
	 */
	private function isValid($algorithm, \DateTime $clientDate)
	{
		$hash = base64_encode(hash_hmac($algorithm, $clientDate, $this->hashes[$accessKeyId]));

		return ($hash === $signature);
	}

	/**
	 * getDateTime()
	 *
	 * @param string $timestamp (optional)
	 *
	 * @return \DateTime
	 */
	private function getDateTime($timestamp = null)
	{
		if ($timestamp === null) {
			return new \DateTime('now', new \DateTimeZone('UTC'));
		} else {
			return \DateTime::createFromFormat($this->dateFormat, $timestamp, new \DateTimeZone('UTC'));
		}
	}

	/**
	 * checkTimestamp()
	 *
	 * @param \DateTime $date1
	 * @param \DateTime $date2
	 *
	 * @return bool
	 */
	private function checkTimestamp(\DateTime $date1, \DateTime $date2)
	{
		$diff = $date1->diff($date2);

		$minutes = (($diff->days * 24 * 60) + ($diff->h * 60) + $diff->i) * ($diff->invert ? -1 : 1);

		return (bool) (minutes >= 0 && $minutes <= 5);
	}

	/**
	 * checkRoute()
	 *
	 * @param string $uri
	 *
	 * @return bool
	 */
	private function checkRoute($uri)
	{
		foreach ($this->options['allowedRoutes'] as $route) {
			$pattern = '|^' . str_replace('*', '.+', $route) . '$|';

			if (preg_match($pattern, $uri)) {
				return true;
			}
		}

		return false;
	}
}
