<?php

/*
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Dunglas\AngularCsrfBundle\EventListener;

use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenManager;
use Dunglas\AngularCsrfBundle\Routing\RouteMatcherInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Checks the validity of the CSRF token sent by AngularJS.
 *
 * @author Kévin Dunglas <dunglas@gmail.com>
 */
class AngularCsrfValidationListener
{
    const TOKEN_INPUT_METHOD_HEADER = 'header';
    const TOKEN_INPUT_METHOD_QUERY = 'query';
    const TOKEN_INPUT_METHOD_REQUEST = 'request';

    /**
     * @var AngularCsrfTokenManager
     */
    protected $angularCsrfTokenManager;
    /**
     * @var RouteMatcherInterface
     */
    protected $routeMatcher;
    /**
     * @var array
     */
    protected $routes;
    /**
     * @var string
     */
    private $tokenInputMethod;
    /**
     * @var string
     */
    private $tokenInputKey;
    /**
     * @var array
     */
    private $exclude;

    /**
     * @param AngularCsrfTokenManager $angularCsrfTokenManager
     * @param RouteMatcherInterface   $routeMatcher
     * @param array                   $routes
     * @param string                  $tokenInputMethod
     * @param string                  $tokenInputKey
     * @param array                   $exclude
     */
    public function __construct(
        AngularCsrfTokenManager $angularCsrfTokenManager,
        RouteMatcherInterface $routeMatcher,
        array $routes,
        string $tokenInputMethod,
        string $tokenInputKey,
        array $exclude = array()
    ) {
        $this->angularCsrfTokenManager = $angularCsrfTokenManager;
        $this->routeMatcher = $routeMatcher;
        $this->routes = $routes;
        $this->tokenInputMethod = $tokenInputMethod;
        $this->tokenInputKey = $tokenInputKey;
        $this->exclude = $exclude;
    }

    /**
     * Handles CSRF token validation.
     *
     * @param GetResponseEvent $event
     *
     * @throws AccessDeniedHttpException
     */
    public function onKernelRequest(GetResponseEvent $event)
    {
        if (
            HttpKernelInterface::MASTER_REQUEST !== $event->getRequestType()
            ||
            $this->routeMatcher->match($event->getRequest(), $this->exclude)
            ||
            !$this->routeMatcher->match($event->getRequest(), $this->routes)
        ) {
            return;
        }

        $value = $this->getToken($event->getRequest());

        if (!$value || !$this->angularCsrfTokenManager->isTokenValid($value)) {
            throw new AccessDeniedHttpException('Bad CSRF token.');
        }
    }

    /**
     * @param Request $request
     * @return string|null
     */
    private function getToken(Request $request)
    {
        switch ($this->tokenInputMethod) {
            case self::TOKEN_INPUT_METHOD_HEADER:
                return $request->headers->get($this->tokenInputKey);
                break;
            case self::TOKEN_INPUT_METHOD_QUERY:
                return $request->query->get($this->tokenInputKey);
                break;
            case self::TOKEN_INPUT_METHOD_REQUEST:
                return $request->request->get($this->tokenInputKey);
                break;
            default:
                return null;
                break;
        }
    }
}
