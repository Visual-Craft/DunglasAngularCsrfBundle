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
    protected $headerName;
    /**
     * @var string
     */
    private $tokenSubmitMethod;
    /**
     * @var string
     */
    private $tokenName;
    /**
     * @var array
     */
    private $exclude;

    /**
     * @param AngularCsrfTokenManager $angularCsrfTokenManager
     * @param RouteMatcherInterface   $routeMatcher
     * @param array                   $routes
     * @param string                  $headerName
     * @param string                  $tokenSubmitMethod
     * @param string                  $tokenName
     * @param array                   $exclude
     */
    public function __construct(
        AngularCsrfTokenManager $angularCsrfTokenManager,
        RouteMatcherInterface $routeMatcher,
        array $routes,
        $headerName,
        string $tokenSubmitMethod,
        string $tokenName,
        array $exclude = array()
    ) {
        $this->angularCsrfTokenManager = $angularCsrfTokenManager;
        $this->routeMatcher = $routeMatcher;
        $this->routes = $routes;
        $this->headerName = $headerName;
        $this->exclude = $exclude;
        $this->tokenSubmitMethod = $tokenSubmitMethod;
        $this->tokenName = $tokenName;
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

        $this->unsetQueryStringParameter($event->getRequest());
    }

    /**
     * @param Request $request
     * @return string|null
     */
    private function getToken(Request $request)
    {
        if ('query_string' === $this->tokenSubmitMethod) {
            return $request->query->get($this->tokenName);
        }

        if ('header' === $this->tokenSubmitMethod) {
            return $request->headers->get($this->headerName);
        }

        return null;
    }

    /**
     * @param Request $request
     */
    private function unsetQueryStringParameter(Request $request)
    {
        $request->query->remove($this->tokenName);
    }
}
