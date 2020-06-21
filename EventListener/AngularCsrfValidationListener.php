<?php

/*
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Dunglas\AngularCsrfBundle\EventListener;

use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenManager;
use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenResolver;
use Dunglas\AngularCsrfBundle\Routing\RouteMatcherInterface;
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
     * @var AngularCsrfTokenResolver
     */
    private $angularCsrfTokenResolver;

    /**
     * @var RouteMatcherInterface
     */
    protected $routeMatcher;

    /**
     * @var array
     */
    protected $routes;

    /**
     * @var array
     */
    private $exclude;

    /**
     * @param AngularCsrfTokenManager $angularCsrfTokenManager
     * @param AngularCsrfTokenResolver $angularCsrfTokenResolver
     * @param RouteMatcherInterface $routeMatcher
     * @param array $routes
     * @param array $exclude
     */
    public function __construct(
        AngularCsrfTokenManager $angularCsrfTokenManager,
        AngularCsrfTokenResolver $angularCsrfTokenResolver,
        RouteMatcherInterface $routeMatcher,
        array $routes,
        array $exclude = []
    ) {
        $this->angularCsrfTokenManager = $angularCsrfTokenManager;
        $this->angularCsrfTokenResolver = $angularCsrfTokenResolver;
        $this->routeMatcher = $routeMatcher;
        $this->routes = $routes;
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

        $value = $this->angularCsrfTokenResolver->resolve($event->getRequest());

        if (!$value || !$this->angularCsrfTokenManager->isTokenValid($value)) {
            throw new AccessDeniedHttpException('Bad CSRF token.');
        }
    }
}
