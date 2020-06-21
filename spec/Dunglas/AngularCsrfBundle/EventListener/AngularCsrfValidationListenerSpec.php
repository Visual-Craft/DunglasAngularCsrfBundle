<?php

/*
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace spec\Dunglas\AngularCsrfBundle\EventListener;

use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenManager;
use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenResolver;
use Dunglas\AngularCsrfBundle\Routing\RouteMatcherInterface;
use PhpSpec\ObjectBehavior;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * @author Kévin Dunglas <dunglas@gmail.com>
 */
class AngularCsrfValidationListenerSpec extends ObjectBehavior
{
    const INPUT_KEY = 'csrf';
    const INPUT_METHOD = 'header';
    const VALID_TOKEN = 'valid';
    const INVALID_TOKEN = 'invalid';

    private $routes = array('^/secured');
    private $excluded = array('^/secured/excluded');
    private $secureValidRequest;
    private $secureInvalidRequest;
    private $unsecureRequest;
    private $excludedSecureRequest;

    public function let(
        AngularCsrfTokenManager $tokenManager,
        RouteMatcherInterface $routeMatcher,
        AngularCsrfTokenResolver $validTokenResolver,
        Request $secureValidRequest,
        Request $secureInvalidRequest,
        Request $unsecureRequest,
        Request $excludedSecureRequest,
        HeaderBag $validHeaders,
        HeaderBag $invalidHeaders
    ) {
        $tokenManager->isTokenValid(self::VALID_TOKEN)->willReturn(true);

        $this->secureValidRequest = $secureValidRequest;
        $validHeaders->get(self::INPUT_KEY)->willReturn(self::VALID_TOKEN);
        $this->secureValidRequest->headers = $validHeaders;

        $validTokenResolver->resolve($secureValidRequest)->willReturn(self::VALID_TOKEN);

        $this->secureInvalidRequest = $secureInvalidRequest;
        $invalidHeaders->get(self::INPUT_KEY)->willReturn(self::INVALID_TOKEN);
        $this->secureInvalidRequest->headers = $invalidHeaders;

        $this->unsecureRequest = $unsecureRequest;
        $this->excludedSecureRequest = $excludedSecureRequest;

        $routeMatcher->match($this->secureValidRequest, $this->routes)->willReturn(true);
        $routeMatcher->match($this->secureValidRequest, $this->excluded)->willReturn(false);
        $routeMatcher->match($this->secureInvalidRequest, $this->routes)->willReturn(true);
        $routeMatcher->match($this->secureInvalidRequest, $this->excluded)->willReturn(false);
        $routeMatcher->match($this->unsecureRequest, $this->routes)->willReturn(false);
        $routeMatcher->match($this->unsecureRequest, $this->excluded)->willReturn(false);
        $routeMatcher->match($this->excludedSecureRequest, $this->routes)->willReturn(true);
        $routeMatcher->match($this->excludedSecureRequest, $this->excluded)->willReturn(true);

        $this->beConstructedWith(
            $tokenManager,
            $validTokenResolver,
            $routeMatcher,
            $this->routes,
            $this->excluded
        );
    }

    public function it_is_initializable()
    {
        $this->shouldHaveType('Dunglas\AngularCsrfBundle\EventListener\AngularCsrfValidationListener');
    }

    public function it_secures(GetResponseEvent $event)
    {
        $event->getRequestType()->willReturn(HttpKernelInterface::MASTER_REQUEST);
        $event->getRequest()->willReturn($this->secureValidRequest);

        $this->onKernelRequest($event);
    }

    public function it_does_not_secure_on_sub_request(GetResponseEvent $event)
    {
        $event->getRequestType()->willReturn(HttpKernelInterface::SUB_REQUEST);
        $event->getRequest()->shouldNotBeCalled();

        $this->onKernelRequest($event);
    }

    public function it_does_not_secure_when_it_does_not(GetResponseEvent $event)
    {
        $event->getRequestType()->willReturn(HttpKernelInterface::MASTER_REQUEST);
        $event->getRequest()->willReturn($this->unsecureRequest);
        $event->getResponse()->shouldNotBeCalled();

        $this->onKernelRequest($event);
    }

    public function it_does_not_secure_when_it_is_excluded(GetResponseEvent $event)
    {
        $event->getRequestType()->willReturn(HttpKernelInterface::MASTER_REQUEST);
        $event->getRequest()->willReturn($this->excludedSecureRequest);

        $this->onKernelRequest($event);
    }
}
