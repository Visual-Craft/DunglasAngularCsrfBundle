<?php

/*
 * (c) Kévin Dunglas <dunglas@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Dunglas\AngularCsrfBundle\Form\Extension;

use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenManager;
use Dunglas\AngularCsrfBundle\Csrf\AngularCsrfTokenResolver;
use Dunglas\AngularCsrfBundle\Routing\RouteMatcherInterface;
use Symfony\Component\Form\AbstractTypeExtension;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\OptionsResolver\OptionsResolver;

/**
 * Form extension that disables the given forms' CSRF token validation
 * in favor of the validation token sent with header.
 * It disables only when header token is valid.
 *
 * @author Michal Dabrowski <dabrowski@brillante.pl>
 */
class DisableCsrfExtension extends AbstractTypeExtension
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
     * @var RequestStack
     */
    protected $requestStack;

    /**
     * @param AngularCsrfTokenManager $angularCsrfTokenManager
     * @param AngularCsrfTokenResolver $angularCsrfTokenResolver
     * @param RouteMatcherInterface $routeMatcher
     * @param RequestStack $requestStack
     * @param array $routes
     */
    public function __construct(
        AngularCsrfTokenManager $angularCsrfTokenManager,
        AngularCsrfTokenResolver $angularCsrfTokenResolver,
        RouteMatcherInterface $routeMatcher,
        RequestStack $requestStack,
        array $routes
    ) {
        $this->angularCsrfTokenManager = $angularCsrfTokenManager;
        $this->angularCsrfTokenResolver = $angularCsrfTokenResolver;
        $this->routeMatcher = $routeMatcher;
        $this->requestStack = $requestStack;
        $this->routes = $routes;
    }

    /**
     * {@inheritdoc}
     */
    public function configureOptions(OptionsResolver $resolver)
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request) {
            return;
        }

        if (false === $this->routeMatcher->match($request, $this->routes)) {
            return;
        }

        $value = $this->angularCsrfTokenResolver->resolve($request);

        if ($this->angularCsrfTokenManager->isTokenValid($value)) {
            $resolver->setDefaults([
                'csrf_protection' => false,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getExtendedType()
    {
        return 'Symfony\Component\Form\Extension\Core\Type\FormType';
    }
}
