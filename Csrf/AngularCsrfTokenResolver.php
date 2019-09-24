<?php

namespace Dunglas\AngularCsrfBundle\Csrf;

use Symfony\Component\HttpFoundation\Request;

class AngularCsrfTokenResolver
{
    const TOKEN_INPUT_METHOD_HEADER = 'header';
    const TOKEN_INPUT_METHOD_QUERY = 'query';
    const TOKEN_INPUT_METHOD_REQUEST = 'request';

    /**
     * @var string
     */
    private $tokenInputMethod;

    /**
     * @var string
     */
    private $tokenInputKey;

    /**
     * @param string $tokenInputMethod
     * @param string $tokenInputKey
     */
    public function __construct(string $tokenInputMethod, string $tokenInputKey)
    {
        $this->tokenInputMethod = $tokenInputMethod;
        $this->tokenInputKey = $tokenInputKey;
    }

    /**
     * @param Request $request
     * @return string|null
     */
    public function resolve(Request $request)
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
                throw new \InvalidArgumentException('Invalid token input method provided: "%s"', $this->tokenInputMethod);
                break;
        }
    }
}
