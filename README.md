# DunglasAngularCsrfBundle

This [Symfony 2](http://symfony.com) bundle provides automatic [Cross Site Request Forgery](http://en.wikipedia.org/wiki/Cross-site_request_forgery) (CSRF or XSRF) protection for client-side [AngularJS](http://angularjs.org/) applications.
It can also be used to secure apps using jQuery or raw JavaScript issuing [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest).

## How it works

AngularJS' `ng.$http` service has [a built-in CSRF protection system](http://docs.angularjs.org/api/ng.$http#description_security-considerations_cross-site-request-forgery-protection).
To enable it, the server-side application (the Symfony app) must set a cookie containing a XSRF token on the first HTTP request.
Subsequent XHR requests made by AngularJS will provide a special HTTP header containing the value of the cookie.

To prevent CSRF attacks, the server-side application must check that the header's value match the cookie's value.

This bundle provides a (Symfony's Event Listener)[http://symfony.com/doc/current/cookbook/service_container/event_listener.html] that set the cookie and another one that checks the HTTP header to block CSRF attacks.
Thanks to DunglasAngularCsrfBundle, you get CSRF security without modifying your code base.

This bundle works fine with [FOSRestBundle](https://github.com/FriendsOfSymfony/FOSRestBundle).

## Installation

Use [Composer](http://getcomposer.org/) to install this bundle:

    composer require dunglas/angular-csrf-bundle

Add the bundle in your application kernel:

```php
// app/AppKernel.php

public function registerBundles()
{
    return array(
        // ...
        new Dunglas\AngularCsrfBundle\DunglasAngularCsrfBundle(),
        // ...
    );
}
```

Configure URLs where the cookie must be set and that must be protected against CSRF attacks:

```yaml
# app/config/security.yml

dunglas_angular_csrf:
  # Collection of patterns where to set the cookie
  cookie:
      set_on:
          - ^/$
  # Collection of patterns to secure
  secure:
    - ^/api
```

Your Symfony/AngularJS app is now secured.

## Full configuration

```yaml
dunglas_angular_csrf:
  token:
      # The CSRF token id
      id: angular
  header:
      # The name of the HTTP header to check (default to the AngularJS default)
      name: X-XSRF-TOKEN
  cookie:
      # The name of the cookie to set (default to the AngularJS default)
      name: XSRF-TOKEN
      # Expiration time of the cookie
      expire: 0
      # Path of the cookie
      path: /
      # Domain of the cookie
      domain: ~
      # If true, set the cookie only on HTTPS connection
      secure: false
      # Patterns of URLs to set the cookie
      set_on:
          - ^/$
  # Patterns of URLs to check for a valid CSRF token
  secure:
    - ^/api
```

## Credits

This bundle has been written by [Kévin Dunglas](http://dunglas.fr).