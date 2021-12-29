<?php

namespace Darkink\OpenIdServer\Repositories;

use Darkink\OpenIdServer\Models\ResourceScope;
use Darkink\OpenIdServer\OpenIdServer;
use Laravel\Passport\Bridge\ScopeRepository as PassportScopeRepository;

class ScopeRepository extends PassportScopeRepository
{
    public function getScopeEntityByIdentifier($identifier)
    {
        if (array_key_exists($identifier, OpenIdServer::$resourceScopes)) {
            return new ResourceScope($identifier);
        }
        return parent::getScopeEntityByIdentifier($identifier);
    }
}
