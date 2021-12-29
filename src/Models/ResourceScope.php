<?php

namespace Darkink\OpenIdServer\Models;

use Laravel\Passport\Bridge\Scope;

class ResourceScope extends Scope
{
    public function __construct($id)
    {
        parent::__construct($id);
    }
}
