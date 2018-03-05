// This module exports functions that give access to the auth API hosted at openshift.io.
// It uses the axios javascript library for making the actual HTTP requests.
define(['axios'] , function (axios) {
  function merge(obj1, obj2) {
    var obj3 = {};
    for (var attrname in obj1) { obj3[attrname] = obj1[attrname]; }
    for (var attrname in obj2) { obj3[attrname] = obj2[attrname]; }
    return obj3;
  }

  return function (scheme, host, timeout) {
    scheme = scheme || 'http';
    host = host || 'openshift.io';
    timeout = timeout || 20000;

    // Client is the object returned by this module.
    var client = axios;

    // URL prefix for all API requests.
    var urlPrefix = scheme + '://' + host;

  // create a user using a service account
  // path is the request path, the format is "/api/users"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.CreateUsers = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Delete the external token for resources belonging to external providers like Github and OpenShift
  // path is the request path, the format is "/api/token"
  // for is used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.DeleteToken = function (path, for, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'delete',
      params: {
        for: for
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Obtain a security token
  // path is the request path, the format is "/api/token"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.ExchangeToken = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Get the external token for resources belonging to external providers like Github and OpenShift
  // path is the request path, the format is "/api/token"
  // for, force_pull are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.RetrieveToken = function (path, for, force_pull, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        for: for,
        force_pull: force_pull
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Check if the external token is available. Returns 200 OK if the token is available and 401 Unauthorized if no token available
  // path is the request path, the format is "/api/token/status"
  // for, force_pull are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.StatusToken = function (path, for, force_pull, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        for: for,
        force_pull: force_pull
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Add a user to the list of space collaborators.
  // path is the request path, the format is "/api/spaces/:spaceID/collaborators/:identityID"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.addCollaborators = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Add users to the list of space collaborators.
  // path is the request path, the format is "/api/spaces/:spaceID/collaborators"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.add-manyCollaborators = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Authorize service client
  // path is the request path, the format is "/api/authorize"
  // api_client, client_id, redirect_uri, response_mode, response_type, scope, state are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.authorizeAuthorize = function (path, api_client, client_id, redirect_uri, response_mode, response_type, scope, state, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        api_client: api_client,
        client_id: client_id,
        redirect_uri: redirect_uri,
        response_mode: response_mode,
        response_type: response_type,
        scope: scope,
        state: state
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Authorize service client callback
  // path is the request path, the format is "/api/authorize/callback"
  // code, state are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.callbackAuthorize = function (path, code, state, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        code: code,
        state: state
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Callback from an external oauth2 resource provider such as GitHub as part of user's account linking
  // path is the request path, the format is "/api/token/link/callback"
  // code, state are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.callbackToken = function (path, code, state, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        code: code,
        state: state
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Create a new organization
  // path is the request path, the format is "/api/organizations"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.createOrganization = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Create a space resource for the giving space
  // path is the request path, the format is "/api/spaces/:spaceID"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.createSpace = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Delete a resource
  // path is the request path, the format is "/api/resource/:resourceId"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.deleteResource = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'delete',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Delete a space resource for the given space ID
  // path is the request path, the format is "/api/spaces/:spaceID"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.deleteSpace = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'delete',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Generate a set of Tokens for different Auth levels. NOT FOR PRODUCTION. Only available if server is running in dev mode
  // path is the request path, the format is "/api/token/generate"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.generateToken = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Returns public keys which should be used to verify tokens
  // path is the request path, the format is "/api/token/keys"
  // format is used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.keysToken = function (path, format, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        format: format
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Get a redirect location which should be used to initiate account linking between the user account and an external resource provider such as GitHub
  // path is the request path, the format is "/api/token/link"
  // for, redirect are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.linkToken = function (path, for, redirect, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        for: for,
        redirect: redirect
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // List collaborators for the given space ID.
  // path is the request path, the format is "/api/spaces/:spaceID/collaborators"
  // page[limit], page[offset] are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.listCollaborators = function (path, page[limit], page[offset], config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        page[limit]: page[limit],
        page[offset]: page[offset]
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Lists organizations that the user has access to
  // path is the request path, the format is "/api/organizations"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.listOrganization = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // List available roles by resource type
  // path is the request path, the format is "/api/roles"
  // resource_type is used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.listRoles = function (path, resource_type, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        resource_type: resource_type
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // List all users.
  // path is the request path, the format is "/api/users"
  // filter[email], filter[username] are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.listUsers = function (path, filter[email], filter[username], config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        filter[email]: filter[email],
        filter[username]: filter[username]
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // List assigned roles by resource
  // path is the request path, the format is "/api/resources/:resourceID/roles/assigned"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.listAssignedResource_roles = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Login user
  // path is the request path, the format is "/api/login"
  // api_client, redirect, scope are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.loginLogin = function (path, api_client, redirect, scope, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        api_client: api_client,
        redirect: redirect,
        scope: scope
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Logout user
  // path is the request path, the format is "/api/logout"
  // redirect is used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.logoutLogout = function (path, redirect, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        redirect: redirect
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Read a specific resource
  // path is the request path, the format is "/api/resource/:resourceId"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.readResource = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Refresh access token
  // path is the request path, the format is "/api/token/refresh"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.refreshToken = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Register a new resource
  // path is the request path, the format is "/api/resource"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.registerResource = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'post',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Remove a user from the list of space collaborators.
  // path is the request path, the format is "/api/spaces/:spaceID/collaborators/:identityID"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.removeCollaborators = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'delete',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Remove users form the list of space collaborators.
  // path is the request path, the format is "/api/spaces/:spaceID/collaborators"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.remove-manyCollaborators = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'delete',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Get clusters configuration
  // path is the request path, the format is "/api/clusters/"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showClusters = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Show Indentity Provider Configuration. It lists all endpoints supported by Auth Service
  // path is the request path, the format is "/api/.well-known/openid-configuration"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showOpenid_configuration = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Show the status of the current running instance
  // path is the request path, the format is "/api/status"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showStatus = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Get the authenticated user
  // path is the request path, the format is "/api/user"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showUser = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Get the authenticated user
  // path is the request path, the format is "/api/userinfo"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showUserinfo = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Retrieve user for the given ID.
  // path is the request path, the format is "/api/users/:id"
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.showUsers = function (path, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Update the details of the specified resource
  // path is the request path, the format is "/api/resource/:resourceId"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.updateResource = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'patch',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // update the authenticated user
  // path is the request path, the format is "/api/users"
  // data contains the action payload (request body)
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.updateUsers = function (path, data, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'patch',
    data: data,
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Search by fullname
  // path is the request path, the format is "/api/search/users"
  // page[limit], page[offset], q are used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.usersSearch = function (path, page[limit], page[offset], q, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        page[limit]: page[limit],
        page[offset]: page[offset],
        q: q
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }

  // Verify if the new email updated by the user is a valid email
  // path is the request path, the format is "/api/users/verifyemail"
  // code is used to build the request query string.
  // config is an optional object to be merged into the config built by the function prior to making the request.
  // The content of the config object is described here: https://github.com/mzabriskie/axios#request-api
  // This function returns a promise which raises an error if the HTTP response is a 4xx or 5xx.
  client.verifyEmailUsers = function (path, code, config) {
    var cfg = {
      timeout: timeout,
      url: urlPrefix + path,
      method: 'get',
      params: {
        code: code
      },
      responseType: 'json'
    };
    if (config) {
      cfg = merge(cfg, config);
    }
    return client(cfg);
  }
  return client;
  };
});
