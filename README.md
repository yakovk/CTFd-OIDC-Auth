# CTFd OIDC Authentication Plugin

Add OpenID Connect (OIDC) authentication to CTFd 2.x using compatible providers. Users can be linked between the CTFd User database and the OIDC provider; these users can be created on the fly or not.


**This plugin is still in development and may not work properly in your configuration.**

✅ `Authlib` is required.
✅ `Loginpass` is required.

## Supported Providers:
* `azure` (Azure Active Directory)
* Other OIDC providers supported by Authlib


## Configuration

The following configuration options must be provided via environment:

### Common
```
OIDC_LOGIN_BACKEND - What OIDC backend to use. Defaults to "None" and will not load the plugin.
OIDC_CREATE_MISSING_USER - Whether to create missing users in CTFd database. Defaults to "False".
```
### Provider-specific

Azure Active Directory:
```
AZURE_CLIENT_ID - Azure Active Directory Client ID
AZURE_CLIENT_SECRET - Azure Active Directory Client Secret
AZURE_TENANT_ID - Azure Active Directory Tenant
```