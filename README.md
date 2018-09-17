## Example Plugin for the new Core and Administration.

**Note: This plugins only works with the Shopware Platform** (see: https://github.com/shopware/development)

## Setup:

- Move plugin to custom/plugins
- Run bin/console plugin:update
- Run bin/console plugin:install --activate SwagOAuth
- Run bin/console cache:clear

## Configuration example for Insomnia (https://insomnia.rest/)
- Create a new Integration (Admin → Settings → Integration)
- Create a new Request in Insomnia
- Route e.g. https://shopware.local/storefront-api/customer
- Auth → OAuth 2
    - Grant Type: Authorization Code
    - Authorization URL: https://shopware.local/customer/oauth/authorize
    - Access Token URL https://shopware.local/customer/oauth/token
    - Client ID: Access Key ID of the integration
    - Client Secret: Secret Access Key of the integration
    - Redirect Url: some text (irrelevant for insomnia)
    - (Optional) state: some text (CSRF)
    - Credentials: As Basic Auth Header
    - "Fetch Tokens"
    - Log in with your customer data of the shop
- Fetch data from route "Send"