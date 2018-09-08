CREATE TABLE IF NOT EXISTS `swag_oauth_access_token` (
  `id`                  BINARY(16)   NOT NULL,
  `tenant_id`           BINARY(16)   NOT NULL,
  `context_token`       VARCHAR(255) NOT NULL,
  `x_sw_access_key`     VARCHAR(255) NOT NULL,
  `access_token`        VARCHAR(2000) NOT NULL,
  `expires`             DATETIME(3)  NOT NULL,
  PRIMARY KEY (`id`, `tenant_id`)
);

CREATE TABLE IF NOT EXISTS `swag_oauth_refresh_token` (
  `id` BINARY(16) NOT NULL,
  `tenant_id` BINARY(16) NOT NULL,
  `refresh_token` VARCHAR(250) NOT NULL,
  `integration_id` BINARY(16) NOT NULL,
  `integration_tenant_id` BINARY(16) NOT NULL,
  `context_token` VARCHAR(255) NOT NULL,
  `expires` DATETIME(3),
  PRIMARY KEY (`id`, `tenant_id`),
  FOREIGN KEY (`integration_id`, `integration_tenant_id`) REFERENCES integration (`id`, `tenant_id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS `swag_oauth_authorization_code` (
  `id` BINARY(16) NOT NULL,
  `tenant_id` BINARY(16) NOT NULL,
  `authorization_code` VARCHAR(250) NOT NULL,
  `integration_id` BINARY(16) NOT NULL,
  `integration_tenant_id` BINARY(16) NOT NULL,
  `redirect_uri` VARCHAR(2000),
  `expires` DATETIME(3) NOT NULL,
  `swag_oauth_refresh_token_id` BINARY(16),
  `swag_oauth_refresh_token_tenant_id` BINARY(16),
  `context_token` VARCHAR(255) NOT NULL,
  PRIMARY KEY (`id`, `tenant_id`),
  FOREIGN KEY (`integration_id`,  `integration_tenant_id`) REFERENCES integration(`id`, `tenant_id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  FOREIGN KEY (`swag_oauth_refresh_token_id`, `swag_oauth_refresh_token_tenant_id`) REFERENCES swag_oauth_refresh_token(`id`, `tenant_id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
);
