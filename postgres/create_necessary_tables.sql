CREATE TABLE IF NOT EXISTS persistent_logins(
    username  VARCHAR(64) NOT NULL,
    series    VARCHAR(64) NOT NULL PRIMARY KEY,
    token     VARCHAR(64) NOT NULL,
    last_used TIMESTAMP WITHOUT TIME ZONE NOT NULL
);

CREATE TABLE IF NOT EXISTS users(
    username VARCHAR(50) NOT NULL PRIMARY KEY ,
    password TEXT NOT NULL,
    enabled  BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS authorities(
    username  VARCHAR(50) NOT NULL REFERENCES users(username),
    authority VARCHAR(50) NOT NULL
);

CREATE UNIQUE INDEX ix_auth_username
ON authorities(username, authority);