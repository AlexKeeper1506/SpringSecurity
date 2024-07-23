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

CREATE TABLE IF NOT EXISTS groups(
    id         BIGINT NOT NULL PRIMARY KEY,
    group_name VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS group_authorities(
    group_id  BIGINT NOT NULL REFERENCES groups(id),
    authority VARCHAR(50) NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members(
    id       BIGINT NOT NULL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    group_id BIGINT NOT NULL REFERENCES groups(id)
);

INSERT INTO users(username, password, enabled)
VALUES
    (
        'admin',
        '{bcrypt}$2a$10$3QCbbXpTQoQmCLwul8AcKuIh/xly8xFZVr7HDk2rCTiuJKkHnUcM6',
        true
    ),
    (
        'user',
        '{bcrypt}$2a$10$NjvaXm3ejL28gUGVcbxJVOAz/NIevnGQ1DJaeRGg7nZ5tZdC6sozu',
        true
    );

INSERT INTO authorities(username, authority)
VALUES ('admin', 'ROLE_ADMIN'),
       ('user',  'ROLE_USER');