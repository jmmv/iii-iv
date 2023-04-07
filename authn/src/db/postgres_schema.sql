-- III-IV
-- Copyright 2023 Julio Merino
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may not
-- use this file except in compliance with the License.  You may obtain a copy
-- of the License at:
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
-- License for the specific language governing permissions and limitations
-- under the License.

CREATE TABLE IF NOT EXISTS users (
    -- The user's chosen username.
    username VARCHAR(32) PRIMARY KEY NOT NULL,

    -- The user's hashed password using the bcrypt algorithm.
    -- May be null, in which case the user is denied login.
    password VARCHAR(60),

    -- The user's email address.
    email VARCHAR(64) UNIQUE NOT NULL,

    -- Activation code.  If present, the account has not been activated yet.
    activation_code INT,

    -- The user's last successful login timestamp.
    last_login TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token CHAR(256) PRIMARY KEY NOT NULL,

    username VARCHAR(32) NOT NULL REFERENCES users (username),

    login_time TIMESTAMPTZ NOT NULL,

    -- Logout time, if known.  Sessions have a maximum validity time as enforced by the driver
    -- but users can also explicitly log out.
    logout_time TIMESTAMPTZ
);
