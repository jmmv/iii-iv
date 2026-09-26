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

CREATE TABLE IF NOT EXISTS coupons (
    -- Canonical, user-facing coupon name.
    name VARCHAR(16) PRIMARY KEY NOT NULL,

    -- Half-open interval during which the coupon can be redeemed.
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,

    -- Maximum and consumed numbers of successful signups.
    max_usages BIGINT NOT NULL,
    usages BIGINT NOT NULL DEFAULT 0,

    CHECK (name ~ '^[A-Z0-9_-]+$'),
    CHECK (valid_from < valid_until),
    CHECK (max_usages BETWEEN 0 AND 4294967295),
    CHECK (usages BETWEEN 0 AND max_usages)
);

CREATE TABLE IF NOT EXISTS users (
    -- Stable internal identifier for the user.
    id UUID PRIMARY KEY NOT NULL,

    -- The user's chosen username.
    -- Null for services that identify users by email address.
    username VARCHAR(32) UNIQUE,

    -- The user's hashed password using the bcrypt algorithm.
    -- May be null, in which case the user is denied login.
    password VARCHAR(60),

    -- The user's email address.
    email VARCHAR(64) UNIQUE NOT NULL,

    -- Coupon used during signup, if any.
    coupon VARCHAR(16) REFERENCES coupons (name),

    -- Activation code.  If present, the account has not been activated yet.
    --
    -- Note that this is supposed to be an u64 so it can show up as negative when persisted
    -- in the database.
    activation_code BIGINT,

    -- The user's last successful login timestamp.
    last_login TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token CHAR(256) PRIMARY KEY NOT NULL,

    user_id UUID NOT NULL REFERENCES users (id),

    login_time TIMESTAMPTZ NOT NULL,

    max_age_secs BIGINT NOT NULL,
    max_age_nsecs INTEGER NOT NULL,

    -- Logout time, if known.  Sessions have a maximum validity time as enforced by the driver
    -- but users can also explicitly log out.
    logout_time TIMESTAMPTZ
);
