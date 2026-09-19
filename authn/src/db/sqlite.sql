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

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS coupons (
    name TEXT PRIMARY KEY NOT NULL,
    valid_from_secs INTEGER NOT NULL,
    valid_from_nsecs INTEGER NOT NULL,
    valid_until_secs INTEGER NOT NULL,
    valid_until_nsecs INTEGER NOT NULL,
    max_usages INTEGER NOT NULL,
    usages INTEGER NOT NULL DEFAULT 0,
    CHECK (length(name) BETWEEN 1 AND 16),
    CHECK (name NOT GLOB '*[^A-Z0-9_-]*'),
    CHECK (valid_from_secs < valid_until_secs
           OR (valid_from_secs = valid_until_secs
               AND valid_from_nsecs < valid_until_nsecs)),
    CHECK (max_usages BETWEEN 0 AND 4294967295),
    CHECK (usages BETWEEN 0 AND max_usages)
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY NOT NULL,
    username TEXT UNIQUE,
    password TEXT,
    email TEXT UNIQUE NOT NULL,
    coupon TEXT REFERENCES coupons (name),
    activation_code INTEGER,
    last_login_secs INTEGER,
    last_login_nsecs INTEGER,
    CHECK ((last_login_secs IS NULL AND last_login_nsecs IS NULL)
           OR (last_login_secs IS NOT NULL AND last_login_nsecs IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token TEXT PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL REFERENCES users (id),
    login_time_secs INTEGER NOT NULL,
    login_time_nsecs INTEGER NOT NULL,
    logout_time_secs INTEGER,
    logout_time_nsecs INTEGER
);
