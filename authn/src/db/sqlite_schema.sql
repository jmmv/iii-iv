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

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY NOT NULL,
    password TEXT,
    email TEXT UNIQUE NOT NULL,
    activation_code INTEGER,
    last_login_secs INTEGER,
    last_login_nsecs INTEGER,
    CHECK ((last_login_secs IS NULL AND last_login_nsecs IS NULL)
           OR (last_login_secs IS NOT NULL AND last_login_nsecs IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS sessions (
    access_token TEXT PRIMARY KEY NOT NULL,
    username TEXT NOT NULL REFERENCES users (username),
    login_time_secs INTEGER NOT NULL,
    login_time_nsecs INTEGER NOT NULL,
    logout_time_secs INTEGER,
    logout_time_nsecs INTEGER
);
