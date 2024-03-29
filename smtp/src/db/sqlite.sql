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

CREATE TABLE IF NOT EXISTS email_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    sent_sec INTEGER NOT NULL,
    sent_nsec INTEGER NOT NULL,
    message BYTEA NOT NULL,
    result TEXT
);

CREATE INDEX email_log_by_sent ON email_log (sent_sec, sent_nsec);
