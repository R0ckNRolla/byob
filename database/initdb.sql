
/*	Copyright (c) 2017 Angry Eggplant (https://github.com/colental/ae)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


-- create the Angry Eggplant database
CREATE DATABASE IF NOT EXISTS `ae`;

-- create the client table 
CREATE TABLE IF NOT EXISTS `ae.tbl_clients` (
  `id` text NOT NULL,
  `ip` text,
  `mac` text,
  `encryption` text,
  `local` text,
  `username` text,
  `administrator` text,
  `platform` text,
  `device` text,
  `architecture` text,
  `email` text,
  `password` text,
  `last_update` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(64)),
  KEY `last_update` (`last_update`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- create the session table 
CREATE TABLE IF NOT EXISTS `ae.tbl_sessions` (
  `id` text NOT NULL,
  `session` tinyint(11),
  `client` text,
  `session_key` text,
  `public_key` text,
  `private_key` text,
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(64)),
  KEY `last_update` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- create the task table 
CREATE TABLE IF NOT EXISTS `ae.tbl_tasks` (
  `task` text NOT NULL,
  `session` text,
  `client` text,
  `command` text,
  `result` text,
  `completed` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`task`(64)),
  KEY `task` (`completed`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
