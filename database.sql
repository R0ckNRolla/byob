#!/usr/bin/mysql

CREATE DATABASE IF NOT EXISTS `ae`;

use `ae`;

CREATE TABLE IF NOT EXISTS `tbl_clients` (
  `id` text NOT NULL,
  `ip` text,
  `mac` text,
  `local` text,
  `username` text,
  `administrator` text,
  `platform` text,
  `device` text,
  `architecture` text,
  `credentials` text,
  `last_update` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(64)),
  KEY `last_update` (`last_update`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `tbl_sessions` (
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

CREATE TABLE IF NOT EXISTS `tbl_tasks` (
  `task` text NOT NULL,
  `session` text,
  `client` text,
  `command` text,
  `result` text,
  `completed` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`task`(64)),
  KEY `task` (`completed`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
