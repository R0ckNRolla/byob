#!/usr/bin/mysql

CREATE DATABASE IF NOT EXISTS `ae`;

use `ae`;

CREATE TABLE IF NOT EXISTS `tbl_clients` (
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


DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_createUser`(
	IN client_id VARCHAR(20), 
	IN client_session VARCHAR(20), 
	IN client_ VARCHAR(20)
)
BEGIN
    if ( select exists (select * from tbl_clients where id=p_username) ) THEN
        select 'Client a';
    ELSE
        insert into tbl_clients
        (
            user_name,
            user_username,
            user_password
        )
        values
        (
            p_name,
            p_username,
            p_password
        );
    END IF;
END$$
DELIMITER ;