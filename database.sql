#!/usr/bin/mysql
#
# The Angry Eggplant Project
# https://github.com/colental/ae
#
# Copyright (c) 2017 Daniel Vega-Myhre
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


#	`angryeggplant`
#		type: database


CREATE DATABASE IF NOT EXISTS `ae`;
use `ae`;


#	`tbl_clients`
#		type: table


CREATE TABLE IF NOT EXISTS `tbl_clients` (
  `id` text NOT NULL,
  `public_ip` text ,
  `mac_address` text ,
  `local_ip` text ,
  `username` text ,
  `administrator` text ,
  `platform` text ,
  `device` text ,
  `architecture` text ,
  `last_update` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(32)),
  KEY `last_update` (`last_update`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


#	`tbl_sessions`	
#		type: table


CREATE TABLE IF NOT EXISTS `tbl_sessions` (
  `id` text NOT NULL,
  `client` text ,
  `session_key` text ,
  `public_key` text ,
  `private_key` text ,
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(32)),
  KEY `last_update` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


#	`tbl_tasks`
#		type: table

CREATE TABLE IF NOT EXISTS `tbl_tasks` (
  `id` text NOT NULL,
  `session` text ,
  `client` text ,
  `command` text ,
  `result` text ,
  `completed` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(32)),
  KEY `task` (`completed`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


#	`sp_addClient`
#		type: stored procedure	
#		usage: CALL sp_addClient(
#			client_id, 
#			public_ip, 
#			local_ip, 
#			mac_address, 
#			username, 
#			administrator, 
#			device, 
#			platform,
#			architecture
#		);



DROP procedure IF EXISTS `ae`.`sp_addClient`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addClient`(
    IN client_id varchar(32),
    IN client_public_ip varchar(42),
    IN client_local_ip varchar(42),    
    IN client_mac_address varchar(17),
    IN client_username text,
    IN client_administrator text,
    IN client_device text,
    IN client_platform text,
    IN client_architecture text
)
BEGIN
    insert into tbl_clients(
    id,
    public_ip,
    local_ip,
    mac_address,
    username,
    administrator,
    device,
    platform,
    architecture
    )
    values
    (
    client_id, 
    client_public_ip,
    client_local_ip,
    client_mac_address,
    client_username,
    client_administrator,
    client_device,
    client_platform,
    client_architecture
    );
END$$
DELIMITER ;


#	`sp_addSession`
#		type: stored procedure
#		usage: CALL sp_addSession(
#			session_id, 
#			client_id, 
#			session_key, 
#			public_key,
#			private_key
#		);



DROP procedure IF EXISTS `ae`.`sp_addSession`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addSession`(
    IN session_id varchar(32),
    IN client_id varchar(32),
	IN client_session_key text,
    IN client_public_key text,
    IN client_private_key text
)
BEGIN
    insert into tbl_sessions
	(
    id,
	client,
	session_key,
	public_key,
	private_key
	)
    values (
	session_id,
	client_id,
	client_session_key,
	client_public_key,
	client_private_key
	);
END$$
DELIMITER ;


#	`sp_addTask`
#		type  stored procedure 
#		usage: CALL sp_addTask(
#				task_id, 
#				client_id, 
#				session_id, 
#				command, 
#				result
#			);


DROP procedure IF EXISTS `ae`.`sp_addTask`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addTask`(
    IN task_id varchar(32),
    IN task_client_id varchar(32),
    IN task_session_id varchar(32),
    IN task_command text, 
	IN task_result text
)
BEGIN
    insert into tbl_tasks
	(
    id,
	client,
	session,
	command,
	result
    )
    values
    (
	task_id,
	task_client_id,
	task_session_id,
	task_command,
	task_result
    );
END$$
DELIMITER ;
