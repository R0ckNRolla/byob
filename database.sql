#!/usr/bin/mysql


-- The Angry Eggplant Project --


#	DATABASE
--		`ae`

#	TABLES
--		`tbl_clients`
--		`tbl_sessions`
--		`tbl_tasks`

#	STORED PROCEDURES
--		`sp_addClient`
--		`sp_addSession`
--		`sp_addTask`
--		`sp_selectClient`
--		`sp_selectSession`
--		`sp_selectTasks`
--		`sp_updateClient`



-- DATABASE --

# ae

CREATE DATABASE IF NOT EXISTS `ae`;
use `ae`;


-- TABLES --

# tbl_clients

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

# tbl_sessions

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

# tbl_tasks

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


-- STORED PROCEDURES --

# sp_selectClient

DROP procedure IF EXISTS `ae`.`sp_selectClient`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_selectClient`(
    IN client_id varchar(32)
)
BEGIN
  	SELECT * FROM tbl_clients WHERE id=client_id;
END$$
DELIMITER ;

# sp_selectSession

DROP procedure IF EXISTS `ae`.`sp_selectSession`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_selectSession`(
    IN session_id varchar(32)
)
BEGIN
  	SELECT * FROM tbl_sessions WHERE id=session_id;
END$$
DELIMITER ;


# sp_selectSession

DROP procedure IF EXISTS `ae`.`sp_selectTasks`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_selectTasks`(
    IN client_id varchar(32)
)
BEGIN
  	SELECT * FROM tbl_tasks WHERE client=client_id;
END$$
DELIMITER ;


# sp_updateClient

DROP procedure IF EXISTS `ae`.`sp_updateClient`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_updateClient`(
    IN client_id varchar(32)
)
BEGIN
  	UPDATE tbl_clients SET last_update=NOW() WHERE id=client_id;
END$$
DELIMITER ;

# sp_addClient

DROP procedure IF EXISTS `ae`.`sp_addClient`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addClient`(
    IN client_id varchar(32),
    IN client_mac_address varchar(17),
    IN client_public_ip varchar(42),
    IN client_local_ip varchar(42),    
    IN client_username text,
    IN client_administrator text,
    IN client_platform text,
    IN client_architecture text,
    IN client_device text
)
BEGIN
    insert into tbl_clients(
    id,
    mac_address,
    public_ip,
    local_ip,
	username,
	administrator,
	platform,
	architecture,
	device,
	last_update
    )
    values
    (
    client_id, 
	client_mac_address,
	client_public_ip,
	client_local_ip,
	client_username,
	client_administrator,
	client_platform,
	client_architecture,
	client_device,
	NOW()
    );
END$$
DELIMITER ;

# sp_addSession

DROP procedure IF EXISTS `ae`.`sp_addSession`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addSession`(
    IN session_id varchar(32),
    IN client_id varchar(32),
    IN client_private_key text,
    IN client_public_key text,    
    IN client_timestamp TIMESTAMP
)
BEGIN
    insert into tbl_sessions
	(
    id,
	client,
	private_key,
	public_key,
	timestamp
    )
    values
    (
	session_id,
	client_id,
	client_private_key,
	client_public_key,
	client_timestamp
    );
END$$
DELIMITER ;

# sp_addTask

DROP procedure IF EXISTS `ae`.`sp_addTask`; 
DELIMITER $$
USE `ae`$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addTask`(
    IN task_id varchar(32),
    IN task_client_id varchar(32),
    IN task_session_id varchar(32),
    IN task_command text,    
    IN task_completed TIMESTAMP
)
BEGIN
    insert into tbl_tasks
	(
    task,
	client,
	session,
	command,
	completed
    )
    values
    (
	task_id,
	task_client_id,
	task_session_id,
	task_command,
	task_completed
    );
END$$
DELIMITER ;




