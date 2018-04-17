#!/usr/bin/mysql
#
# BYOB (Build Your Own Botnet)
# https://github.com/colental/byob
# Copyright (c) 2018 Daniel Vega-Myhre

# create byob database if it doesnt exist
CREATE DATABASE IF NOT EXISTS `byob`;
use `byob`;

# create clients table if it does not exist
CREATE TABLE IF NOT EXISTS `tbl_clients` (
  `id` varchar(32) NOT NULL,
  `public_ip` varchar(42) NOT NULL,
  `mac_address` varchar(17) DEFAULT NULL,
  `local_ip` varchar(42) DEFAULT NULL,
  `username` text DEFAULT NULL,
  `administrator` text DEFAULT NULL,
  `platform` text DEFAULT NULL,
  `device` text DEFAULT NULL,
  `architecture` text DEFAULT NULL,
  `last_online` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `last_session` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`(32))
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


# create sessions table if it does not exist
CREATE TABLE IF NOT EXISTS `tbl_sessions` (
  `id` varchar(32) NOT NULL,
  `client` varchar(32) ,
  `session_key` text NOT NULL,
  `duration` text DEFAULT NULL,
  PRIMARY KEY (`id`(32))
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


# create tasks table if it does not exist
CREATE TABLE IF NOT EXISTS `tbl_tasks` (
  `id` varchar(32) NOT NULL,
  `session` varchar(32) ,
  `client` varchar(32) ,
  `task` text NOT NULL,
  `result` text DEFAULT NULL,
  `completed` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(32))
) ENGINE=MyISAM DEFAULT CHARSET=latin1;



# create stored procedure for adding new clients
DROP procedure IF EXISTS `sp_addClient`;
DELIMITER $$
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


#create stored procedure for adding new sessions
DROP procedure IF EXISTS `sp_addSession`;
DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addSession`(
    IN session_id varchar(32),
    IN client_id varchar(32),
    IN client_session_key text
)
BEGIN
    insert into tbl_sessions
    (
    id,
    client,
    session_key
    )
    values (
    session_id,
    client_id,
    client_session_key
    );
END$$
DELIMITER ;

# create stored procedure for adding task results
DROP procedure IF EXISTS `sp_addTask`;
DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `sp_addTask`(
    IN task_client_id varchar(32),
    IN task_session_id varchar(32),
    IN task_command text,
    OUT task varchar(32)
)
BEGIN
    DECLARE task_id varchar(32) DEFAULT NULL;
    SET task_id = MD5(concat(task_client_id, task_session_id, task_command, NOW()));
    insert into tbl_tasks
    (
    id,
    client,
    session,
    task
    )
    values
    (
    task_id,
    task_client_id,
    task_session_id,
    task_command
    );
    SELECT id INTO task FROM tbl_tasks WHERE id = task_id;
END$$
DELIMITER ;


