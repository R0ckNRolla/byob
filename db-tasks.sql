CREATE TABLE IF NOT EXISTS `sessions` (
  `task` text NOT NULL,
  `session` text,
  `client` text,
  `command` text,
  `result` text,
  `completed` NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`task`(64)),
  KEY `task` (`completed`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
