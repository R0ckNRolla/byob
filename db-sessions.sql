CREATE TABLE IF NOT EXISTS `sessions` (
  `id` text NOT NULL,
  `session` tinyint(11),
  `client` text,
  `session_key` text,
  `public_key` text,
  `private_key` text,
  `timestamp` NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(64)),
  KEY `last_update` (`timestamp`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;