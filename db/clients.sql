CREATE TABLE IF NOT EXISTS `clients` (
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
  `last_update` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`(64)),
  KEY `last_update` (`last_update`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
