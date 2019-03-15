# bulletin-board-tutorial
#golang #bulletinboard #mariadb

go언어로 작성된 간단한 게시판입니다

# DB 설정
CREATE TABLE `txt` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(20) NOT NULL,
  `time` bigint(20) DEFAULT NULL,
  `body` varchar(128) DEFAULT NULL,
  `writer` varchar(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
)
CREATE TABLE `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(10) DEFAULT NULL,
  `password` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`)
) 

# 실행방법
실행파일 "username:password@protocol(address)/dbname?param=value"
