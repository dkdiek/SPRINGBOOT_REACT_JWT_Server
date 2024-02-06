--기존 테이블 존재하면 삭제
drop table if exists user;

create table `user` (
    `NO` int not null AUTO_INCREMENT,
    `USER_ID` varchar(100) not null,
    `USER_PW` varchar(200) not null,
    `NAME` varchar(100) not null,
    `EMAIL` varchar(200) default null,
    `REG_DATE` timestamp not null default CURRENT_TIMESTAMP,
    `UPD_DATE` timestamp not null default CURRENT_TIMESTAMP,
    `ENABLED` int default 1,
    PRIMARY KEY (`NO`)
) COMMENT='회원';

--BCRYPTPASSWORDENCDER - 암호화 시
--사용자
insert into user(USER_ID,USER_PW,NAME,EMAIL)
values ('user','$2a$12TrN..KcVjciCiz.5Vj96YOB1jeVTTGJ9AUKmtfbGpgc9hmC7BxQ92','사용자','user@mail.com');

--관리자
insert into user(USER_ID,USER_PW,NAME,EMAIL)
values ('admin','$2a$12TrN..KcVjciCiz.5Vj96YOB1jeVTTGJ9AUKmtfbGpgc9hmC7BxQ92','관리자','admin@mail.com');
