--기존 테이블 존재하면 삭제
drop table if exists user_auth;

--user_auth : 권한 테이블
create table `user_auth`(
    auth_no int not null AUTO_INCREMENT
    ,user_id varchar(100) not null
    ,auth varchar(100) not null
    ,primary key (auth_no)
);

--기본 데이터
--사용자
--*권한:user
insert into user_auth(user_id,auth)
values ('user','ROLE_USER');

--관리자
--*권한:user,admin
insert into user_auth (user_id, auth)
values ('admin','ROLE_USER');

insert into user_auth (user_id, auth)
values ('admin','ROLE_ADMIN');