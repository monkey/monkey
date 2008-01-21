CREATE TABLE log_access(
	id_entry int auto_increment not null primary key,
	ip_client varchar(15),
	date_time datetime,
	method varchar(10),
	uri varchar(255),
	protocol varchar(10),
	response smallint,
	bytes_sent int
);

CREATE TABLE log_error(
        id_entry int auto_increment not null primary key,
        ip_client varchar(15),
        date_time datetime,
        method varchar(10),
        uri varchar(255),
        protocol varchar(10),
        error_code smallint
);
