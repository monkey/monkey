int mk_net_ipv4_listen(const char *addr, unsigned int port, int backlog)
{
	struct sockaddr_in sa;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if(fd == -1)
		return -1;

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(addr);

	memset(&sa.sin_zero, 0, sizeof(sa.sin_zero));

	if(bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		goto error;

	if(listen(fd, backlog) == -1)
		goto error;

	return fd;

error:
	close(fd);
	return -1;
}
