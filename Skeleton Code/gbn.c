#include "gbn.h"

uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

void sig_handler(int signum){
	s.timed_out = 0;
	printf("Received signal %d\n", signum);
}

gbnhdr * make_packet(uint8_t type, uint8_t seqnum, int isHeader, char *buffer, int datalen){
	gbnhdr *packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = seqnum;

	if (isHeader == 0) {
		packet->checksum = 0;
	}
	else {
		memcpy(packet->data, buffer, sizeof(buffer));

		packet->checksum = checksum((uint16_t *) buffer, datalen);
	}
	return packet;
}

int check_header(gbnhdr *packet, int type) {

	//check packet type
	if (s.timed_out == 0 || packet->type != type || packet->seqnum < s.seqnum) {
		return -1;
	}
	return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr * dest, socklen_t socklen){
	int attempts = 0;
	// check current state

    // if state
	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	socklen_t socketlen = sizeof(struct sockaddr);
	if (len > DATALEN) {
		// split data into multiple packets
		int numPackets = (int)len / DATALEN;
		if (len % DATALEN != 0) {
			numPackets ++;
		}
		char slicedBuf[DATALEN];
		for (int i=0; i<numPackets; i++) {
			memcpy(slicedBuf, &buf[i*DATALEN], DATALEN);
			slicedBuf[DATALEN] = '\0';
			sendto(sockfd, slicedBuf, DATALEN, flags, dest, socketlen);

	}

	else {
		if (s.mode == SLOW) {

		}
		else {

		}
	}


	if (s.timed_out || attempts == 5) {
		s.mode = SLOW;

	}
	s.state = CLOSED;

	return sendto(sockfd, buf, DATALEN, flags, dest, socklen);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags, struct sockaddr *client, socklen_t socklen){

	// process buffer data

	gbnhdr * packet = malloc(sizeof(gbnhdr));

	recvfrom(sockfd, packet, sizeof(gbnhdr), 0, client, &socklen);


	if (check_header(packet, DATA) == 0){

		// check if data is corrupt
		if (checksum(buf, sizeof(packet->data))) {
			// reject
		}

		// TODO: get data into our buffer



		// reply with dataack (reply with seqnum sent or next seqnum??)

		gbnhdr *header = make_packet(DATAACK, packet->seqnum, 0, NULL, NULL);

		// sendto sender
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, client, socklen) == -1) {
			return -1;
		}
		return sizeof(packet->data);
	}

	if (check_header(packet, FIN) == 0) {
		gbnhdr *header = make_packet(FINACK, 0, 0, NULL, NULL);
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, client, socklen) == -1){
			return -1;
		}
		s.state = FIN_RCVD;
		return 0;
	}

	return -1;

}

int gbn_close(int sockfd){

	if (sockfd == -1){
		return(-1);
	}


	if (s.state == 3) {
		gbnhdr * header = make_packet(FIN, 0, 0, NULL, NULL);
		//return sendto(sockfd, header, sizeof(gbnhdr), 0, clientAddr, clientLen);
	}
	// if finished, end connection
	else if (s.state == 4){
		gbnhdr * header = make_packet(FINACK, 0, 0, NULL, NULL);

		//sendto(sockfd, header, sizeof(gbnhdr), 0, hostAddr, hostLen);
		return close(sockfd);
	}
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	// SIGALRM is called after timeout alarm
	signal(SIGALRM, sig_handler);

	if (sockfd < 0) {
		return -1;
	}

	gbnhdr *header = make_packet(SYN, 0, 0, NULL, NULL);

	int attempt = 0;
	while (attempt < MAX_RETRIES) {
		// send SYN header to initialize connection
		if (sendto(sockfd, header, sizeof(header), 0, server, socklen) == -1 ) {
			attempt ++;
			continue;
		}

		s.state = SYN_SENT;

		// wait for ack

		alarm(TIMEOUT);

		// TODO: set client address globally
		ssize_t rec_size = recvfrom(sockfd, header, sizeof(header), 0, server, &socklen);

		// check for timeout
		if (s.timed_out == 0 || rec_size < 0) {
			s.timed_out = 1;
			attempt ++;
		}

		if (check_header(header, SYNACK) == 0) {
			s.state = ESTABLISHED;
			return 0;
		}
		attempt ++;
	}
	s.state = CLOSED;

	return -1;
}

int gbn_listen(int sockfd, int backlog, struct sockaddr * server, socklen_t socklen){
	gbnhdr * rec_buffer = malloc(sizeof(gbnhdr));

	if (recvfrom(sockfd, rec_buffer, sizeof(gbnhdr), 0, server, &socklen) == -1) {
		return -1;
	}
	return check_header(rec_buffer, SYN);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	return bind(sockfd, server, socklen);
}	

int gbn_socket(int domain, int type, int protocol){
		
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	return socket(domain, type, protocol);
}

// receiver sends ack
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t socklen){
	if (sockfd < 0) {
		return -1;
	}

	gbnhdr * packet = make_packet(SYNACK, 0, 0, NULL, NULL);

	if (sendto(sockfd, packet, sizeof(packet), 0, client, socklen) == -1) {
		return -1;
	}
	return sockfd;
}


ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);
	
	
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
