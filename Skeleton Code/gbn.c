#include "gbn.h"

state_t s;

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
    printf("creating packet with size %i\n", (int)sizeof(gbnhdr));
	gbnhdr *packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = seqnum;

    // if just a header, ignore check sum
	if (isHeader == 0) {
		packet->checksum = 0;
	}
    // otherwise set checksum when sending data packet
	else {
		memcpy(packet->data, buffer, sizeof(buffer));

		packet->checksum = checksum((uint16_t *) buffer, datalen);
	}
	return packet;
}

int check_packet(gbnhdr *packet, int type) {
	//check time out
	if (s.timed_out == 0) {
        printf("timed out\n");
        // reset time out flag
        s.timed_out = -1;
        return -1;
    }

    // check packet type
    if (packet->type != type) {
		return -1;
	}
	return 0;
}

int check_seqnum(gbnhdr *packet, int expected) {
    // on sender side: acked packet should be equal to or greater than current seqnum
    // if received an ack with seqnum less than current seqnum, either last packet was lost, or last ack was lost

    // on receiver side: packet seqnum received should be next expected seqnum
    if (packet->seqnum != expected) {
        printf("expected seqnum %i but received seqnum %i\n", packet->seqnum, s.seqnum);
        return -1;
    }
    return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	int attempts = 0;
    s.seqnum = 0;
    s.mode = SLOW;

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

    // split data into multiple packets
    int numPackets = (int) len / DATALEN;

    if (len % DATALEN != 0) {
        numPackets ++;
    }
    printf("in send and ready to send %i packets\n", numPackets);

    char * slicedBuf = (char *) malloc(DATALEN * sizeof(char));

    for (int i=1; i<=numPackets; i++) {
        slicedBuf[DATALEN] = '\0';

        memcpy(slicedBuf, buf, DATALEN);
        printf("sending packet %i\n", i);
        printf("sliced buf %s\n", slicedBuf);
        gbnhdr *packet, *rec_header;

        // slow mode
        if (s.mode == SLOW) {
            printf("in slow mode\n");
            //while no ack received and retries not reached
            while (s.state != DATA_RCVD && attempts < 5) {

                // make packet with buffer data
                packet = make_packet(DATA, s.seqnum, -1, slicedBuf, DATALEN);
                if (sendto(sockfd, packet, sizeof(*packet), flags, senderServerAddr, senderSocklen) == -1) {
                    attempts ++;
                    continue;
                }

                // start timer
                alarm(TIMEOUT);

                printf("sent data with seq num %i\n", s.seqnum);
                s.state = DATA_SENT;

                // receive ack header
                rec_header = malloc(sizeof(gbnhdr));

                recvfrom(sockfd, rec_header, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen);

                // check for timeout and verify type = dataack and seqnum is expected
                if (check_packet(rec_header, DATAACK) == 0 && check_seqnum(rec_header, s.seqnum) == 0) {
                    printf("received dataack\n");
                    s.state = DATA_RCVD;
                    // switch to fast
                    s.mode = FAST;
                    s.seqnum ++;
                }
                else {
                    attempts ++;
                }
                free(packet);
                free(rec_header);
            }

            // if data was sent 5 times without receiving dataack, return -1
            if (attempts == 5) {
                return -1;
            }
        }
        // fast mode
        else {
            printf("in fast mode\n");
            gbnhdr * packet_one = make_packet(DATA, s.seqnum, -1, slicedBuf, DATALEN);

            // send
            if (sendto(sockfd, packet_one, sizeof(packet_one), flags, senderServerAddr, senderSocklen) == -1) {
                return -1;
            }

            // set state to data sent
            s.state = DATA_SENT;
            int firstSeqnum = s.seqnum;
            int secondSeqnum = s.seqnum;
            int isSecondPacket = -1;

            memset(slicedBuf, NULL, DATALEN);

            // only send second packet if there's remaining data
            if (i + 1 < numPackets) {
                secondSeqnum = s.seqnum ++;
                isSecondPacket = 0;
                memcpy(slicedBuf, &buf[(i + 1) * DATALEN], DATALEN);
                gbnhdr *packet_second = make_packet(DATA, s.seqnum, -1, slicedBuf, DATALEN);
                sendto(sockfd, packet_second, sizeof(packet_second), flags, senderServerAddr, senderSocklen);
            }


            while (s.state != DATA_RCVD && attempts < 5) {
                alarm(TIMEOUT);

                rec_header = malloc(sizeof(gbnhdr));

                if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, receiverServerAddr, &receiverSocklen) == -1) {
                    attempts ++;
                    continue;
                }

                // verify time out, check header type
                if (check_packet(rec_header, DATAACK) == 0) {
                    s.state = DATA_RCVD;
                }
            }

            // received ack for second packet, all good
            if (s.state == DATA_RCVD) {
                if (isSecondPacket == 0 && check_seqnum(rec_header, secondSeqnum)) {
                    s.seqnum++;
                    i++;
                }
                    // only received ack for first packet sent
                else if (check_seqnum(rec_header, firstSeqnum)) {
                    s.mode = SLOW;
                }
                free(rec_header);
            }

            if (s.timed_out == 0 || attempts == 5) {
                // switch to slow mode
                s.mode = SLOW;
                s.timed_out = -1;
                if (isSecondPacket == 0) {
                    s.seqnum --;
                }
            }
        }
    }
    printf("end of send\n");
	return len;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	// process buffer data
	printf ("in receive\n");

	gbnhdr * packet = malloc(sizeof(gbnhdr));
    printf("size of packet data is %i\n", (int)sizeof(packet->data));

	recvfrom(sockfd, packet, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen);

    // if a data packet is received, check packet to verify its type
	if (check_packet(packet, DATA) == 0){
		printf("received data packet with seqnum %i\n", packet->seqnum);

        if (check_seqnum(packet, s.rec_seqnum) == -1) {
            printf("received an unexpected seqnum, discarding data...\n");
            return -1;
        }
		// check if data is corrupt
		if (checksum(buf, DATALEN) == -1) {
			printf("data is corrupt\n");
			return -1;
		}

        printf("buffer rec: %s\n", packet->data);
        memcpy(buf, packet->data, DATALEN);

        checksum(buf, DATALEN);

		// reply with dataack header with seqnum received
		gbnhdr *header = make_packet(DATAACK, packet->seqnum, 0, NULL, 0);

		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1) {
			printf ("error sending dataack\n");
			return -1;
		}
        printf("sent dataack\n");

        s.rec_seqnum ++;
		return DATALEN;
	}

    // if a connection teardown request is received, reply with FINACK header
	if (check_packet(packet, FIN) == 0) {
		printf("reply with FINACK header \n");
		gbnhdr *header = make_packet(FINACK, 0, 0, NULL, 0);
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1){
			return -1;
		}
		s.state = FIN_RCVD;
		return 0;
	}

	return -1;

}

int gbn_close(int sockfd){
    printf("in connection close\n");
    printf("state %i\n", s.state);
    // sender initiates connection teardown by sending a FIN header
	if (s.state == ESTABLISHED || s.state == DATA_SENT || s.state == DATA_RCVD) {
		printf("sending fin to close connection \n");
		gbnhdr * header = make_packet(FIN, 0, 0, NULL, 0);
		if (sendto(sockfd, header, sizeof(gbnhdr), 0, senderServerAddr, senderSocklen) == -1){
            return -1;
        }
        s.state = FIN_SENT;
        printf("fin sent to close connection\n");
    }
	// if receiver sees a FIN header, reply with FINACK and close socket connection
	else if (s.state == FIN_SENT) {
        printf("sending finack to close connection \n");
        gbnhdr * header = make_packet(FINACK, 0, 0, NULL, 0);

		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1){
            return -1;
        }
        printf("finack sent to close connection\n");
        close(sockfd);
	}
    return 0;
}

// client initiates connection by sending SYN to server
int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
    // pointer to local struct on sender server where receiver address is stored
    senderServerAddr = (struct sockaddr *)server;
    senderSocklen = socklen;

    // SIGALRM is called after timeout alarm
	signal(SIGALRM, sig_handler);

	if (sockfd < 0) {
		return -1;
	}

	gbnhdr *header = make_packet(SYN, 0, 0, NULL, 0);
    printf("in gbn connect\n");
	int attempt = 0;
    s.timed_out = -1;

    while (attempt < MAX_RETRIES) {
		// send SYN header to initialize connection
		if (sendto(sockfd, header, sizeof(header), 0, server, socklen) == -1 ) {
            printf("send syn failed\n");
			attempt ++;
			continue;
		}

        printf("sent syn header\n");
		s.state = SYN_SENT;

		// start timer and wait for ack

		alarm(TIMEOUT);

        gbnhdr *rec_header = malloc(sizeof(gbnhdr));
		// received an ack from receiver/server
		if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, receiverServerAddr, &receiverSocklen) < 0) {
            printf("error in recvfrom syn ack\n");
            attempt ++;
            continue;
		}

        // check for timeout, check if header type is SYNACK
		if (check_packet(rec_header, SYNACK) == 0) {
            printf("received synack header\n");
            s.state = ESTABLISHED;

            printf("connection established\n");
            return 0;
		}
		attempt ++;
	}
	s.state = CLOSED;
	return -1;
}

int gbn_listen(int sockfd, int backlog){
    printf("in listen\n");
    // wait for sender to initiate connection
	gbnhdr * header = malloc(sizeof(gbnhdr));

	if (recvfrom(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen) == -1) {
        printf("error rec syn from sender\n");
		return -1;
	}

    // check if packet contains SYN header
	if (check_packet(header, SYN) == 0) {
        s.state = SYN_RCVD;
        printf("received syn header\n");

        return 0;
    }
    return -1;
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
    // pointer to local struct on receiver server where sender address is to be stored
    receiverServerAddr = (struct sockaddr *)server;
    receiverSocklen = socklen;

    printf("in bind\n");
    s.timed_out = -1;
	return bind(sockfd, server, socklen);
}

int gbn_socket(int domain, int type, int protocol){

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	return socket(domain, type, protocol);
}

// receiver sends ack
int gbn_accept(int sockfd, struct sockaddr *client, socklen_t socklen){
    s.rec_seqnum = 0;
    printf("in accept\n");
    gbnhdr * header;
    // if connection teardown initiated, reject connection by sending RST
    if (s.state == FIN_SENT) {
         header = make_packet(RST, 0, 0, NULL, 0);
    }

    // accept connection initiation by sending header with SYNACK
    else {
        header = make_packet(SYNACK, 0, 0, NULL, 0);
    }

    if (sendto(sockfd, header, sizeof(header), 0, client, socklen) == -1) {
		return -1;
	}
    printf("sent synack header\n");

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
