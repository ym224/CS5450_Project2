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

// signal handler that sets time out to true
void sig_handler(int signum){
	s.timed_out = 0;
    printf("Timeout has occurred\n");
}

// create packet for sending headers, data and acks
gbnhdr * make_packet(uint8_t type, uint8_t seqnum, int isHeader, char *buffer, int datalen){
    printf("datalen %i\n", datalen);

    gbnhdr *packet = malloc(sizeof(gbnhdr));

	packet->type = type;
	packet->seqnum = seqnum;

    // if just a header, ignore check sum
	if (isHeader == 0) {
		packet->checksum = 0;
	}
    // otherwise set checksum when sending data packet
	else {
		memcpy(packet->data, buffer, datalen);
        packet->datalen = datalen; // need to keep track of the exact size of data to write to output file
        packet->checksum = checksum((uint16_t *) buffer, datalen);
	}
	return packet;
}


int check_timeout() {
    if (s.timed_out == 0) {
        printf("timed out\n");
        // reset time out flag
        s.timed_out = -1;
        return -1;
    }
    return 0;
}

// check packet type is expected
int check_packetType(gbnhdr *packet, int type) {
    // check packet type
    if (packet->type != type) {
		return -1;
	}
	return 0;
}

int check_seqnum(gbnhdr *packet, int expected) {
    // on receiver side: packet seqnum received should be next expected seqnum
    // on sender side: packet seqnum for acks should be last sent seqnum
    if (packet->seqnum != expected) {
        printf("expected seqnum %i but received seqnum %i\n", packet->seqnum, s.seqnum);
        return -1;
    }
    return 0;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){
	int attempts = 0;

    if (&s.seqnum == NULL) {
        s.seqnum = 0;
    }
    if (&s.mode == NULL) {
        s.mode = SLOW;
    }

    // split data into multiple packets
    int numPackets = (int) len / DATALEN;

    if (len % DATALEN != 0) {
        numPackets ++;
    }
    printf("in send and ready to send %i packets\n", numPackets);

    char * slicedBuf = malloc(DATALEN);
    int datalen = (int)len;
    int i;

    for (i=0; i<numPackets; i++) {

        datalen = (int)len - (i*DATALEN);

        if (datalen > DATALEN) {
            datalen = DATALEN;
        }
        memset(slicedBuf, '\0', datalen);

        // copy part or all of char buffer into the new sliced buffer
        memcpy(slicedBuf, buf + i * DATALEN, datalen);

        printf("sending packet %i\n", i);
        gbnhdr *packet, *rec_header;

        // slow mode
        if (s.mode == SLOW) {
            printf("in slow mode\n");
            //while no ack received and retries not reached
            while (s.state != DATA_RCVD && attempts < 5) {

                // make packet with buffer data
                packet = make_packet(DATA, s.seqnum, -1, slicedBuf, datalen);
                printf("sending packet with seqnum %i in slow mode\n", s.seqnum);

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

                // verify there is no timeout, verify type = dataack and seqnum is expected
                if (check_timeout() == 0 && check_packetType(rec_header, DATAACK) == 0 && check_seqnum(rec_header, s.seqnum) == 0) {
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
            gbnhdr * packet_one, *packet_two;
            packet_one = make_packet(DATA, s.seqnum, -1, slicedBuf, datalen);

            printf("sending packet 1 with seqnum %i in fast mode\n", s.seqnum);

            // send packet one
            if (sendto(sockfd, packet_one, sizeof(*packet_one), flags, senderServerAddr, senderSocklen) == -1) {
                printf("sending packet 1 failed\n");
                continue;
            }

            // set state to data sent
            s.state = DATA_SENT;
            int firstSeqnum = s.seqnum;
            int secondSeqnum = s.seqnum;
            int isSecondPacket = -1;

            // only send second packet if there's remaining data
            if (i + 1 < numPackets) {
                datalen = (int)len - (i + 1) * DATALEN;
                if (datalen > DATALEN) {
                    datalen = DATALEN;
                }
                s.seqnum ++;
                secondSeqnum = s.seqnum;

                isSecondPacket = 0;
                memset(slicedBuf, '\0', DATALEN);
                memcpy(slicedBuf, buf + (i + 1) * DATALEN, datalen);
                packet_two = make_packet(DATA, s.seqnum, -1, slicedBuf, datalen);

                printf("sending packet 2 with seqnum %i in fast mode\n", s.seqnum);
                printf("pk2 data size %i\n", packet_two->datalen);

                if (sendto(sockfd, packet_two, sizeof(*packet_two), flags, senderServerAddr, senderSocklen) == -1){
                    printf("sending packet 2 failed\n");
                    isSecondPacket = -1;
                    continue;
                }
            }

            int firstAckReceived = -1;
            while (s.timed_out == -1 && s.state != DATA_RCVD && attempts < 5) {
                alarm(TIMEOUT);

                rec_header = malloc(sizeof(gbnhdr));

                if (recvfrom(sockfd, rec_header, sizeof(rec_header), 0, receiverServerAddr, &receiverSocklen) == -1) {
                    attempts ++;
                    continue;
                }

                // if header type is not dataack, attempt again
                if (check_timeout() == 0 && check_packetType(rec_header, DATAACK) == -1) {
                    attempts ++;
                    continue;
                }

                // check if 2 packets were sent.
                if (isSecondPacket == 0) {
                    // if sent and received ack for packet 2, then slide window by increasing seqnum.
                    // Since acks are sent in order, ack for first packet must've been received earlier
                    if (check_seqnum(rec_header, secondSeqnum) == 0) {
                        printf("received ack for packet 2 with seqnum %i\n", secondSeqnum);
                        firstAckReceived = -1;
                        s.state = DATA_RCVD;
                        s.seqnum++;
                        i++;
                        break;
                    }
                    // received ack only for packet 1, need to wait for ack for packet 2.
                    if (check_seqnum(rec_header, firstSeqnum) == 0) {
                        printf("received ack for packet 1 with seqnum %i\n", firstSeqnum);
                        firstAckReceived = 0;
                        continue;
                    }
                    // received ack for packet sent earlier
                    attempts ++;
                }
                // if only one packet was sent and received ack for that, then done.
                else {
                    if (check_seqnum(rec_header, firstSeqnum) == 0) {
                        s.seqnum ++;
                        s.state = DATA_RCVD;
                        break;
                    }
                    attempts ++;
                }
                free(rec_header);
                free(packet_one);
            }

            // if only received ack for packet 1 and not 2, switch to slow mode
            if (firstAckReceived == 0) {
                printf("only 1st ack received in fast mode. switching to slow mode\n");
                s.mode = SLOW;
            }
            // if received no acks, switch to slow mode, reset seqnum if packet 2 was sent
            if (s.timed_out == 0 || attempts == 5) {
                printf("switching to slow mode\n");
                // switch to slow mode
                s.mode = SLOW;
                s.timed_out = -1;
                if (isSecondPacket == 0) {
                    s.seqnum --;
                }
            }
        }
    }
    free(slicedBuf);

    printf("end of send\n");

	return 0;
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){
	// process buffer data
	printf ("in receive\n");

	gbnhdr * packet = malloc(sizeof(gbnhdr));
    int discard = -1;

	recvfrom(sockfd, packet, sizeof(gbnhdr), 0, receiverServerAddr, &receiverSocklen);

    // if a data packet is received, check packet to verify its type
	if (check_packetType(packet, DATA) == 0){
		printf("received data packet with seqnum %i\n", packet->seqnum);

        // discard if data seqnum is not the expected seqnum
        if (check_seqnum(packet, s.rec_seqnum) == -1) {
            printf("received an unexpected seqnum, discarding data...\n");
            discard = 0;
        }

        //int packet_size = (int)strlen((const char*)packet->data);
        int packet_size = packet->datalen;

        // discard if data is corrupt
		if (checksum(buf, packet_size) == -1) {
			printf("data is corrupt\n");
            discard = 0;
        }

        printf("buffer size: %i\n", packet_size);

        memcpy(buf, packet->data, packet_size);

		// reply with dataack header with seqnum received
		gbnhdr *header = make_packet(DATAACK, s.rec_seqnum, 0, NULL, 0);

		if (sendto(sockfd, header, sizeof(gbnhdr), 0, receiverServerAddr, receiverSocklen) == -1) {
			printf ("error sending dataack\n");
			return -1;
		}
        printf("sent dataack with seqnum %i\n", s.rec_seqnum);
        free(header);

        if (discard == 0) {
            return 0;
        }
        s.rec_seqnum ++;
        return packet_size;
	}

    // if a connection teardown request is received, reply with FINACK header
	if (check_packetType(packet, FIN) == 0) {
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
    s.mode = SLOW;
    // pointer to local struct on sender server where receiver address is stored
    senderServerAddr = (struct sockaddr *)server;
    senderSocklen = socklen;

    gbnhdr *header = make_packet(SYN, 0, 0, NULL, 0);

    // SIGALRM is called after timeout alarm
    signal(SIGALRM, sig_handler);

	if (sockfd < 0) {
		return -1;
	}

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
		if (check_packetType(rec_header, SYNACK) == 0) {
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
	if (check_packetType(header, SYN) == 0) {
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
        free(header);
        return -1;
	}
    printf("sent synack header\n");
    free(header);

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
		int retval = maybe_sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
